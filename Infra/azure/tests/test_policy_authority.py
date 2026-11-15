"""Unit tests for the authority-tier rules of Infra/azure/policy_check.py (ADR-0028 section 5).

Run:  python3 -I -m unittest discover -s Infra/azure/tests -t Infra/azure/tests
Each test builds a minimal authority plan that passes, then introduces exactly one violation (the exploit path the rule exists for).
"""
from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import policy_check  # noqa: E402
from test_policy_check import add_resource, load, rules  # noqa: E402

AUTH = "azurerm_user_assigned_identity.authority"
ADMIN = "azurerm_user_assigned_identity.authority_admin"
KEY = "azapi_resource.kv_key"


def base(profile: str = "lean", **variables) -> dict:
    plan = {"format_version": "1.2", "variables": {"profile": {"value": profile}, "authority_enabled": {"value": True},
                                                   **{k: {"value": v} for k, v in variables.items()}},
            "resource_changes": [], "configuration": {"root_module": {"resources": []}}}
    nsg_rules = [
        {"name": "allow-postgres", "priority": 100, "direction": "Outbound", "access": "Allow", "destination_address_prefix": "10.40.2.0/28"},
        {"name": "deny-internet-outbound", "priority": 4000, "direction": "Outbound", "access": "Deny", "destination_address_prefix": "Internet"},
    ]
    add_resource(plan, "azurerm_network_security_group", "auth", {"name": "nsg-viadere-stg-auth", "security_rule": nsg_rules})
    add_resource(plan, "azurerm_subnet_network_security_group_association", "auth", {},
                 refs={"network_security_group_id": ["azurerm_network_security_group.auth[0].id", "azurerm_network_security_group.auth"]})
    add_resource(plan, "azapi_resource", "cae", {"type": "Microsoft.App/managedEnvironments@2026-01-01", "name": "cae-viadere-stg-auth", "location": "centralus",
                                                 "body": {"properties": {"vnetConfiguration": {"internal": True}, "publicNetworkAccess": "Disabled",
                                                                         "workloadProfiles": [{"workloadProfileType": "Consumption"}]}}})
    add_resource(plan, "azurerm_container_app", "authority",
                 {"name": "ca-viadere-authority", "ingress": [{"external_enabled": False, "allow_insecure_connections": False}]},
                 refs={"identity": [AUTH + "[0].id", AUTH]})
    add_resource(plan, "azurerm_role_definition", "signer", {"name": "Viadere Authority Signer (stg)", "permissions": [
        {"data_actions": ["Microsoft.KeyVault/vaults/keys/read", "Microsoft.KeyVault/vaults/keys/sign/action"], "actions": []}]})
    assign(plan, 'azurerm_role_assignment.authority_key["grant-signing"]', "viadere authority signer (stg)", [AUTH + "[0].principal_id", AUTH],
           [KEY + '["grant-signing"].id', KEY], "workload:authority: sign")
    return plan


def assign(plan: dict, address: str, role: str, principal_refs: list[str], scope_refs: list[str], description: str) -> None:
    type_, rest = address.split(".", 1)
    name = rest.split("[", 1)[0]
    add_resource(plan, type_, name, {"role_definition_name": role, "description": description, "principal_type": "ServicePrincipal"},
                 refs={"principal_id": principal_refs, "scope": scope_refs})
    plan["resource_changes"][-1]["address"] = address


class Baseline(unittest.TestCase):
    def test_clean_authority_plan_passes(self):
        report = policy_check.evaluate(base())
        self.assertEqual(report.violations, [])

    def test_ordinary_fixtures_still_pass(self):
        for profile in ("lean", "standard"):
            self.assertEqual(policy_check.evaluate(load(profile)).violations, [])


class KeyCustody(unittest.TestCase):
    def test_an_ordinary_identity_on_the_authority_vault(self):
        plan = base()
        assign(plan, 'azurerm_role_assignment.x["api"]', "key vault secrets user", ["azurerm_user_assigned_identity.workload"], [KEY, KEY + '["grant-signing"].id'],
               "workload:api: read")
        self.assertIn("AUTH-KEY-SCOPE", rules(policy_check.evaluate(plan)))

    def test_crypto_user_includes_backup(self):
        plan = base()
        assign(plan, 'azurerm_role_assignment.y["k"]', "Key Vault Crypto User", [AUTH], [KEY], "workload:authority: sign")
        found = rules(policy_check.evaluate(plan))
        self.assertIn("AUTH-KEY-BACKUP", found)
        self.assertIn("AUTH-SIGNER-ROLE", found)

    def test_admin_identity_has_no_key_vault_role(self):
        plan = base()
        assign(plan, 'azurerm_role_assignment.z["k"]', "viadere authority signer (stg)", [ADMIN], [KEY], "workload:authority-admin: sign")
        self.assertIn("AUTH-ADMIN-NO-KV", rules(policy_check.evaluate(plan)))

    def test_admin_workflow_identity_reads_no_log(self):
        # S6-06: the key inventory is never read from a log; the admin workflow identity holds only the job-starter role on the admin job.
        gh_admin = "azurerm_user_assigned_identity.gh_authority_admin"
        plan = base()
        assign(plan, "azurerm_role_assignment.gh_authority_admin_start", "viadere container apps job starter (stg)", [gh_admin + "[0].principal_id", gh_admin],
               ["azurerm_container_app_job.admin[0].id", "azurerm_container_app_job.admin"], "deploy:gh-authority-admin: start the admin job")
        self.assertNotIn("AUTH-INVENTORY-CHANNEL", rules(policy_check.evaluate(plan)))
        assign(plan, "azurerm_role_assignment.gh_authority_admin_logs", "Log Analytics Reader", [gh_admin + "[0].principal_id", gh_admin],
               ["azurerm_log_analytics_workspace.auth[0].id", "azurerm_log_analytics_workspace.auth"], "deploy:gh-authority-admin: read logs")
        self.assertIn("AUTH-INVENTORY-CHANNEL", rules(policy_check.evaluate(plan)))

    def test_signer_role_with_extra_data_actions(self):
        plan = base()
        plan["resource_changes"][-2]["change"]["after"]["permissions"][0]["data_actions"].append("Microsoft.KeyVault/vaults/keys/decrypt/action")
        self.assertIn("AUTH-SIGNER-ROLE", rules(policy_check.evaluate(plan)))

    def test_backup_in_a_custom_role(self):
        plan = base()
        plan["resource_changes"][-2]["change"]["after"]["permissions"][0]["data_actions"].append("Microsoft.KeyVault/vaults/keys/backup/action")
        self.assertIn("AUTH-KEY-BACKUP", rules(policy_check.evaluate(plan)))

    def test_exec_on_the_authority_app_is_refused(self):
        plan = base()
        plan["resource_changes"][-2]["change"]["after"]["permissions"][0]["actions"] = ["Microsoft.App/containerApps/getAuthToken/action"]
        self.assertIn("AUTH-SIGNER-ROLE", rules(policy_check.evaluate(plan)))

    def test_unwrapper_only_on_the_active_kek(self):
        plan = base()
        assign(plan, 'azurerm_role_assignment.authority_key["grant-signing"]', "viadere authority unwrapper (stg)", [AUTH], [KEY], "workload:authority: x")
        self.assertIn("AUTH-SIGNER-ROLE", rules(policy_check.evaluate(plan)))

    def test_standby_role_without_rollover(self):
        plan = base()
        assign(plan, 'azurerm_role_assignment.authority_key["device-statement-signing-standby"]', "viadere authority signer (stg)", [AUTH], [KEY],
               "workload:authority: sign")
        self.assertIn("AUTH-STANDBY-ROLE", rules(policy_check.evaluate(plan)))

    def test_standby_role_with_a_recorded_rollover_is_allowed(self):
        plan = base(rollover_change_file="docs/ops/changes/rollover-1.json")
        assign(plan, 'azurerm_role_assignment.rollover["device-statement-signing-standby"]', "viadere authority signer (stg)", [AUTH], [KEY],
               "workload:authority: ROLLOVER")
        self.assertNotIn("AUTH-STANDBY-ROLE", rules(policy_check.evaluate(plan)))

    def test_standard_has_no_kek_or_unwrapper(self):
        plan = base("standard")
        add_resource(plan, "azapi_resource", "kek", {"type": "Microsoft.KeyVault/vaults/keys@2026-02-01", "name": "recovery-seal-kek",
                                                     "body": {"properties": {"kty": "RSA-HSM"}}})
        self.assertIn("AUTH-SIGNER-ROLE", rules(policy_check.evaluate(plan)))


class Isolation(unittest.TestCase):
    def test_external_ingress(self):
        plan = base()
        for rc in plan["resource_changes"]:
            if rc["address"] == "azurerm_container_app.authority":
                rc["change"]["after"]["ingress"][0]["external_enabled"] = True
        self.assertIn("AUTH-NO-PUBLIC-INGRESS", rules(policy_check.evaluate(plan)))

    def test_insecure_ingress(self):
        plan = base()
        for rc in plan["resource_changes"]:
            if rc["address"] == "azurerm_container_app.authority":
                rc["change"]["after"]["ingress"][0]["allow_insecure_connections"] = True
        self.assertIn("AUTH-NO-PUBLIC-INGRESS", rules(policy_check.evaluate(plan)))

    def test_public_authority_environment(self):
        plan = base()
        for rc in plan["resource_changes"]:
            if rc["address"] == "azapi_resource.cae":
                rc["change"]["after"]["body"]["properties"]["vnetConfiguration"]["internal"] = False
        self.assertIn("AUTH-NO-PUBLIC-INGRESS", rules(policy_check.evaluate(plan)))

    def test_ordinary_identity_on_an_authority_app(self):
        plan = base()
        for rc in plan["resource_changes"]:
            if rc["address"] == "azurerm_container_app.authority":
                pass
        cfg = plan["configuration"]["root_module"]["resources"]
        next(r for r in cfg if r["name"] == "authority")["expressions"]["identity"]["references"].append("azurerm_user_assigned_identity.workload")
        self.assertIn("AUTH-IDENTITY-SEPARATE", rules(policy_check.evaluate(plan)))

    def test_authority_identity_on_an_ordinary_app(self):
        plan = base()
        add_resource(plan, "azurerm_container_app", "api", {"name": "ca-viadere-api", "ingress": [{"external_enabled": False}]},
                     refs={"identity": [AUTH + "[0].id"]})
        self.assertIn("AUTH-IDENTITY-SEPARATE", rules(policy_check.evaluate(plan)))

    def test_one_identity_deploying_both_tiers(self):
        plan = base()
        deploy = "azurerm_user_assigned_identity.gh_deploy_auth"
        assign(plan, "azurerm_role_assignment.a", "Managed Identity Operator", [deploy], [AUTH], "deploy:gh: a")
        assign(plan, "azurerm_role_assignment.b", "Managed Identity Operator", [deploy], ['azurerm_user_assigned_identity.workload["api"].id',
                                                                                              "azurerm_user_assigned_identity.workload"], "deploy:gh: b")
        self.assertIn("AUTH-DEPLOY-SEPARATE", rules(policy_check.evaluate(plan)))

    def test_missing_deny_internet_rule(self):
        plan = base()
        nsg = plan["resource_changes"][0]["change"]["after"]
        nsg["security_rule"] = [r for r in nsg["security_rule"] if r["access"] == "Allow"]
        self.assertIn("AUTH-EGRESS", rules(policy_check.evaluate(plan)))

    def test_deny_rule_ahead_of_an_allow_rule(self):
        plan = base()
        nsg = plan["resource_changes"][0]["change"]["after"]
        nsg["security_rule"][0]["priority"] = 4100
        self.assertIn("AUTH-EGRESS", rules(policy_check.evaluate(plan)))

    def test_allow_everything_outbound(self):
        plan = base()
        plan["resource_changes"][0]["change"]["after"]["security_rule"][0]["destination_address_prefix"] = "Internet"
        self.assertIn("AUTH-EGRESS", rules(policy_check.evaluate(plan)))

    def test_worker_with_evidence_submit(self):
        plan = base()
        add_resource(plan, "azuread_app_role_assignment", "worker_submit", {}, refs={
            "principal_object_id": ['azurerm_user_assigned_identity.workload["worker"].principal_id', "azurerm_user_assigned_identity.workload.worker"],
            "app_role_id": ["azuread_application_app_role.evidence_submit"]})
        # the reference of the worker is by name in this fixture
        plan["configuration"]["root_module"]["resources"][-1]["expressions"]["principal_object_id"]["references"].append("var.worker_identity_worker")
        self.assertIn("AUTH-REVOCATIONS-ROLE", rules(policy_check.evaluate(plan)))


class CrossTier(unittest.TestCase):
    def test_api_gets_a_new_key(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "key_user", {"role_definition_name": "Key Vault Crypto User", "description": "workload:api: use key"})
        plan["resource_changes"][-1]["address"] = 'azurerm_role_assignment.key_user["api/grant-signing"]'
        self.assertIn("API-NO-NEW-KEYS", rules(policy_check.evaluate(plan)))

    def test_residency(self):
        plan = load("lean")
        add_resource(plan, "azurerm_resource_group", "elsewhere", {"name": "rg-x", "location": "westeurope"})
        self.assertIn("RESIDENCY-US", rules(policy_check.evaluate(plan)))

    def test_ghcr_pat_secret_name(self):
        plan = load("lean")
        add_resource(plan, "azapi_resource", "pat", {"type": "Microsoft.KeyVault/vaults/secrets@2026-02-01", "name": "ghcr-pull-token", "body": {"properties": {}}})
        self.assertIn("GHCR-NO-PAT", rules(policy_check.evaluate(plan)))

    def test_oidc_subject_without_workflow_ref_is_a_recorded_exception(self):
        plan = base()
        add_resource(plan, "azurerm_federated_identity_credential", "gh_deploy_auth", {"subject": "repo:o/r:environment:authority-staging"})
        report = policy_check.evaluate(plan)
        self.assertIn("AUTH-OIDC-SUBJECT", {f.rule for f in report.exceptions})
        self.assertEqual(report.violations, [])


class Source(unittest.TestCase):
    def run_source(self, files: dict[str, str], name: str) -> set[str]:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / name
            directory.mkdir()
            for filename, text in files.items():
                (directory / filename).write_text(text, encoding="utf-8")
            report = policy_check.Report(profile="lean")
            policy_check.source_checks(directory, report)
            return {f.rule for f in report.violations}

    def test_repository_modules_pass(self):
        root = HERE.parents[1]
        for directory in ("Infra/azure", "Infra/cloudflare", "Infra/azure-authority"):
            report = policy_check.Report(profile="lean")
            policy_check.source_checks(root / directory, report)
            self.assertEqual(report.violations, [], directory)

    def test_new_api_key_grant_in_locals(self):
        text = 'locals {\n  key_grants = {\n    api    = ["kek-data", "grant-signing"]\n    worker = ["kek-data"]\n  }\n}\n'
        self.assertIn("API-NO-NEW-KEYS", self.run_source({"locals.tf": text}, "azure"))

    def test_ghcr_pat_in_locals(self):
        self.assertIn("GHCR-NO-PAT", self.run_source({"locals.tf": 'locals {\n  ghcr_pull_secret = "ghcr-pull-token"\n}\n'}, "azure"))

    def test_cloudflare_route_to_the_authority(self):
        self.assertIn("AUTH-NO-PUBLIC-INGRESS", self.run_source({"cloudflare_tunnel.tf": 'service = "http://ca-viadere-authority"\n'}, "cloudflare"))

    def test_cloudflare_comment_about_the_authority_is_fine(self):
        self.assertEqual(self.run_source({"x.tf": "# the authority has no route\n"}, "cloudflare"), set())


if __name__ == "__main__":
    unittest.main()
