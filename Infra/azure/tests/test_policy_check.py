"""Unit tests for Infra/azure/policy_check.py.

Run:  python3 -I -m unittest discover -s Infra/azure/tests -t Infra/azure/tests
The fixtures are minimal `tofu show -json` plans mirroring this module's resources for each profile; each test copies one and introduces
exactly one violation (the exploit path the rule exists for), then asserts that the checker reports it.
"""
from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # isolated mode (-I) does not add the script directory

import policy_check  # noqa: E402

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"


def load(profile: str) -> dict:
    return json.loads((HERE / "fixtures" / f"{profile}_plan.json").read_text(encoding="utf-8"))


def find(plan: dict, address: str) -> dict:
    for rc in plan["resource_changes"]:
        if rc["address"] == address:
            return rc
    raise KeyError(address)


def after(plan: dict, address: str) -> dict:
    return find(plan, address)["change"]["after"]


def add_resource(plan: dict, type_: str, name: str, values: dict, *, unknown: dict | None = None, refs: dict | None = None,
                 module: str | None = None, actions: list[str] | None = None) -> None:
    address = f"{module}.{type_}.{name}" if module else f"{type_}.{name}"
    rc = {"address": address, "mode": "managed", "type": type_, "name": name,
          "change": {"actions": actions or ["create"], "before": None, "after": values, "after_unknown": unknown or {}}}
    if module:
        rc["module_address"] = module
    plan["resource_changes"].append(rc)
    if refs:
        expressions = {attr: {"references": r} for attr, r in refs.items()}
        target = plan["configuration"]["root_module"]
        if module:
            name_ = module.split(".", 1)[1]
            calls = target.setdefault("module_calls", {})
            target = calls.setdefault(name_, {"module": {"resources": []}})["module"]
        target.setdefault("resources", []).append({"address": f"{type_}.{name}", "type": type_, "name": name, "expressions": expressions})


def rules(report: policy_check.Report) -> set[str]:
    return {f.rule for f in report.violations}


def exception_rules(report: policy_check.Report) -> set[str]:
    return {f.rule for f in report.exceptions}


class Baselines(unittest.TestCase):
    def test_lean_fixture_passes_with_its_recorded_exceptions(self):
        report = policy_check.evaluate(load("lean"))
        self.assertEqual(report.profile, "lean")
        self.assertEqual(report.violations, [])
        self.assertEqual(exception_rules(report), {"KV-PUBLIC", "SB-PUBLIC", "KV-SOFTWARE-KEYS", "PG-NO-HA", "PG-PASSWORD-AUTH"})

    def test_standard_fixture_passes(self):
        report = policy_check.evaluate(load("standard"))
        self.assertEqual(report.profile, "standard")
        self.assertEqual(report.violations, [])
        self.assertEqual(exception_rules(report), {"PG-PASSWORD-AUTH"})

    def test_standard_without_password_auth_has_no_exception(self):
        plan = load("standard")
        after(plan, "azurerm_postgresql_flexible_server.this")["authentication"][0]["password_auth_enabled"] = False
        self.assertEqual(policy_check.evaluate(plan).exceptions, [])


class PostgreSQL(unittest.TestCase):
    def test_public_access_is_a_violation_in_both_profiles(self):
        for profile in ("lean", "standard"):
            plan = load(profile)
            after(plan, "azurerm_postgresql_flexible_server.this")["public_network_access_enabled"] = True
            self.assertIn("PG-PUBLIC", rules(policy_check.evaluate(plan)), profile)

    def test_public_access_left_to_the_azure_default_is_a_violation(self):
        plan = load("lean")
        del after(plan, "azurerm_postgresql_flexible_server.this")["public_network_access_enabled"]
        self.assertIn("PG-PUBLIC", rules(policy_check.evaluate(plan)))

    def test_firewall_rule_is_forbidden(self):
        plan = load("lean")
        add_resource(plan, "azurerm_postgresql_flexible_server_firewall_rule", "office",
                     {"start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"})
        self.assertIn("FORBIDDEN-RESOURCE", rules(policy_check.evaluate(plan)))

    def test_server_without_vnet_integration_is_a_violation(self):
        plan = load("lean")
        rc = find(plan, "azurerm_postgresql_flexible_server.this")
        rc["change"]["after_unknown"].pop("delegated_subnet_id")
        plan["configuration"]["root_module"]["resources"] = [
            r for r in plan["configuration"]["root_module"]["resources"] if r["address"] != "azurerm_postgresql_flexible_server.this"]
        self.assertIn("PG-PRIVATE", rules(policy_check.evaluate(plan)))

    def test_standard_requires_ha_pitr_and_geo_backup(self):
        plan = load("standard")
        pg = after(plan, "azurerm_postgresql_flexible_server.this")
        pg["high_availability"] = []
        pg["backup_retention_days"] = 7
        pg["geo_redundant_backup_enabled"] = False
        self.assertTrue({"PG-HA", "PG-PITR", "PG-GEO-BACKUP"} <= rules(policy_check.evaluate(plan)))

    def test_lean_rejects_a_general_purpose_sku(self):
        plan = load("lean")
        after(plan, "azurerm_postgresql_flexible_server.this")["sku_name"] = "GP_Standard_D2ds_v5"
        self.assertIn("LEAN-FIXED-FEE", rules(policy_check.evaluate(plan)))


class KeyVault(unittest.TestCase):
    def test_purge_protection_is_mandatory(self):
        plan = load("lean")
        after(plan, "azurerm_key_vault.this")["purge_protection_enabled"] = False
        self.assertIn("KV-PURGE-PROTECTION", rules(policy_check.evaluate(plan)))

    def test_public_access_is_a_violation_in_standard(self):
        plan = load("standard")
        after(plan, "azurerm_key_vault.this")["public_network_access_enabled"] = True
        self.assertIn("KV-PUBLIC", rules(policy_check.evaluate(plan)))

    def test_open_firewall_is_a_violation_even_in_lean(self):
        plan = load("lean")
        after(plan, "azurerm_key_vault.this")["network_acls"][0]["default_action"] = "Allow"
        self.assertIn("KV-FIREWALL", rules(policy_check.evaluate(plan)))

    def test_lean_public_access_needs_rbac(self):
        plan = load("lean")
        after(plan, "azurerm_key_vault.this")["rbac_authorization_enabled"] = False
        found = rules(policy_check.evaluate(plan))
        self.assertIn("KV-RBAC", found)
        self.assertIn("KV-PUBLIC", found)

    def test_access_policy_resource_is_forbidden(self):
        plan = load("lean")
        add_resource(plan, "azurerm_key_vault_access_policy", "app", {"key_permissions": ["Get"]})
        self.assertIn("FORBIDDEN-RESOURCE", rules(policy_check.evaluate(plan)))

    def test_standard_requires_premium_and_hsm_keys(self):
        plan = load("standard")
        after(plan, "azurerm_key_vault.this")["sku_name"] = "standard"
        after(plan, 'azapi_resource.kv_key["kek-data"]')["body"]["properties"]["kty"] = "RSA"
        found = policy_check.evaluate(plan)
        self.assertIn("KV-HSM", rules(found))
        self.assertIn('azapi_resource.kv_key["kek-data"]', {f.address for f in found.violations})

    def test_lean_must_not_buy_premium(self):
        plan = load("lean")
        after(plan, "azurerm_key_vault.this")["sku_name"] = "premium"
        self.assertIn("LEAN-FIXED-FEE", rules(policy_check.evaluate(plan)))

    def test_managed_hsm_is_never_used(self):
        for profile in ("lean", "standard"):
            plan = load(profile)
            add_resource(plan, "azurerm_key_vault_managed_hardware_security_module", "hsm", {"sku_name": "Standard_B1"})
            self.assertIn("FORBIDDEN-RESOURCE", rules(policy_check.evaluate(plan)), profile)


class Storage(unittest.TestCase):
    def test_public_storage_is_a_violation_in_both_profiles(self):
        for profile in ("lean", "standard"):
            plan = load(profile)
            add_resource(plan, "azurerm_storage_account", "extra", {"public_network_access": "Enabled", "shared_access_key_enabled": False,
                                                                    "allow_nested_items_to_be_public": False})
            self.assertIn("ST-PUBLIC", rules(policy_check.evaluate(plan)), profile)

    def test_shared_keys_and_public_blobs_are_violations(self):
        plan = load("standard")
        st = after(plan, "azurerm_storage_account.audit[0]")
        st["shared_access_key_enabled"] = True
        st["allow_nested_items_to_be_public"] = True
        self.assertTrue({"ST-SHARED-KEY", "ST-PUBLIC-BLOBS"} <= rules(policy_check.evaluate(plan)))

    def test_legacy_boolean_public_flag_is_understood(self):
        plan = load("standard")
        st = after(plan, "azurerm_storage_account.audit[0]")
        del st["public_network_access"]
        st["public_network_access_enabled"] = True
        self.assertIn("ST-PUBLIC", rules(policy_check.evaluate(plan)))


class ServiceBus(unittest.TestCase):
    def test_local_auth_is_a_violation_in_both_profiles(self):
        for profile in ("lean", "standard"):
            plan = load(profile)
            after(plan, "azurerm_servicebus_namespace.this")["local_auth_enabled"] = True
            self.assertIn("SB-LOCAL-AUTH", rules(policy_check.evaluate(plan)), profile)

    def test_local_auth_left_to_the_azure_default_is_a_violation(self):
        plan = load("lean")
        del after(plan, "azurerm_servicebus_namespace.this")["local_auth_enabled"]
        found = rules(policy_check.evaluate(plan))
        self.assertIn("SB-LOCAL-AUTH", found)
        self.assertIn("SB-PUBLIC", found)  # the lean public endpoint is only an exception with Entra-only auth

    def test_public_access_is_a_violation_in_standard(self):
        plan = load("standard")
        after(plan, "azurerm_servicebus_namespace.this")["public_network_access_enabled"] = True
        self.assertIn("SB-PUBLIC", rules(policy_check.evaluate(plan)))

    def test_old_tls_is_a_violation(self):
        plan = load("lean")
        after(plan, "azurerm_servicebus_namespace.this")["minimum_tls_version"] = "1.0"
        self.assertIn("SB-TLS", rules(policy_check.evaluate(plan)))

    def test_lean_allows_only_basic(self):
        plan = load("lean")
        after(plan, "azurerm_servicebus_namespace.this")["sku"] = "Premium"
        self.assertIn("LEAN-FIXED-FEE", rules(policy_check.evaluate(plan)))


class RoleAssignments(unittest.TestCase):
    def test_known_subscription_scope_is_a_violation(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "wide", {"scope": SUB, "role_definition_name": "Reader",
                                                               "description": "workload:api: read everything"})
        self.assertIn("RBAC-SCOPE", rules(policy_check.evaluate(plan)))

    def test_subscription_scope_by_reference_is_a_violation(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "wide", {"role_definition_name": "Key Vault Secrets User",
                                                               "description": "workload:api: secrets"},
                     unknown={"scope": True}, refs={"scope": ["data.azurerm_subscription.current.id", "data.azurerm_subscription.current"]})
        self.assertIn("RBAC-SCOPE", rules(policy_check.evaluate(plan)))

    def test_management_group_scope_is_a_violation(self):
        plan = load("standard")
        add_resource(plan, "azurerm_role_assignment", "mg", {"scope": "/providers/Microsoft.Management/managementGroups/root",
                                                             "role_definition_name": "Reader", "description": "human:auditors: read"})
        self.assertIn("RBAC-SCOPE", rules(policy_check.evaluate(plan)))

    def test_workload_on_a_resource_group_is_a_violation(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "rg", {"scope": SUB + "/resourceGroups/rg-viadere-stg-sec",
                                                             "role_definition_name": "Key Vault Secrets User",
                                                             "description": "workload:api: all secrets in the group"})
        self.assertIn("RBAC-WORKLOAD-SCOPE", rules(policy_check.evaluate(plan)))

    def test_workload_on_a_resource_group_by_reference_is_a_violation(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "rg2", {"role_definition_name": "Key Vault Secrets User",
                                                              "description": "workload:api: all secrets in the group"},
                     unknown={"scope": True}, refs={"scope": ['azurerm_resource_group.this["sec"].id', "azurerm_resource_group.this"]})
        self.assertIn("RBAC-WORKLOAD-SCOPE", rules(policy_check.evaluate(plan)))

    def test_deploy_identity_may_not_hold_contributor(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "deploy_contrib", {"scope": SUB + "/resourceGroups/rg-viadere-stg-app",
                                                                         "role_definition_name": "Contributor",
                                                                         "description": "deploy:gh-deploy: everything"})
        found = rules(policy_check.evaluate(plan))
        self.assertIn("RBAC-PRIVILEGED", found)
        self.assertIn("RBAC-SCOPE", found)

    def test_privileged_role_at_resource_scope_is_a_violation_for_workloads(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "kvadmin", {
            "scope": SUB + "/resourceGroups/rg-viadere-stg-sec/providers/Microsoft.KeyVault/vaults/kv-vdr-stgabc1l",
            "role_definition_name": "Key Vault Administrator", "description": "workload:api: manage the vault"})
        self.assertIn("RBAC-PRIVILEGED", rules(policy_check.evaluate(plan)))

    def test_unclassified_assignment_is_a_violation(self):
        plan = load("lean")
        rc = find(plan, 'azurerm_role_assignment.secret_user["api/database-url"]')
        rc["change"]["after"]["description"] = "reads a secret"
        self.assertIn("RBAC-UNCLASSIFIED", rules(policy_check.evaluate(plan)))

    def test_scope_hidden_behind_a_local_is_a_violation(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "opaque", {"role_definition_name": "Reader", "description": "workload:api: x"},
                     unknown={"scope": True}, refs={"scope": ["local.some_scope"]})
        self.assertIn("RBAC-SCOPE", rules(policy_check.evaluate(plan)))

    def test_assignment_inside_a_child_module_is_resolved(self):
        plan = load("lean")
        add_resource(plan, "azurerm_role_assignment", "child", {"role_definition_name": "Reader", "description": "workload:api: x"},
                     unknown={"scope": True}, refs={"scope": ["data.azurerm_subscription.this.id"]}, module="module.extra")
        found = policy_check.evaluate(plan)
        self.assertIn("module.extra.azurerm_role_assignment.child", {f.address for f in found.violations if f.rule == "RBAC-SCOPE"})


class ContainerApps(unittest.TestCase):
    def test_external_ingress_is_a_violation(self):
        plan = load("lean")
        after(plan, "azurerm_container_app.api")["ingress"][0]["external_enabled"] = True
        self.assertIn("CA-EXTERNAL-INGRESS", rules(policy_check.evaluate(plan)))

    def test_environment_must_be_internal_and_private(self):
        plan = load("standard")
        props = after(plan, "azapi_resource.cae")["body"]["properties"]
        props["vnetConfiguration"]["internal"] = False
        props["publicNetworkAccess"] = "Enabled"
        self.assertTrue({"CAE-INTERNAL", "CAE-PUBLIC"} <= rules(policy_check.evaluate(plan)))

    def test_lean_rejects_dedicated_workload_profiles(self):
        plan = load("lean")
        after(plan, "azapi_resource.cae")["body"]["properties"]["workloadProfiles"].append(
            {"name": "d4", "workloadProfileType": "D4", "minimumCount": 1, "maximumCount": 1})
        self.assertIn("LEAN-FIXED-FEE", rules(policy_check.evaluate(plan)))

    def test_azurerm_environment_resource_is_checked_too(self):
        plan = load("lean")
        add_resource(plan, "azurerm_container_app_environment", "other", {"internal_load_balancer_enabled": False,
                                                                          "public_network_access": "Enabled"})
        self.assertTrue({"CAE-INTERNAL", "CAE-PUBLIC"} <= rules(policy_check.evaluate(plan)))


class FixedFeesAndRegistry(unittest.TestCase):
    def test_lean_rejects_private_endpoints_nat_and_registry(self):
        plan = load("lean")
        add_resource(plan, "azurerm_private_endpoint", "kv", {"name": "pe-kv"})
        add_resource(plan, "azurerm_nat_gateway", "ng", {"name": "ng"})
        add_resource(plan, "azurerm_container_registry", "cr", {"admin_enabled": False, "anonymous_pull_enabled": False,
                                                                "public_network_access_enabled": False})
        found = [f for f in policy_check.evaluate(plan).violations if f.rule == "LEAN-FIXED-FEE"]
        self.assertEqual(len(found), 3)

    def test_registry_admin_user_and_public_access_are_violations(self):
        plan = load("standard")
        cr = after(plan, "azurerm_container_registry.this[0]")
        cr["admin_enabled"] = True
        cr["public_network_access_enabled"] = True
        self.assertTrue({"ACR-ADMIN", "ACR-PUBLIC"} <= rules(policy_check.evaluate(plan)))

    def test_any_other_public_resource_is_a_violation(self):
        plan = load("standard")
        add_resource(plan, "azurerm_eventhub_namespace", "x", {"public_network_access_enabled": True})
        self.assertIn("PUBLIC-ACCESS", rules(policy_check.evaluate(plan)))

    def test_deleted_resources_are_ignored(self):
        plan = load("lean")
        add_resource(plan, "azurerm_private_endpoint", "old", {"name": "pe-old"}, actions=["delete"])
        self.assertEqual(policy_check.evaluate(plan).violations, [])


class CommandLine(unittest.TestCase):
    def run_cli(self, plan, *args: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            path.write_text(plan if isinstance(plan, str) else json.dumps(plan), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = policy_check.main([str(path), *args])
        return code, out.getvalue(), err.getvalue()

    def test_clean_plan_exits_zero_and_lists_exceptions(self):
        code, out, _ = self.run_cli(load("lean"))
        self.assertEqual(code, 0)
        self.assertIn("EXCEPTION SB-PUBLIC", out)

    def test_violation_exits_one(self):
        plan = load("lean")
        after(plan, "azurerm_postgresql_flexible_server.this")["public_network_access_enabled"] = True
        code, out, _ = self.run_cli(plan)
        self.assertEqual(code, 1)
        self.assertIn("VIOLATION PG-PUBLIC", out)

    def test_json_output(self):
        code, out, _ = self.run_cli(load("standard"), "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["profile"], "standard")
        self.assertEqual(data["violations"], [])

    def test_profile_mismatch_is_an_input_error(self):
        code, _, err = self.run_cli(load("lean"), "--profile", "standard")
        self.assertEqual(code, 2)
        self.assertIn("does not match", err)

    def test_state_json_is_rejected(self):
        code, _, err = self.run_cli({"format_version": "1.0", "values": {}})
        self.assertEqual(code, 2)
        self.assertIn("resource_changes", err)

    def test_garbage_is_rejected(self):
        code, _, _ = self.run_cli("not json")
        self.assertEqual(code, 2)

    def test_lean_plan_checked_as_standard_fails(self):
        plan = copy.deepcopy(load("lean"))
        del plan["variables"]["profile"]
        code, out, _ = self.run_cli(plan, "--profile", "standard")
        self.assertEqual(code, 1)
        self.assertIn("KV-PUBLIC", out)


if __name__ == "__main__":
    unittest.main()
