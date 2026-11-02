#!/usr/bin/env python3
"""Policy check for an OpenTofu plan of Infra/azure (WP-B1 "Tests first"; plan sections 5.3, 5.8a; CLAUDE.md exceptions).

Usage:
    tofu plan -out tfplan ... && tofu show -json tfplan > plan.json
    python3 -I Infra/azure/policy_check.py plan.json [--profile lean|standard] [--json]

Exit status: 0 = no violation, 1 = at least one violation, 2 = the input could not be read or is not a plan.
Standard library only; safe to run with `python3 -I` (isolated mode). The plan JSON contains configuration values, never secret values:
the module writes no secret into the state (write-only attributes, ephemeral variables).

Rules (profile-aware). A VIOLATION fails the check; an EXCEPTION is allowed but printed, because each one must have a row in CLAUDE.md's
exceptions table:
  * PostgreSQL: public network access or firewall rules are never allowed (either profile); the server must be VNet-integrated.
    standard: zone-redundant HA, PITR >= 35 days, geo-redundant backup. lean: no HA and 7-day PITR are exceptions.
    Password authentication next to Entra is an exception until WP-B2 ships Entra token auth.
  * Key Vault: purge protection, RBAC authorization and a Deny-by-default network ACL are mandatory; access policies are forbidden. Public
    network access is a violation in standard and an exception in lean (only with RBAC). Software-protected keys / Standard SKU: violation in standard, exception in lean.
  * Storage: public network access, shared-key access or public blobs are violations in both profiles. One recorded lean exception: the
    Brand Kit asset account (`azurerm_storage_account.brand`, WP-2.1) may keep its public endpoint in lean only when its firewall denies by
    default, bypasses nothing, admits only subnets (no IP rules) and shared keys are off (`ST-BRAND-PUBLIC`); in standard it is a violation.
  * Service Bus: local (SAS) authentication must be disabled (both profiles); public network access is a violation in standard and an
    exception in lean (only with local auth disabled); minimum TLS below 1.2 is a violation.
  * Role assignments: none at subscription or management-group scope; workload identities only at resource scope (never a resource group);
    the deploy identity only Container Apps Contributor on a resource group; no privileged role (Owner, Contributor, User Access
    Administrator, RBAC Administrator, Key Vault Administrator/Officer roles) for workloads or deploy; every assignment must carry a
    `description` classifying it as workload:, deploy: or human:.
  * Container Apps: no external ingress (the origin is reachable only through the Cloudflare Tunnel); the environment must be internal with
    public network access disabled.
  * Container registry: admin user, anonymous pull or public network access are violations.
  * Managed HSM, Azure Firewall, Application Gateway, Bastion: not part of either profile.
  * lean only: nothing that bills a fixed fee beyond the plan's lean table (private endpoints, NAT gateway, public IPs, container registry,
    Service Bus other than Basic, Key Vault Premium, PostgreSQL other than Burstable, dedicated workload profiles).
  * Any other resource with public network access enabled is a violation.
  * Authority tier (Infra/azure-authority, ADR-0028 section 5; fail in both profiles): AUTH-KEY-SCOPE, AUTH-NO-PUBLIC-INGRESS,
    AUTH-IDENTITY-SEPARATE, AUTH-DEPLOY-SEPARATE, AUTH-EGRESS, AUTH-KEY-BACKUP, AUTH-SIGNER-ROLE, AUTH-ADMIN-NO-KV, AUTH-STANDBY-ROLE,
    AUTH-REVOCATIONS-ROLE; plus API-NO-NEW-KEYS (the api holds only the five exception keys), RESIDENCY-US (US regions only) and
    GHCR-NO-PAT (the registry pull secret is the dedicated credential, not the owner's PAT). Recorded exceptions: AUTH-OIDC-SUBJECT
    (federated subject without job_workflow_ref) and ACR-AUTH-PUBLIC (lean Basic registry).
  * `--source DIR` adds static source checks (API-NO-NEW-KEYS in locals.tf, GHCR-NO-PAT, no Cloudflare file naming the authority).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILES = ("lean", "standard")

PRIVILEGED_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
    "key vault administrator",
    "key vault crypto officer",
    "key vault secrets officer",
    "key vault certificates officer",
    "key vault data access administrator",
}
DEPLOY_RG_ROLES = {"container apps contributor"}
NEVER_ALLOWED_TYPES = {
    "azurerm_key_vault_managed_hardware_security_module": "Managed HSM is not used (ADR-0012)",
    "azurerm_firewall": "Azure Firewall is an owner decision (O-8), not part of either profile",
    "azurerm_application_gateway": "Application Gateway is not part of the design (Cloudflare is the edge)",
    "azurerm_bastion_host": "Bastion is not part of either profile (admin access through a Container Apps Job)",
    "azurerm_postgresql_flexible_server_firewall_rule": "PostgreSQL firewall rules imply public access, never allowed",
    "azurerm_key_vault_access_policy": "Key Vault access policies are forbidden (RBAC only)",
}
LEAN_FIXED_FEE_TYPES = {
    "azurerm_private_endpoint": "private endpoint (~USD 7.30/month each)",
    "azurerm_nat_gateway": "NAT gateway (~USD 32.85/month)",
    "azurerm_public_ip": "static public IP (~USD 3.65/month)",
    "azurerm_container_registry": "container registry (lean pulls from GHCR)",
    "azurerm_servicebus_namespace_disaster_recovery_config": "Service Bus geo-recovery (Premium)",
}


@dataclass
class Finding:
    rule: str
    address: str
    message: str


@dataclass
class Report:
    profile: str
    violations: list[Finding] = field(default_factory=list)
    exceptions: list[Finding] = field(default_factory=list)

    def violate(self, rule: str, address: str, message: str) -> None:
        self.violations.append(Finding(rule, address, message))

    def allow(self, rule: str, address: str, message: str) -> None:
        self.exceptions.append(Finding(rule, address, message))


class PlanError(Exception):
    pass


# ---- Plan access ----------------------------------------------------------------------------------------------------------
@dataclass
class Resource:
    address: str
    type: str
    name: str
    module: str
    after: dict
    unknown: dict
    expressions: dict

    def get(self, *path: str | int) -> tuple[Any, bool]:
        """(value, is_unknown) at a path in the planned values; nested blocks are lists of one object."""
        value: Any = self.after
        unknown: Any = self.unknown
        for key in path:
            if unknown is True:
                return None, True
            if isinstance(value, dict):
                value = value.get(key)
            elif isinstance(value, list) and isinstance(key, int) and key < len(value):
                value = value[key]
            else:
                value = None
            if isinstance(unknown, dict):
                unknown = unknown.get(key, False)
            elif isinstance(unknown, list) and isinstance(key, int) and key < len(unknown):
                unknown = unknown[key]
            else:
                unknown = False
        return value, unknown is True

    def block(self, name: str) -> dict | None:
        value, _ = self.get(name)
        if isinstance(value, list):
            return value[0] if value and isinstance(value[0], dict) else None
        return value if isinstance(value, dict) else None

    def references(self, attribute: str) -> list[str]:
        expr = self.expressions.get(attribute)
        if isinstance(expr, dict):
            return [r for r in expr.get("references", []) if isinstance(r, str)]
        return []


def _config_index(plan: dict) -> dict[tuple[str, str], dict]:
    index: dict[tuple[str, str], dict] = {}

    def walk(module: dict, prefix: str) -> None:
        for res in module.get("resources", []) or []:
            index[(prefix, res.get("address", ""))] = res.get("expressions", {}) or {}
        for name, call in (module.get("module_calls", {}) or {}).items():
            child = f"{prefix}.module.{name}" if prefix else f"module.{name}"
            walk(call.get("module", {}) or {}, child)

    walk((plan.get("configuration") or {}).get("root_module") or {}, "")
    return index


def _strip_module_prefix(module: str) -> str:
    # module_address "module.a[0].module.b" -> configuration path "module.a.module.b"
    return re.sub(r"\[[^\]]*\]", "", module or "")


def load_resources(plan: dict) -> list[Resource]:
    if not isinstance(plan, dict) or "format_version" not in plan:
        raise PlanError("not a `tofu show -json` document (format_version missing)")
    changes = plan.get("resource_changes")
    if changes is None:
        raise PlanError("no resource_changes: pass the JSON of a saved PLAN (tofu show -json tfplan), not of the state")
    config = _config_index(plan)
    resources = []
    for rc in changes:
        if rc.get("mode") != "managed":
            continue
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        if actions == ["delete"]:
            continue
        module = rc.get("module_address", "") or ""
        config_address = f"{rc.get('type')}.{rc.get('name')}"
        expressions = config.get((_strip_module_prefix(module), config_address), {})
        resources.append(Resource(
            address=rc.get("address", config_address),
            type=rc.get("type", ""),
            name=rc.get("name", ""),
            module=module,
            after=change.get("after") or {},
            unknown=change.get("after_unknown") or {},
            expressions=expressions,
        ))
    return resources


def plan_profile(plan: dict) -> str | None:
    value = ((plan.get("variables") or {}).get("profile") or {}).get("value")
    return value if isinstance(value, str) else None


# ---- Helpers --------------------------------------------------------------------------------------------------------------
def is_true(r: Resource, *path: str | int, default: bool | None = None) -> bool | None:
    """True/False when known; None when unknown; `default` when absent (Azure's default for the attribute)."""
    value, unknown = r.get(*path)
    if unknown:
        return None
    if value is None:
        return default
    return bool(value)


def azapi_type(r: Resource) -> str:
    value, _ = r.get("type")
    return value.split("@", 1)[0].lower() if isinstance(value, str) else ""


def azapi_props(r: Resource) -> dict:
    body, _ = r.get("body")
    if isinstance(body, str):  # older azapi versions keep the body as a JSON string
        try:
            body = json.loads(body)
        except ValueError:
            body = {}
    return (body or {}).get("properties", {}) if isinstance(body, dict) else {}


SUBSCRIPTION_RE = re.compile(r"^/subscriptions/[^/]+/?$", re.I)
MANAGEMENT_GROUP_RE = re.compile(r"^/providers/microsoft\.management/managementgroups/", re.I)
RESOURCE_GROUP_RE = re.compile(r"^/subscriptions/[^/]+/resourcegroups/[^/]+/?$", re.I)


def scope_kind(r: Resource) -> str:
    """subscription | management_group | resource_group | resource | unknown."""
    value, unknown = r.get("scope")
    if isinstance(value, str) and not unknown and value:
        if value == "/" or MANAGEMENT_GROUP_RE.match(value):
            return "management_group"
        if SUBSCRIPTION_RE.match(value):
            return "subscription"
        if RESOURCE_GROUP_RE.match(value):
            return "resource_group"
        if value.lower().startswith("/subscriptions/") and "/providers/" in value.lower():
            return "resource"
        return "unknown"
    kinds = set()
    for ref in r.references("scope"):
        head = ref.split("[", 1)[0]
        if head.startswith(("each.", "count.", "var.", "local.", "path.", "terraform.", "self.")):
            if head.startswith(("var.", "local.")):
                kinds.add("unknown")
            continue
        if head.startswith(("data.azurerm_subscription", "data.azurerm_client_config", "azurerm_subscription")):
            kinds.add("subscription")
        elif head.startswith(("azurerm_management_group", "data.azurerm_management_group")):
            kinds.add("management_group")
        elif head.startswith(("azurerm_resource_group", "data.azurerm_resource_group")):
            kinds.add("resource_group")
        elif head:
            kinds.add("resource")
    for worst in ("management_group", "subscription", "unknown", "resource_group", "resource"):
        if worst in kinds:
            return worst
    return "unknown"


# ---- Rules ----------------------------------------------------------------------------------------------------------------
def check_postgres(r: Resource, rep: Report) -> None:
    public = is_true(r, "public_network_access_enabled")
    if public is not False:
        rep.violate("PG-PUBLIC", r.address, "PostgreSQL public network access must be explicitly disabled (both profiles)")
    subnet, subnet_unknown = r.get("delegated_subnet_id")
    if not subnet and not subnet_unknown and not r.references("delegated_subnet_id"):
        rep.violate("PG-PRIVATE", r.address, "PostgreSQL must be VNet-integrated (delegated_subnet_id + private DNS zone)")
    auth = r.block("authentication") or {}
    if auth.get("active_directory_auth_enabled") is not True:
        rep.violate("PG-ENTRA", r.address, "Microsoft Entra authentication must be enabled")
    if auth.get("password_auth_enabled") is not False:
        rep.allow("PG-PASSWORD-AUTH", r.address, "password authentication enabled next to Entra: the opt-in fallback (Entra-only is the default since WP-B2); needs the CLAUDE.md exception row")
    ha = r.block("high_availability")
    backup_days, _ = r.get("backup_retention_days")
    geo = is_true(r, "geo_redundant_backup_enabled", default=False)
    if rep.profile == "standard":
        if not ha or str(ha.get("mode", "")).lower() != "zoneredundant":
            rep.violate("PG-HA", r.address, "standard profile requires zone-redundant HA")
        if not isinstance(backup_days, (int, float)) or backup_days < 35:
            rep.violate("PG-PITR", r.address, "standard profile requires PITR of 35 days")
        if geo is not True:
            rep.violate("PG-GEO-BACKUP", r.address, "standard profile requires geo-redundant backup")
    else:
        if not ha:
            rep.allow("PG-NO-HA", r.address, "lean: no HA standby (Burstable)")
        if not isinstance(backup_days, (int, float)) or backup_days < 7:
            rep.violate("PG-PITR", r.address, "PITR must be at least 7 days")
        sku, _ = r.get("sku_name")
        if isinstance(sku, str) and not sku.startswith("B_"):
            rep.violate("LEAN-FIXED-FEE", r.address, f"lean allows only Burstable PostgreSQL (got {sku})")
        if ha:
            rep.violate("LEAN-FIXED-FEE", r.address, "lean must not create a PostgreSQL HA standby")


def check_key_vault(r: Resource, rep: Report) -> None:
    if is_true(r, "purge_protection_enabled", default=False) is not True:
        rep.violate("KV-PURGE-PROTECTION", r.address, "Key Vault purge protection is mandatory")
    if is_true(r, "rbac_authorization_enabled", default=False) is not True:
        rep.violate("KV-RBAC", r.address, "Key Vault must use Azure RBAC authorization (no access policies)")
    policies, _ = r.get("access_policy")
    if policies:
        rep.violate("KV-RBAC", r.address, "Key Vault access policies are forbidden")
    public = is_true(r, "public_network_access_enabled", default=True)
    acls = r.block("network_acls") or {}
    if str(acls.get("default_action", "Allow")).lower() != "deny":
        rep.violate("KV-FIREWALL", r.address, "Key Vault network ACL default action must be Deny (lean admits only the Container Apps subnet)")
    if public is not False:
        if rep.profile == "lean" and is_true(r, "rbac_authorization_enabled") is True:
            rep.allow("KV-PUBLIC", r.address, "lean: Key Vault on its public endpoint (firewalled to the Container Apps subnet), Entra RBAC only")
        else:
            rep.violate("KV-PUBLIC", r.address, "Key Vault public network access must be disabled (standard profile; lean needs RBAC)")
    sku, _ = r.get("sku_name")
    if isinstance(sku, str) and sku.lower() != "premium":
        if rep.profile == "lean":
            rep.allow("KV-SOFTWARE-KEYS", r.address, "lean: Key Vault Standard, software-protected keys")
        else:
            rep.violate("KV-HSM", r.address, "standard profile requires Key Vault Premium (HSM-backed keys)")
    elif rep.profile == "lean" and isinstance(sku, str):
        rep.violate("LEAN-FIXED-FEE", r.address, "lean must not use Key Vault Premium (HSM keys bill per key per month)")


def check_kv_key(address: str, kty: Any, rep: Report) -> None:
    if not isinstance(kty, str):
        rep.violate("KV-KEY-TYPE", address, "key type unknown at plan time")
        return
    if not kty.upper().endswith("-HSM"):
        if rep.profile == "lean":
            rep.allow("KV-SOFTWARE-KEYS", address, f"lean: software-protected key ({kty})")
        else:
            rep.violate("KV-HSM", address, f"standard profile requires HSM keys (got {kty})")


BRAND_STORAGE_NAMES = {"brand"}


def _subnet_only_firewall(r: Resource) -> bool:
    """Deny by default, bypass nothing, at least one subnet rule and no IP rule (the Container Apps subnet's service endpoint only)."""
    rules = r.block("network_rules") or {}
    if str(rules.get("default_action", "Allow")).lower() != "deny":
        return False
    bypass = rules.get("bypass") or []
    if any(str(b).lower() != "none" for b in bypass):
        return False
    if rules.get("ip_rules"):
        return False
    subnets_value, subnets_unknown = r.get("network_rules", 0, "virtual_network_subnet_ids")
    return bool(subnets_value) or subnets_unknown


def check_storage(r: Resource, rep: Report) -> None:
    access, access_unknown = r.get("public_network_access")
    legacy = is_true(r, "public_network_access_enabled")
    disabled = (isinstance(access, str) and access.lower() == "disabled") or (access is None and not access_unknown and legacy is False)
    if not disabled:
        if (rep.profile == "lean" and r.name in BRAND_STORAGE_NAMES and _subnet_only_firewall(r)
                and is_true(r, "shared_access_key_enabled", default=True) is False
                and is_true(r, "allow_nested_items_to_be_public", default=True) is False):
            rep.allow("ST-BRAND-PUBLIC", r.address, "lean: brand-asset storage on its public endpoint, firewalled to the Container Apps subnet, Entra only")
        else:
            rep.violate("ST-PUBLIC", r.address, "storage public network access must be disabled (both profiles; lean brand assets need a subnet-only firewall)")
    if is_true(r, "shared_access_key_enabled", default=True) is not False:
        rep.violate("ST-SHARED-KEY", r.address, "storage shared-key access must be disabled (Entra only)")
    if is_true(r, "allow_nested_items_to_be_public", default=True) is not False:
        rep.violate("ST-PUBLIC-BLOBS", r.address, "public blob access must be disabled")


def check_service_bus(r: Resource, rep: Report) -> None:
    local_auth = is_true(r, "local_auth_enabled", default=True)
    if local_auth is not False:
        rep.violate("SB-LOCAL-AUTH", r.address, "Service Bus local (SAS) authentication must be disabled")
    public = is_true(r, "public_network_access_enabled", default=True)
    if public is not False:
        if rep.profile == "lean" and local_auth is False:
            rep.allow("SB-PUBLIC", r.address, "lean: Service Bus on its public endpoint, Entra tokens only")
        else:
            rep.violate("SB-PUBLIC", r.address, "Service Bus public network access must be disabled (standard profile; lean needs local auth off)")
    tls, _ = r.get("minimum_tls_version")
    if isinstance(tls, str) and tls in {"1.0", "1.1"}:
        rep.violate("SB-TLS", r.address, "Service Bus minimum TLS must be 1.2 or higher")
    sku, _ = r.get("sku")
    if rep.profile == "lean" and isinstance(sku, str) and sku.lower() != "basic":
        rep.violate("LEAN-FIXED-FEE", r.address, f"lean allows only Service Bus Basic (got {sku})")


def check_role_assignment(r: Resource, rep: Report) -> None:
    description, _ = r.get("description")
    description = description if isinstance(description, str) else ""
    klass = description.split(":", 1)[0].strip().lower() if ":" in description else ""
    if klass not in {"workload", "deploy", "human"}:
        rep.violate("RBAC-UNCLASSIFIED", r.address, "role assignment description must start with workload:, deploy: or human:")
    kind = scope_kind(r)
    role, role_unknown = r.get("role_definition_name")
    role = role.lower() if isinstance(role, str) else ""
    if kind in {"subscription", "management_group"}:
        rep.violate("RBAC-SCOPE", r.address, f"role assignment at {kind.replace('_', '-')} scope")
    elif kind == "unknown":
        rep.violate("RBAC-SCOPE", r.address, "role assignment scope cannot be determined from the plan")
    elif kind == "resource_group":
        if klass == "deploy" and role in DEPLOY_RG_ROLES:
            pass
        elif klass == "workload":
            rep.violate("RBAC-WORKLOAD-SCOPE", r.address, "workload identities get roles at resource scope only, never on a resource group")
        else:
            rep.violate("RBAC-SCOPE", r.address, f"{klass or 'unclassified'} role assignment on a resource group ({role or 'role unknown'})")
    if klass in {"workload", "deploy"}:
        if role_unknown or not role:
            rep.violate("RBAC-ROLE", r.address, "role must be given by name so it can be reviewed")
        elif role in PRIVILEGED_ROLES:
            rep.violate("RBAC-PRIVILEGED", r.address, f"privileged role '{role}' for a {klass} identity")


def check_container_app(r: Resource, rep: Report) -> None:
    ingress = r.block("ingress")
    if ingress and ingress.get("external_enabled") is not False:
        rep.violate("CA-EXTERNAL-INGRESS", r.address, "container app ingress must be environment-internal (origin only through the tunnel)")


def check_environment_azurerm(r: Resource, rep: Report) -> None:
    if is_true(r, "internal_load_balancer_enabled", default=False) is not True:
        rep.violate("CAE-INTERNAL", r.address, "Container Apps environment must be internal")
    access, _ = r.get("public_network_access")
    if isinstance(access, str) and access.lower() == "enabled":
        rep.violate("CAE-PUBLIC", r.address, "Container Apps environment public network access must be disabled")
    if rep.profile == "lean":
        profiles, _ = r.get("workload_profile")
        for wp in profiles or []:
            if isinstance(wp, dict) and str(wp.get("workload_profile_type", "")).lower() != "consumption":
                rep.violate("LEAN-FIXED-FEE", r.address, "lean allows only the Consumption workload profile")


def check_environment_azapi(r: Resource, rep: Report) -> None:
    props = azapi_props(r)
    vnet = props.get("vnetConfiguration") or {}
    if vnet.get("internal") is not True:
        rep.violate("CAE-INTERNAL", r.address, "Container Apps environment must be internal (vnetConfiguration.internal)")
    if str(props.get("publicNetworkAccess", "Enabled")).lower() != "disabled":
        rep.violate("CAE-PUBLIC", r.address, "Container Apps environment public network access must be disabled")
    if rep.profile == "lean":
        for wp in props.get("workloadProfiles") or []:
            if str((wp or {}).get("workloadProfileType", "")).lower() != "consumption":
                rep.violate("LEAN-FIXED-FEE", r.address, "lean allows only the Consumption workload profile")


def check_registry(r: Resource, rep: Report) -> None:
    if r.name == "auth" and rep.profile == "lean":
        # The authority has no Internet egress, so it cannot use GHCR: a Basic registry (no firewall exists below Premium), Entra only.
        sku, _ = r.get("sku")
        if is_true(r, "admin_enabled", default=False) is not False or is_true(r, "anonymous_pull_enabled", default=False) is not False:
            rep.violate("ACR-ADMIN", r.address, "authority registry: admin user and anonymous pull must be disabled")
        if isinstance(sku, str) and sku.lower() != "basic":
            rep.violate("LEAN-FIXED-FEE", r.address, f"lean allows only a Basic authority registry (got {sku})")
        rep.allow("ACR-AUTH-PUBLIC", r.address, "lean: authority registry (Basic) on its public endpoint, Entra tokens only; no GHCR egress for the authority")
        return
    if is_true(r, "admin_enabled", default=False) is not False:
        rep.violate("ACR-ADMIN", r.address, "registry admin user must be disabled")
    if is_true(r, "anonymous_pull_enabled", default=False) is not False:
        rep.violate("ACR-ANONYMOUS", r.address, "anonymous pull must be disabled")
    if is_true(r, "public_network_access_enabled", default=True) is not False:
        rep.violate("ACR-PUBLIC", r.address, "registry public network access must be disabled")


def check_generic_public(r: Resource, rep: Report) -> None:
    if is_true(r, "public_network_access_enabled") is True:
        rep.violate("PUBLIC-ACCESS", r.address, f"{r.type} has public network access enabled")
    access, _ = r.get("public_network_access")
    if isinstance(access, str) and access.lower() == "enabled":
        rep.violate("PUBLIC-ACCESS", r.address, f"{r.type} has public network access enabled")


# ---- Authority tier and cross-tier rules (ADR-0028 section 5) -------------------------------------------------------------------
US_REGIONS = {"centralus", "eastus", "eastus2", "southcentralus", "northcentralus", "westcentralus", "westus", "westus2", "westus3", "global"}
API_EXCEPTION_KEYS = {"kek-data", "kd-log-signing", "link-descriptor", "loop-publication", "brand-manifest"}
OFFICER_VARS = {"var.authority_crypto_officers_group_object_id", "var.authority_secrets_officers_group_object_id"}
ALLOWED_AUTH_DATA_ACTIONS = {
    "signer": {"Microsoft.KeyVault/vaults/keys/read", "Microsoft.KeyVault/vaults/keys/sign/action"},
    "unwrapper": {"Microsoft.KeyVault/vaults/keys/read", "Microsoft.KeyVault/vaults/keys/unwrap/action"},
    "decrypter": {"Microsoft.KeyVault/vaults/keys/read", "Microsoft.KeyVault/vaults/keys/decrypt/action"},
}
# Console/exec on the authority app (verify the exact name with `az provider operation show --namespace Microsoft.App`).
FORBIDDEN_AUTHORITY_ACTIONS = ("Microsoft.App/containerApps/getAuthToken/action",)


def deep_refs(expr: Any) -> list[str]:
    out: list[str] = []
    if isinstance(expr, dict):
        for key, value in expr.items():
            if key == "references" and isinstance(value, list):
                out += [v for v in value if isinstance(v, str)]
            else:
                out += deep_refs(value)
    elif isinstance(expr, list):
        for item in expr:
            out += deep_refs(item)
    return out


def ref_bases(refs: list[str]) -> set[str]:
    """`azurerm_user_assigned_identity.authority[0].principal_id` -> `azurerm_user_assigned_identity.authority`."""
    bases = set()
    for ref in refs:
        m = re.match(r"^((?:data\.)?[a-z0-9_]+\.[A-Za-z0-9_]+|var\.[A-Za-z0-9_]+)", ref)
        if m:
            bases.add(m.group(1))
    return bases


def index_of(address: str) -> str:
    m = re.search(r'\["([^"]+)"\]$', address)
    return m.group(1) if m else ""


def is_authority_plan(plan: dict, resources: list[Resource]) -> bool:
    if "authority_enabled" in (plan.get("variables") or {}):
        return True
    return any(r.address.startswith(("azurerm_user_assigned_identity.authority", "azurerm_container_app.authority")) for r in resources)


def role_name(r: Resource) -> str:
    value, _ = r.get("role_definition_name")
    return value.lower() if isinstance(value, str) else ""


def check_cross_tier(resources: list[Resource], rep: Report) -> None:
    """Rules that apply to the ordinary plan as well (API-NO-NEW-KEYS, GHCR-NO-PAT, RESIDENCY-US)."""
    for r in resources:
        if r.type == "azurerm_role_assignment" and r.name == "key_user" and index_of(r.address).startswith("api/"):
            key = index_of(r.address).split("/", 1)[1]
            if key not in API_EXCEPTION_KEYS:
                rep.violate("API-NO-NEW-KEYS", r.address, f"the api identity may hold only the five exception keys, not '{key}' (decision 12, ADR-0028)")
        if r.type == "azapi_resource" and azapi_type(r) == "microsoft.keyvault/vaults/secrets" and r.after.get("name") == "ghcr-pull-token":
            rep.violate("GHCR-NO-PAT", r.address, "the registry pull secret must be the dedicated deploy-owned credential (ghcr-pull-credential), not the owner's PAT")
        location, unknown = r.get("location")
        if isinstance(location, str) and not unknown and location.lower() not in US_REGIONS:
            rep.violate("RESIDENCY-US", r.address, f"location {location} is outside the Azure US regions (decision 13)")


def _check_role_definition(r: Resource, rep: Report) -> None:
    name, _ = r.get("name")
    name = (name or "").lower()
    perms = r.block("permissions") or {}
    data_actions = set(perms.get("data_actions") or [])
    actions = set(perms.get("actions") or [])
    kind = next((k for k in ALLOWED_AUTH_DATA_ACTIONS if f"authority {k}" in name), None)
    if kind and not data_actions <= ALLOWED_AUTH_DATA_ACTIONS[kind]:
        rep.violate("AUTH-SIGNER-ROLE", r.address, f"{name} grants {sorted(data_actions - ALLOWED_AUTH_DATA_ACTIONS[kind])} beyond its allow-list")
    if "backup" in " ".join(data_actions | actions).lower():
        rep.violate("AUTH-KEY-BACKUP", r.address, "no custom role may carry keys/backup/action (only the authority crypto-officer group holds it)")
    for bad in FORBIDDEN_AUTHORITY_ACTIONS:
        if bad in actions | data_actions:
            rep.violate("AUTH-SIGNER-ROLE", r.address, f"{bad} (console/exec on the authority app) must not be granted")
    if rep.profile == "standard" and kind == "unwrapper":
        rep.violate("AUTH-SIGNER-ROLE", r.address, "standard has no wrapped HPKE seal key: the Unwrapper role must not exist (C-16)")


def _check_vault_assignment(r: Resource, rep: Report, principals: set[str], rollover: bool) -> None:
    role = role_name(r)
    key = index_of(r.address)
    officer_only = bool(principals) and principals <= OFFICER_VARS
    if "azurerm_user_assigned_identity.authority_admin" in principals:
        rep.violate("AUTH-ADMIN-NO-KV", r.address, "id-viadere-authority-admin must hold no Key Vault role (ADR-0034 section 5.1)")
    elif not principals or not principals <= ({"azurerm_user_assigned_identity.authority"} | OFFICER_VARS):
        rep.violate("AUTH-KEY-SCOPE", r.address, "a role on kv-vdr-auth or its keys/secrets goes to id-viadere-authority or the authority officer groups only")
    if role in {"key vault crypto user", "key vault administrator", "key vault data access administrator"} or (
            role == "key vault crypto officer" and not officer_only):
        rep.violate("AUTH-KEY-BACKUP", r.address, f"'{role}' includes keys/backup/action: only the authority crypto-officer group may hold it")
    if "azurerm_user_assigned_identity.authority" in principals:
        custom = next((k for k in ALLOWED_AUTH_DATA_ACTIONS if role.startswith("viadere authority ") and k in role), None)
        if role == "key vault secrets user":
            pass
        elif not custom:
            rep.violate("AUTH-SIGNER-ROLE", r.address, f"id-viadere-authority may hold only the Signer/Unwrapper/Decrypter custom roles and Secrets User, not '{role}'")
        elif custom == "unwrapper" and key not in {"recovery-seal-kek", "recovery-seal-kek-standby"}:
            rep.violate("AUTH-SIGNER-ROLE", r.address, "the Unwrapper role is allowed on recovery-seal-kek only")
        elif custom == "decrypter" and key not in {"recovery-seal-rsa", "recovery-seal-rsa-standby"}:
            rep.violate("AUTH-SIGNER-ROLE", r.address, "the Decrypter role is allowed on recovery-seal-rsa only")
        elif custom == "signer" and ("kek" in key or "seal" in key):
            rep.violate("AUTH-SIGNER-ROLE", r.address, "the Signer role does not belong on seal keys")
    if "standby" in key and not officer_only and not (r.name == "rollover" and rollover):
        rep.violate("AUTH-STANDBY-ROLE", r.address, "a standby key has no role before a recorded rollover (rollover_change_file)")


def _check_app(r: Resource, rep: Report) -> None:
    name, _ = r.get("name")
    bases = ref_bases(deep_refs(r.expressions.get("identity")) + deep_refs(r.expressions.get("registry")))
    is_auth_app = isinstance(name, str) and "authority" in name
    if is_auth_app:
        if any(b.startswith(("azurerm_user_assigned_identity.workload", "azurerm_user_assigned_identity.acrpull")) for b in bases):
            rep.violate("AUTH-IDENTITY-SEPARATE", r.address, "an ordinary identity is attached to an authority app")
        if r.type == "azurerm_container_app":
            ingress = r.block("ingress")
            if not ingress or ingress.get("external_enabled") is not False:
                rep.violate("AUTH-NO-PUBLIC-INGRESS", r.address, "authority app ingress must exist and be internal (external_enabled = false)")
            elif ingress.get("allow_insecure_connections") is not False:
                rep.violate("AUTH-NO-PUBLIC-INGRESS", r.address, "authority ingress must be HTTPS only (allow_insecure_connections = false)")
    elif any(b.startswith("azurerm_user_assigned_identity.authority") for b in bases):
        rep.violate("AUTH-IDENTITY-SEPARATE", r.address, "id-viadere-authority* is attached to an app outside the authority group")


def _check_nsg(r: Resource, rep: Report) -> None:
    rules_ = r.after.get("security_rule") or []
    outbound_allow = [x.get("priority", 0) for x in rules_ if x.get("direction") == "Outbound" and x.get("access") == "Allow"]
    deny = [x.get("priority", 0) for x in rules_ if x.get("direction") == "Outbound" and x.get("access") == "Deny"
            and str(x.get("destination_address_prefix", "")).lower() == "internet"]
    if not deny or min(deny) <= max(outbound_allow or [0]):
        rep.violate("AUTH-EGRESS", r.address, "the authority NSG needs a final deny-Internet outbound rule after every allow rule")
    targets = {str(x.get("destination_address_prefix")) for x in rules_ if x.get("access") == "Allow" and x.get("direction") == "Outbound"}
    if targets & {"0.0.0.0/0", "*", "Internet"}:
        rep.violate("AUTH-EGRESS", r.address, "no outbound allow rule may target the whole Internet")


def check_authority(resources: list[Resource], rep: Report, plan: dict) -> None:
    variables = plan.get("variables") or {}
    rollover = bool((variables.get("rollover_change_file") or {}).get("value"))
    kv_scope = {"azurerm_key_vault.auth", "azapi_resource.kv_key", "azapi_resource.kv_secret"}
    tiers: dict[str, set[str]] = {}
    for r in resources:
        if r.type == "azurerm_role_definition":
            _check_role_definition(r, rep)
        if rep.profile == "standard" and r.type == "azapi_resource" and azapi_type(r) == "microsoft.keyvault/vaults/keys" and r.after.get("name") == "recovery-seal-kek":
            rep.violate("AUTH-SIGNER-ROLE", r.address, "standard must not create recovery-seal-kek (no wrapped HPKE seal key in production, C-16)")
        if r.type == "azurerm_role_assignment":
            principals = ref_bases(r.references("principal_id"))
            scopes = ref_bases(r.references("scope"))
            for pr in principals:
                if pr.startswith(("azurerm_user_assigned_identity.", "var.")):
                    if any(s.startswith("azurerm_user_assigned_identity.authority") or s in {"azurerm_resource_group.auth", "azurerm_container_registry.auth", "azurerm_container_app_job.admin"} for s in scopes):
                        tiers.setdefault(pr, set()).add("authority")
                    if any(s.startswith(("azurerm_user_assigned_identity.workload", "azurerm_resource_group.this")) for s in scopes):
                        tiers.setdefault(pr, set()).add("ordinary")
            if scopes & kv_scope:
                _check_vault_assignment(r, rep, principals, rollover)
        if r.type in {"azurerm_container_app", "azurerm_container_app_job"}:
            _check_app(r, rep)
        if r.type == "azapi_resource" and azapi_type(r) == "microsoft.app/managedenvironments" and "-auth" in str(r.after.get("name", "")):
            props = azapi_props(r)
            if (props.get("vnetConfiguration") or {}).get("internal") is not True or str(props.get("publicNetworkAccess", "")).lower() != "disabled":
                rep.violate("AUTH-NO-PUBLIC-INGRESS", r.address, "the authority environment must be internal with public network access disabled")
        if r.type == "azurerm_network_security_group" and "-auth" in str(r.after.get("name", "")):
            _check_nsg(r, rep)
        if r.type == "azuread_app_role_assignment":
            bases = ref_bases(deep_refs(r.expressions))
            if any("worker" in b for b in bases) and any("evidence_submit" in b.lower() for b in bases):
                rep.violate("AUTH-REVOCATIONS-ROLE", r.address, "the worker identity must not hold Authority.Evidence.Submit (only Authority.Revocations)")
        if r.type == "azurerm_federated_identity_credential":
            subject, _ = r.get("subject")
            if isinstance(subject, str) and "job_workflow_ref" not in subject:
                rep.allow("AUTH-OIDC-SUBJECT", r.address, "federated subject lacks job_workflow_ref (repository OIDC subject template not customised yet, ADR-0028 section 6.1)")
    for principal, kinds in tiers.items():
        if len(kinds) > 1:
            rep.violate("AUTH-DEPLOY-SEPARATE", principal, "one identity holds rights over both the ordinary and the authority tier")
    has_nsg = any(r.type == "azurerm_network_security_group" and "-auth" in str(r.after.get("name", "")) for r in resources)
    associated = any(r.type == "azurerm_subnet_network_security_group_association" and any("network_security_group.auth" in x for x in deep_refs(r.expressions)) for r in resources)
    if has_nsg and not associated:
        rep.violate("AUTH-EGRESS", "azurerm_network_security_group.auth", "the authority NSG is not associated with snet-auth")


def source_checks(directory: Path, rep: Report) -> None:
    """Static checks of a module directory (no plan): API-NO-NEW-KEYS, GHCR-NO-PAT and no Cloudflare file naming the authority."""
    locals_tf = directory / "locals.tf"
    if locals_tf.exists():
        text = locals_tf.read_text(encoding="utf-8")
        m = re.search(r"key_grants\s*=\s*\{(.*?)\n\s*\}", text, re.S)
        if m:
            api = re.search(r"^\s*api\s*=\s*\[(.*?)\]", m.group(1), re.S | re.M)
            keys = set(re.findall(r'"([a-z0-9-]+)"', api.group(1))) if api else set()
            for extra in sorted(keys - API_EXCEPTION_KEYS):
                rep.violate("API-NO-NEW-KEYS", str(locals_tf), f"key_grants.api names '{extra}': only the five exception keys are allowed")
        g = re.search(r'ghcr_pull_secret\s*=\s*"([^"]+)"', text)
        if g and g.group(1) == "ghcr-pull-token":
            rep.violate("GHCR-NO-PAT", str(locals_tf), "ghcr_pull_secret still names the owner's PAT secret")
    if directory.name == "cloudflare":
        for tf in directory.glob("*.tf"):
            body = "\n".join(line for line in tf.read_text(encoding="utf-8").splitlines() if not line.strip().startswith("#"))
            if re.search(r"authority", body, re.I):
                rep.violate("AUTH-NO-PUBLIC-INGRESS", str(tf), "a Cloudflare file names the authority: it has no tunnel route or hostname")


HANDLED = {
    "azurerm_postgresql_flexible_server": check_postgres,
    "azurerm_key_vault": check_key_vault,
    "azurerm_storage_account": check_storage,
    "azurerm_servicebus_namespace": check_service_bus,
    "azurerm_role_assignment": check_role_assignment,
    "azurerm_container_app": check_container_app,
    "azurerm_container_app_environment": check_environment_azurerm,
    "azurerm_container_registry": check_registry,
}


def evaluate(plan: dict, profile: str | None = None) -> Report:
    declared = plan_profile(plan)
    if profile and declared and profile != declared:
        raise PlanError(f"--profile {profile} does not match the plan's profile variable ({declared})")
    profile = profile or declared or "lean"
    if profile not in PROFILES:
        raise PlanError(f"unknown profile {profile!r}")
    rep = Report(profile=profile)
    all_resources = load_resources(plan)
    check_cross_tier(all_resources, rep)
    if is_authority_plan(plan, all_resources):
        check_authority(all_resources, rep, plan)
    for r in all_resources:
        if r.type in NEVER_ALLOWED_TYPES:
            rep.violate("FORBIDDEN-RESOURCE", r.address, NEVER_ALLOWED_TYPES[r.type])
            continue
        if profile == "lean" and r.type in LEAN_FIXED_FEE_TYPES and not (r.type == "azurerm_container_registry" and r.name == "auth"):
            rep.violate("LEAN-FIXED-FEE", r.address, f"lean must not create a {LEAN_FIXED_FEE_TYPES[r.type]}")
        if r.type == "azapi_resource":
            kind = azapi_type(r)
            if kind == "microsoft.app/managedenvironments":
                check_environment_azapi(r, rep)
            elif kind == "microsoft.keyvault/vaults/keys":
                check_kv_key(r.address, azapi_props(r).get("kty"), rep)
            elif kind == "microsoft.keyvault/managedhsms":
                rep.violate("FORBIDDEN-RESOURCE", r.address, "Managed HSM is not used (ADR-0012)")
            continue
        if r.type == "azurerm_key_vault_key":
            kty, _ = r.get("key_type")
            check_kv_key(r.address, kty, rep)
            continue
        handler = HANDLED.get(r.type)
        if handler:
            handler(r, rep)
        else:
            check_generic_public(r, rep)
    return rep


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.rule, f.address, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("plan", help="output of `tofu show -json <planfile>`")
    parser.add_argument("--profile", choices=PROFILES, help="expected profile (default: the plan's `profile` variable)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--source", action="append", default=[], metavar="DIR", help="also run the static source checks on this module directory (repeatable)")
    args = parser.parse_args(argv)
    try:
        with open(args.plan, encoding="utf-8") as fh:
            plan = json.load(fh)
        rep = evaluate(plan, args.profile)
        for directory in args.source:
            source_checks(Path(directory), rep)
    except (OSError, ValueError, PlanError) as exc:
        print(f"policy_check: {exc}", file=sys.stderr)
        return 2
    violations, exceptions = _dedupe(rep.violations), _dedupe(rep.exceptions)
    if args.json:
        print(json.dumps({
            "profile": rep.profile,
            "violations": [f.__dict__ for f in violations],
            "exceptions": [f.__dict__ for f in exceptions],
        }, indent=2))
    else:
        print(f"profile: {rep.profile}")
        for f in exceptions:
            print(f"EXCEPTION {f.rule:<20} {f.address}: {f.message}")
        for f in violations:
            print(f"VIOLATION {f.rule:<20} {f.address}: {f.message}")
        print(f"{len(violations)} violation(s), {len(exceptions)} recorded exception(s)")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
