#!/usr/bin/env python3
"""Point the staging hostnames under viadere.io at the Azure Cloudflare Tunnel (Python standard library only; run from any machine).

    python3 -I Infra/cloudflare/point_staging_to_azure.py            # shows the plan, asks before changing anything

Staging lives on subdomains of the production zone (owner decision 2026-11-16): staging.viadere.io (web, links, passkey RP, AASA) and
api-staging.viadere.io (API). What it does, for zone viadere.io and tunnel viadere-staging-azure:
  1. Tunnel: adds public hostnames api-staging.viadere.io and staging.viadere.io -> http://ca-viadere-api (Host header ca-viadere-api),
     before the catch-all rule, and removes the retired cksites.dev hostnames (viadere-api-az, viadere-api, viadere, viadere-assets).
  2. DNS: replaces the records of those two names (A/AAAA/CNAME) and their _acme-challenge records with proxied CNAMEs to
     <tunnel id>.cfargotunnel.com.
  3. Origin lock: a request-header Transform Rule that SETS X-Viadere-Edge-Token for exactly the staging hostnames the tunnel sends to
     the origin (api-staging, staging, and assets-staging once add_asset_host.py has added it). An existing staging rule in the zone keeps
     its value; otherwise the value is copied from the old cksites.dev staging rule when this token can read that zone, or asked for (hidden
     input: the staging api's EDGE_TOKEN, Key Vault secret edge-token). It is never printed. It must not be production's value.

It never touches the production names (viadere.io, www.viadere.io, api.viadere.io): it refuses to run if the tunnel routes one of them,
and it never edits or deletes a Transform Rule that names a host other than a staging one. Production's own rules stay as they are.

The API token is read without echo. It needs: Zone > Zone: Read, Zone > DNS: Edit, Zone > Transform Rules: Edit (zone viadere.io;
optionally Zone: Read and Transform Rules: Read on cksites.dev to copy the old edge token) and Account > Cloudflare Tunnel: Edit. Create it
at dash.cloudflare.com > My Profile > API Tokens > Create Token > Custom token, and delete it afterwards. Nothing is written to disk.
Re-running is safe.
"""
import getpass
import json
import re
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "viadere.io"
TUNNEL_NAME = "viadere-staging-azure"
STAGING_HOSTS = ["api-staging.viadere.io", "staging.viadere.io"]
# Staging names this tunnel may carry (the asset host is added by add_asset_host.py); the edge-token rule covers those it routes.
STAGING_ROUTED = STAGING_HOSTS + ["assets-staging.viadere.io"]
PRODUCTION_HOSTS = {"viadere.io", "www.viadere.io", "api.viadere.io"}
LEGACY_ZONE = "cksites.dev"
LEGACY_HOSTS = {"viadere-api-az.cksites.dev", "viadere-api.cksites.dev", "viadere.cksites.dev", "viadere-assets.cksites.dev"}
ORIGIN = "http://ca-viadere-api"
HOST_HEADER = "ca-viadere-api"
EDGE_HEADER = "X-Viadere-Edge-Token"
EDGE_RULE_DESC = "Viadere staging origin edge token"
PHASE = "http_request_late_transform"
STAGING_NAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?-)?staging\.viadere\.io")


def is_staging(host):
    """staging.viadere.io or <label>-staging.viadere.io: one label below the zone, never a production name."""
    return bool(STAGING_NAME.fullmatch(host)) and host not in PRODUCTION_HOSTS


class CF:
    def __init__(self, token):
        self.token = token

    def call(self, method, path, body=None, allow_404=False, allow_403=False):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(API + path, data=data, method=method,
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as err:
            if (allow_404 and err.code == 404) or (allow_403 and err.code == 403):
                return None
            try:
                errors = json.load(err).get("errors", [])
            except Exception:
                errors = []
            detail = "; ".join(str(e.get("message", e)) for e in errors) or err.reason
            raise SystemExit(f"Cloudflare API {method} {path.split('?')[0]}: HTTP {err.code}: {detail}")
        except urllib.error.URLError as err:
            raise SystemExit(f"cannot reach the Cloudflare API: {err.reason} (on macOS with python.org Python, run 'Install Certificates.command')")
        if not payload.get("success", False):
            raise SystemExit(f"Cloudflare API {method} {path.split('?')[0]}: {payload.get('errors')}")
        return payload.get("result")


def sets_header(rule, name):
    headers = (rule.get("action_parameters") or {}).get("headers") or {}
    return any(h.lower() == name.lower() for h in headers)


def named_hosts(expression):
    return re.findall(r'"([A-Za-z0-9.-]+)"', expression or "")


def classify_edge_rules(rules):
    """(the one staging edge-token rule or None, the rules left alone). Refuses a rule that mixes staging and other names, or that sets
    the header without naming its hosts (it could cover a staging host and overwrite the staging value)."""
    staging, others = [], []
    for rule in rules or []:
        if not sets_header(rule, EDGE_HEADER):
            continue
        hosts = named_hosts(rule.get("expression"))
        if not hosts:
            raise SystemExit(f"edge-token rule '{rule.get('description', '')}' names no hostnames ({rule.get('expression', '')}); "
                             "it may also cover staging: fix it in the dashboard first")
        ours = [h for h in hosts if is_staging(h)]
        if ours and len(ours) != len(hosts):
            raise SystemExit(f"edge-token rule '{rule.get('description', '')}' mixes staging and other hostnames: fix it in the dashboard first")
        (staging if ours else others).append(rule)
    if len(staging) > 1:
        raise SystemExit(f"found {len(staging)} edge-token rules for staging hostnames; keep one in the dashboard first")
    return (staging[0] if staging else None), others


def legacy_edge_parameters(cf):
    """action_parameters of the old cksites.dev staging edge-token rule, when this token can read it (value never printed)."""
    zones = cf.call("GET", f"/zones?name={LEGACY_ZONE}", allow_404=True, allow_403=True) or []
    if not zones:
        return None
    ruleset = cf.call("GET", f"/zones/{zones[0]['id']}/rulesets/phases/{PHASE}/entrypoint", allow_404=True, allow_403=True)
    for rule in (ruleset or {}).get("rules") or []:
        if sets_header(rule, EDGE_HEADER) and set(named_hosts(rule.get("expression"))) & LEGACY_HOSTS:
            return rule.get("action_parameters")
    return None


def main():
    for host in STAGING_ROUTED:
        assert is_staging(host), host
    token = getpass.getpass("Cloudflare API token (input hidden): ").strip()
    if not token:
        raise SystemExit("no token")
    cf = CF(token)

    zones = cf.call("GET", f"/zones?name={ZONE}")
    if not zones:
        raise SystemExit(f"zone {ZONE} not visible to this token")
    zone_id, account_id = zones[0]["id"], zones[0]["account"]["id"]

    tunnels = cf.call("GET", f"/accounts/{account_id}/cfd_tunnel?name={TUNNEL_NAME}&is_deleted=false")
    if not tunnels:
        raise SystemExit(f"tunnel {TUNNEL_NAME} not found (needs Account > Cloudflare Tunnel: Edit)")
    tunnel_id = tunnels[0]["id"]
    target = f"{tunnel_id}.cfargotunnel.com"

    # 1. tunnel ingress
    config = (cf.call("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations") or {}).get("config") or {}
    ingress = list(config.get("ingress") or [])
    present = {rule.get("hostname") for rule in ingress if rule.get("hostname")}
    if present & PRODUCTION_HOSTS:
        raise SystemExit(f"the staging tunnel routes a production name ({', '.join(sorted(present & PRODUCTION_HOSTS))}); fix it by hand first")
    add_ingress = [h for h in STAGING_HOSTS if h not in present]
    remove_ingress = sorted(present & LEGACY_HOSTS)
    catch_all = [r for r in ingress if not r.get("hostname")]
    named = [r for r in ingress if r.get("hostname") and r.get("hostname") not in LEGACY_HOSTS]
    new_ingress = named + [{"hostname": h, "service": ORIGIN, "originRequest": {"httpHostHeader": HOST_HEADER}} for h in add_ingress] \
        + (catch_all or [{"service": "http_status:404"}])
    routed = {r.get("hostname") for r in new_ingress if r.get("hostname")}

    # 2. DNS
    delete_records, create_hosts = [], []
    for host in STAGING_HOSTS:
        records = cf.call("GET", f"/zones/{zone_id}/dns_records?name={host}&per_page=100") or []
        keep = [r for r in records if r["type"] == "CNAME" and r["content"] == target and r.get("proxied")]
        delete_records += [r for r in records if r not in keep and r["type"] in ("CNAME", "A", "AAAA")]
        if not keep:
            create_hosts.append(host)
        delete_records += cf.call("GET", f"/zones/{zone_id}/dns_records?name=_acme-challenge.{host}&per_page=100") or []
    for r in delete_records:
        if r["name"].lower() in PRODUCTION_HOSTS or not r["name"].lower().endswith("staging.viadere.io"):
            raise SystemExit(f"refusing to delete {r['type']} {r['name']}: not a staging name")

    # 3. origin-lock header rule
    ruleset = cf.call("GET", f"/zones/{zone_id}/rulesets/phases/{PHASE}/entrypoint", allow_404=True)
    staging_rule, other_rules = classify_edge_rules((ruleset or {}).get("rules"))
    covered = [h for h in STAGING_ROUTED if h in routed]
    expression = "(http.host in {" + " ".join(f'"{h}"' for h in covered) + "})"
    parameters, source = None, "unchanged"
    if staging_rule is None:
        parameters = legacy_edge_parameters(cf)
        source = "copied from the old cksites.dev staging rule"
        if parameters is None:
            value = getpass.getpass("Staging EDGE_TOKEN value (Key Vault secret edge-token; input hidden): ").strip()
            if len(value) < 32:
                raise SystemExit("the edge token must be at least 32 characters")
            parameters = {"headers": {EDGE_HEADER: {"operation": "set", "value": value}}}
            source = "entered"
        # The staging value must never equal production's: a staging host would then carry production's origin secret.
        for rule in other_rules:
            mine = ((parameters.get("headers") or {}).get(EDGE_HEADER) or {}).get("value")
            theirs = (((rule.get("action_parameters") or {}).get("headers") or {}).get(EDGE_HEADER) or {}).get("value")
            if mine and theirs and mine == theirs:
                raise SystemExit("the staging edge token equals the value of a non-staging rule: rotate the staging EDGE_TOKEN first")

    print(f"\nZone {ZONE}, tunnel {TUNNEL_NAME} ({tunnel_id})\n")
    print("Tunnel public hostnames to add:", ", ".join(add_ingress) or "none (already there)")
    print("Tunnel public hostnames to remove (retired):", ", ".join(remove_ingress) or "none")
    for r in delete_records:
        print(f"DNS delete: {r['type']} {r['name']} -> {r['content']}")
    for h in create_hosts:
        print(f"DNS create: CNAME {h} -> {target} (proxied)")
    if staging_rule:
        print(f"Edge-token rule '{staging_rule.get('description', '')}': expression -> {expression} (value unchanged)")
    else:
        print(f"Edge-token rule create '{EDGE_RULE_DESC}': {expression} (value {source}, not shown)")
    for r in other_rules:
        print(f"Edge-token rule left alone (not staging): '{r.get('description', '')}'")
    if input("\nApply these changes? Type yes: ").strip() != "yes":
        raise SystemExit("nothing changed")

    if add_ingress or remove_ingress:
        cf.call("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", {"config": dict(config, ingress=new_ingress)})
        print("tunnel hostnames updated")
    for r in delete_records:
        cf.call("DELETE", f"/zones/{zone_id}/dns_records/{r['id']}")
        print(f"deleted {r['type']} {r['name']}")
    for h in create_hosts:
        cf.call("POST", f"/zones/{zone_id}/dns_records", {"type": "CNAME", "name": h, "content": target, "proxied": True,
                                                          "comment": "Viadere Azure staging via Cloudflare Tunnel"})
        print(f"created CNAME {h}")
    if staging_rule:
        patch = {key: staging_rule[key] for key in ("action", "action_parameters", "description", "enabled") if key in staging_rule}
        patch["expression"] = expression
        cf.call("PATCH", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules/{staging_rule['id']}", patch)
    else:
        body = {"action": "rewrite", "expression": expression, "description": EDGE_RULE_DESC, "enabled": True, "action_parameters": parameters}
        if ruleset:
            cf.call("POST", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules", body)
        else:
            cf.call("PUT", f"/zones/{zone_id}/rulesets/phases/{PHASE}/entrypoint", {"rules": [body]})
    print("edge-token rule covers exactly: " + ", ".join(covered))
    print("\nDONE. Check: curl -fsS https://api-staging.viadere.io/healthz && curl -fsS https://staging.viadere.io/.well-known/apple-app-site-association")
    print(f"Then delete the old {LEGACY_ZONE} staging records and its edge-token rule by hand (docs/ops/LAUNCH.md, 'Move staging to viadere.io').")
    return 0


if __name__ == "__main__":
    sys.exit(main())
