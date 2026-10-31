#!/usr/bin/env python3
"""Point the staging hostnames at the Azure Cloudflare Tunnel (Python standard library only; run from any machine).

    python3 -I Infra/cloudflare/point_staging_to_azure.py            # shows the plan, asks before changing anything

What it does, for zone cksites.dev and tunnel viadere-staging-azure:
  1. Tunnel: adds public hostnames viadere-api.cksites.dev and viadere.cksites.dev -> http://ca-viadere-api (Host header ca-viadere-api),
     next to the existing viadere-api-az.cksites.dev, before the catch-all rule.
  2. DNS: replaces the records of those two names (the old Fly CNAMEs, A/AAAA) and their _acme-challenge records with proxied CNAMEs to
     <tunnel id>.cfargotunnel.com.
  3. Origin lock: widens the request-header Transform Rule that sends X-Viadere-Edge-Token for viadere-api-az.cksites.dev to all three
     names, keeping its value (read from Cloudflare, never printed), and deletes other rules that set the same header (the Fly ones),
     which would otherwise overwrite it.

The API token is read without echo. It needs: Zone > Zone: Read, Zone > DNS: Edit, Zone > Transform Rules: Edit (zone cksites.dev) and
Account > Cloudflare Tunnel: Edit. Create it at dash.cloudflare.com > My Profile > API Tokens > Create Token > Custom token, and delete it
afterwards. Nothing is written to disk.
"""
import getpass
import json
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "cksites.dev"
TUNNEL_NAME = "viadere-staging-azure"
EXISTING_HOST = "viadere-api-az.cksites.dev"
NEW_HOSTS = ["viadere-api.cksites.dev", "viadere.cksites.dev"]
ORIGIN = "http://ca-viadere-api"
HOST_HEADER = "ca-viadere-api"
EDGE_HEADER = "X-Viadere-Edge-Token"
PHASE = "http_request_late_transform"


class CF:
    def __init__(self, token):
        self.token = token

    def call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(API + path, data=data, method=method,
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as err:
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


def edge_rules(rules):
    """Rules of the request-header transform phase that set the edge-token header."""
    out = []
    for rule in rules or []:
        headers = (rule.get("action_parameters") or {}).get("headers") or {}
        if any(name.lower() == EDGE_HEADER.lower() for name in headers):
            out.append(rule)
    return out


def main():
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
    present = {rule.get("hostname") for rule in ingress}
    if EXISTING_HOST not in present:
        raise SystemExit(f"the tunnel has no public hostname {EXISTING_HOST}; is this the right tunnel?")
    add_ingress = [h for h in NEW_HOSTS if h not in present]
    catch_all = [r for r in ingress if not r.get("hostname")]
    named = [r for r in ingress if r.get("hostname")]
    new_ingress = named + [{"hostname": h, "service": ORIGIN, "originRequest": {"httpHostHeader": HOST_HEADER}} for h in add_ingress] \
        + (catch_all or [{"service": "http_status:404"}])

    # 2. DNS
    delete_records, create_hosts = [], []
    for host in NEW_HOSTS:
        records = cf.call("GET", f"/zones/{zone_id}/dns_records?name={host}&per_page=100") or []
        keep = [r for r in records if r["type"] == "CNAME" and r["content"] == target and r.get("proxied")]
        delete_records += [r for r in records if r not in keep and r["type"] in ("CNAME", "A", "AAAA")]
        if not keep:
            create_hosts.append(host)
        delete_records += cf.call("GET", f"/zones/{zone_id}/dns_records?name=_acme-challenge.{host}&per_page=100") or []

    # 3. origin-lock header rule
    try:
        ruleset = cf.call("GET", f"/zones/{zone_id}/rulesets/phases/{PHASE}/entrypoint")
    except SystemExit as err:
        raise SystemExit(f"{err}\n(no request-header Transform Rule exists yet: create the edge-token rule for {EXISTING_HOST} first)")
    rules = edge_rules(ruleset.get("rules"))
    azure = [r for r in rules if EXISTING_HOST in r.get("expression", "")]
    if len(azure) != 1:
        raise SystemExit(f"expected exactly one edge-token rule mentioning {EXISTING_HOST}, found {len(azure)}; fix it in the dashboard")
    azure_rule = azure[0]
    other_rules = [r for r in rules if r["id"] != azure_rule["id"]]
    hosts = [EXISTING_HOST] + NEW_HOSTS
    expression = "(http.host in {" + " ".join(f'"{h}"' for h in hosts) + "})"

    print(f"\nZone {ZONE}, tunnel {TUNNEL_NAME} ({tunnel_id})\n")
    print("Tunnel public hostnames to add:", ", ".join(add_ingress) or "none (already there)")
    for r in delete_records:
        print(f"DNS delete: {r['type']} {r['name']} -> {r['content']}")
    for h in create_hosts:
        print(f"DNS create: CNAME {h} -> {target} (proxied)")
    print(f"Edge-token rule '{azure_rule.get('description', '')}': expression -> {expression} (value unchanged)")
    for r in other_rules:
        print(f"Edge-token rule delete: '{r.get('description', '')}' ({r.get('expression', '')})")
    if input("\nApply these changes? Type yes: ").strip() != "yes":
        raise SystemExit("nothing changed")

    if add_ingress:
        cf.call("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", {"config": dict(config, ingress=new_ingress)})
        print("tunnel hostnames added")
    for r in delete_records:
        cf.call("DELETE", f"/zones/{zone_id}/dns_records/{r['id']}")
        print(f"deleted {r['type']} {r['name']}")
    for h in create_hosts:
        cf.call("POST", f"/zones/{zone_id}/dns_records", {"type": "CNAME", "name": h, "content": target, "proxied": True,
                                                          "comment": "Azure staging via Cloudflare Tunnel"})
        print(f"created CNAME {h}")
    patch = {key: azure_rule[key] for key in ("action", "action_parameters", "description", "enabled") if key in azure_rule}
    patch["expression"] = expression
    cf.call("PATCH", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules/{azure_rule['id']}", patch)
    print("edge-token rule now covers all three hostnames")
    for r in other_rules:
        cf.call("DELETE", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules/{r['id']}")
        print(f"deleted edge-token rule '{r.get('description', '')}'")
    print("\nDONE. Check: curl -fsS https://viadere-api.cksites.dev/healthz && curl -fsS https://viadere.cksites.dev/.well-known/apple-app-site-association")
    return 0


if __name__ == "__main__":
    sys.exit(main())
