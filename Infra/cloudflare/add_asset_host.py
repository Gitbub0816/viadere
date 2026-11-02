#!/usr/bin/env python3
"""Add the Brand Kit asset host to the Azure staging tunnel (Python standard library only; run from any machine).

    python3 -I Infra/cloudflare/add_asset_host.py                       # host viadere-assets.cksites.dev, shows the plan, asks first
    python3 -I Infra/cloudflare/add_asset_host.py other-host.cksites.dev

AZURE-SETUP.md section 9.1, for zone cksites.dev and tunnel viadere-staging-azure:
  1. Tunnel: public hostname {host} -> http://ca-viadere-api (Host header ca-viadere-api), before the catch-all rule.
  2. DNS: a proxied CNAME {host} -> <tunnel id>.cfargotunnel.com (replacing other A/AAAA/CNAME records of that name).
  3. Origin lock: adds {host} to the existing request-header Transform Rule that sets X-Viadere-Edge-Token (its value is kept, never printed).
  4. Asset header: a request-header Transform Rule for {host} only that SETS X-Viadere-Asset-Host to {host} (a client value is overwritten;
     the server never reads Host and recognises asset traffic by this header).
  5. Cache: a cache rule for {host} and paths starting with /b/: eligible for cache, edge TTL respects the origin (immutable, one year).
     The query string stays in the cache key (the origin answers any query string 404).

The API token is read without echo. It needs: Zone > Zone: Read, Zone > DNS: Edit, Zone > Transform Rules: Edit, Zone > Cache Rules: Edit
(zone cksites.dev) and Account > Cloudflare Tunnel: Edit. Delete the token afterwards. Nothing is written to disk. Re-running is safe.
"""
import getpass
import json
import re
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "cksites.dev"
TUNNEL_NAME = "viadere-staging-azure"
ANCHOR_HOST = "viadere-api.cksites.dev"  # the edge-token rule already covers this host
ORIGIN = "http://ca-viadere-api"
HOST_HEADER = "ca-viadere-api"
EDGE_HEADER = "X-Viadere-Edge-Token"
ASSET_HEADER = "X-Viadere-Asset-Host"
TRANSFORM_PHASE = "http_request_late_transform"
CACHE_PHASE = "http_request_cache_settings"
ASSET_RULE_DESC = "Viadere asset host header"
CACHE_RULE_DESC = "Viadere brand assets cache"


class CF:
    def __init__(self, token):
        self.token = token

    def call(self, method, path, body=None, allow_404=False):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(API + path, data=data, method=method,
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as err:
            if allow_404 and err.code == 404:
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


def main():
    host = (sys.argv[1] if len(sys.argv) > 1 else "viadere-assets." + ZONE).lower()
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\." + re.escape(ZONE), host):
        raise SystemExit(f"{host}: must be a single label under {ZONE}")
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
    add_ingress = host not in {r.get("hostname") for r in ingress}
    named = [r for r in ingress if r.get("hostname")]
    catch_all = [r for r in ingress if not r.get("hostname")] or [{"service": "http_status:404"}]
    new_ingress = named + ([{"hostname": host, "service": ORIGIN, "originRequest": {"httpHostHeader": HOST_HEADER}}] if add_ingress else []) + catch_all

    # 2. DNS
    records = cf.call("GET", f"/zones/{zone_id}/dns_records?name={host}&per_page=100") or []
    keep = [r for r in records if r["type"] == "CNAME" and r["content"] == target and r.get("proxied")]
    delete_records = [r for r in records if r not in keep and r["type"] in ("CNAME", "A", "AAAA")]

    # 3 + 4. request-header transform rules
    ruleset = cf.call("GET", f"/zones/{zone_id}/rulesets/phases/{TRANSFORM_PHASE}/entrypoint", allow_404=True)
    if not ruleset:
        raise SystemExit("no request-header Transform Rules exist: run point_staging_to_azure.py first (it sets up the edge-token rule)")
    rules = ruleset.get("rules") or []
    edge = [r for r in rules if sets_header(r, EDGE_HEADER) and ANCHOR_HOST in r.get("expression", "")]
    if len(edge) != 1:
        raise SystemExit(f"expected exactly one edge-token rule covering {ANCHOR_HOST}, found {len(edge)}; fix it in the dashboard")
    edge_rule = edge[0]
    hosts = re.findall(r'"([a-z0-9.-]+)"', edge_rule.get("expression", ""))
    edge_needs_host = host not in hosts
    edge_expression = "(http.host in {" + " ".join(f'"{h}"' for h in hosts + ([host] if edge_needs_host else [])) + "})"
    asset_expression = f'(http.host eq "{host}")'
    asset_rule = next((r for r in rules if sets_header(r, ASSET_HEADER)), None)
    asset_ok = bool(asset_rule) and asset_rule.get("expression") == asset_expression and \
        ((asset_rule.get("action_parameters") or {}).get("headers") or {}).get(ASSET_HEADER, {}).get("value") == host
    asset_body = {"action": "rewrite", "expression": asset_expression, "description": ASSET_RULE_DESC, "enabled": True,
                  "action_parameters": {"headers": {ASSET_HEADER: {"operation": "set", "value": host}}}}

    # 5. cache rule
    cache_rs = cf.call("GET", f"/zones/{zone_id}/rulesets/phases/{CACHE_PHASE}/entrypoint", allow_404=True)
    cache_expression = f'(http.host eq "{host}" and starts_with(http.request.uri.path, "/b/"))'
    cache_rule = next((r for r in (cache_rs or {}).get("rules") or [] if r.get("description") == CACHE_RULE_DESC), None)
    cache_body = {"action": "set_cache_settings", "expression": cache_expression, "description": CACHE_RULE_DESC, "enabled": True,
                  "action_parameters": {"cache": True, "edge_ttl": {"mode": "respect_origin"}}}
    cache_ok = bool(cache_rule) and cache_rule.get("expression") == cache_expression

    print(f"\nZone {ZONE}, tunnel {TUNNEL_NAME} ({tunnel_id}), asset host {host}\n")
    print("Tunnel hostname:", f"add {host}" if add_ingress else "already there")
    for r in delete_records:
        print(f"DNS delete: {r['type']} {r['name']} -> {r['content']}")
    print("DNS:", "already a proxied tunnel CNAME" if keep else f"create CNAME {host} -> {target} (proxied)")
    print("Edge-token rule:", f"add {host} (value unchanged)" if edge_needs_host else "already covers the host")
    print("Asset header rule:", "already correct" if asset_ok else f"{'update' if asset_rule else 'create'}: set {ASSET_HEADER}: {host} for {host} only")
    print("Cache rule:", "already correct" if cache_ok else f"{'update' if cache_rule else 'create'}: cache /b/* on {host}, edge TTL from origin")
    if input("\nApply these changes? Type yes: ").strip() != "yes":
        raise SystemExit("nothing changed")

    if add_ingress:
        cf.call("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", {"config": dict(config, ingress=new_ingress)})
        print("tunnel hostname added")
    for r in delete_records:
        cf.call("DELETE", f"/zones/{zone_id}/dns_records/{r['id']}")
        print(f"deleted {r['type']} {r['name']}")
    if not keep:
        cf.call("POST", f"/zones/{zone_id}/dns_records", {"type": "CNAME", "name": host, "content": target, "proxied": True,
                                                          "comment": "Viadere brand assets via Cloudflare Tunnel"})
        print(f"created CNAME {host}")
    if edge_needs_host:
        patch = {k: edge_rule[k] for k in ("action", "action_parameters", "description", "enabled") if k in edge_rule}
        patch["expression"] = edge_expression
        cf.call("PATCH", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules/{edge_rule['id']}", patch)
        print("edge-token rule now covers the asset host")
    if not asset_ok:
        if asset_rule:
            cf.call("PATCH", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules/{asset_rule['id']}", asset_body)
        else:
            cf.call("POST", f"/zones/{zone_id}/rulesets/{ruleset['id']}/rules", asset_body)
        print("asset header rule set")
    if not cache_ok:
        if cache_rs and cache_rule:
            cf.call("PATCH", f"/zones/{zone_id}/rulesets/{cache_rs['id']}/rules/{cache_rule['id']}", cache_body)
        elif cache_rs:
            cf.call("POST", f"/zones/{zone_id}/rulesets/{cache_rs['id']}/rules", cache_body)
        else:
            cf.call("PUT", f"/zones/{zone_id}/rulesets/phases/{CACHE_PHASE}/entrypoint", {"rules": [cache_body]})
        print("cache rule set")
    print(f"\nDONE. Then set ASSET_DOMAIN={host} on the api (docs/ops/AZURE-SETUP.md 9.1).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
