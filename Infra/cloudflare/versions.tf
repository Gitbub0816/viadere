terraform {
  # OpenTofu is the reference tool (ADR-0009). Checked 2026-11-02: OpenTofu 1.13.2.
  required_version = ">= 1.13.2"

  required_providers {
    # Checked 2026-10-27 against the OpenTofu registry (registry.opentofu.org) and registry.terraform.io.
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.28.1"
    }
  }
}

provider "cloudflare" {
  # Token from CLOUDFLARE_API_TOKEN (env). Scope it to: Zone:Edit, DNS:Edit, Zone Settings:Edit, Firewall Services:Edit,
  # Transform Rules:Edit, Workers Scripts:Edit, SSL and Certificates:Edit and (account) Cloudflare Tunnel:Edit, for this account and
  # zone only. It carries no scope for the `id.` host's static assets (ADR-0024 section 7, ADR-0028 section 8): those belong to the
  # token of authority-publish.yml.
}
