terraform {
  # OpenTofu is the reference tool (ADR-09); Terraform 1.x works too. Checked 2026-10-27: OpenTofu 1.13.2, Terraform 1.17.0.
  required_version = ">= 1.13.0"

  required_providers {
    # Checked 2026-10-27 against the OpenTofu registry (registry.opentofu.org) and registry.terraform.io.
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.28.1"
    }
    # google 8.9.0 was published 2026-10-27 and is not mirrored by the OpenTofu registry yet (it serves 8.8.1); ~> 8.8 resolves to
    # the newest the registry offers. Re-run `tofu init -upgrade` and commit the lock file when 8.9.x appears.
    google = {
      source  = "hashicorp/google"
      version = "~> 8.8"
    }
    # Community provider (kislerdm/neon), the one Neon's own documentation points to; Neon publishes no first-party provider.
    neon = {
      source  = "kislerdm/neon"
      version = "0.18.0"
    }
    # Fly.io: no Terraform provider is used. fly-apps/fly (0.0.23) is experimental and unmaintained; Fly is configured by
    # Infra/fly/fly.*.toml and deployed with flyctl from CI.
  }
}

provider "cloudflare" {
  # Token from CLOUDFLARE_API_TOKEN (env). Scope it to: Zone:Edit, DNS:Edit, Zone Settings:Edit, Firewall Services:Edit,
  # Transform Rules:Edit, Workers Scripts:Edit, SSL and Certificates:Edit, for this account and zone only.
}

provider "google" {
  project = var.gcp_project_id
  region  = var.kms_location
  # Credentials from workload identity federation in CI (GOOGLE_APPLICATION_CREDENTIALS / external_account), never a key file.
}

provider "neon" {
  # API key from NEON_API_KEY (env).
}
