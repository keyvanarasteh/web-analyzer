# Feature Request: Certificate Transparency (CT) Log Monitor

## Overview
While `web-analyzer` uses `subfinder` for subdomain discovery, this relies on passive APIs that can be outdated. The most cutting-edge method for discovering new infrastructure is monitoring Certificate Transparency (CT) logs in real-time. Whenever an organization provisions a new server or internal portal, an SSL certificate is issued and recorded publicly.

We need a module that actively queries CT logs to discover subdomains the exact second they are created.

## Implementation Requirements

1. **New Module**: Create `src/ct_log_monitor.rs`.
2. **Data Sources**:
   - Query `crt.sh` via its JSON API: `https://crt.sh/?q=%.target.com&output=json`.
   - Alternatively, integrate directly with Google's CT log servers.
3. **Data Processing**:
   - Parse the `name_value` field which contains the domains.
   - Filter out wildcards (`*.target.com`).
   - Deduplicate against the existing subdomains found by the `subdomain_discovery` module.
4. **Continuous Mode**: Create a daemon mode that polls the CT logs every 15 minutes and emits a notification/event when a *new* subdomain appears.

## Why is this Pro-Level?
Real-time infrastructure discovery is critical for Red Teams trying to find unhardened staging environments before the Blue Team secures them. Integrating CT log parsing directly into the Rust engine gives it an edge over traditional periodic scanners.
