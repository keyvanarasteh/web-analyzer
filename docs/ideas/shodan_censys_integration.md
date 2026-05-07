# Feature Request: Shodan & Censys Passive Recon API Integration

## Overview
Currently, `web-analyzer` relies heavily on active reconnaissance (e.g., `nmap`, direct HTTP probing, and `dig`). Active scanning is noisy and can trigger Web Application Firewalls (WAFs) or Intrusion Detection Systems (IDS). 

To elevate this engine to an enterprise OSINT level, we need a passive reconnaissance module that queries external IoT search engines like Shodan and Censys. This allows the tool to discover historical open ports, forgotten management interfaces, and leaked SSL certificates without ever touching the target's infrastructure directly.

## Implementation Requirements

1. **New Module**: Create `src/passive_recon.rs`.
2. **API Integrations**: 
   - Add support for the Shodan REST API (`https://api.shodan.io/shodan/host/{ip}`).
   - Add support for the Censys Search API (`https://search.censys.io/api/v2/hosts/{ip}`).
3. **Data Structures**:
   - Create a unified `PassiveReconResult` struct that aggregates historical open ports, banners, and vulnerabilities returned by these APIs.
4. **Configuration**:
   - Implement an environment variable or config struct system to pass API keys securely (e.g., `SHODAN_API_KEY`, `CENSYS_API_ID`).

## Why is this Pro-Level?
Passive reconnaissance is the foundation of modern Red Teaming. By integrating Shodan and Censys, `web-analyzer` can instantly map an organization's entire attack surface in milliseconds, revealing exposed databases or unpatched VPN gateways that active scans might miss due to firewall blocking.
