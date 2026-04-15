# Web Analyzer — Documentation Index

> **Crate:** `web-analyzer` v0.1.0
> **Edition:** Rust 2021
> **Total:** 15 modules · 6,725 lines · 14 feature flags

Enterprise-grade domain security & intelligence platform. Rust port of [WebAnalyzer](https://github.com/frkndncr/WebAnalyzer) with full feature parity and enhanced capabilities.

---

## Table of Contents

- [Architecture](#architecture)
- [Module Index](#module-index)
  - [Intelligence Gathering](#intelligence-gathering)
  - [Reconnaissance](#reconnaissance)
  - [Security Assessment](#security-assessment)
- [Dependencies](#dependencies)
- [Feature Flags](#feature-flags)
- [Quick Start](#quick-start)
- [Build](#build)
- [External Tools](#external-tools)
- [Project Structure](#project-structure)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         web-analyzer                                │
├─────────────────────────┬───────────────────┬───────────────────────┤
│  Intelligence Gathering │  Reconnaissance   │  Security Assessment  │
├─────────────────────────┼───────────────────┼───────────────────────┤
│  domain_info       524L │  subdomain_       │  security_            │
│  domain_dns         77L │    discovery 109L │    analysis    679L   │
│  seo_analysis      711L │  contact_spy 400L │  subdomain_           │
│  web_technologies  785L │  advanced_content │    takeover    379L   │
│  domain_validator  437L │    _scanner  754L │  cloudflare_          │
│                         │                   │    bypass      274L   │
│                         │                   │  nmap_zero_day 249L   │
│                         │                   │  api_security_        │
│                         │                   │    scanner    1046L   │
│                         │                   │  geo_analysis  189L   │
├─────────────────────────┴───────────────────┴───────────────────────┤
│                        payloads (compile-time)                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Module Index

### Intelligence Gathering

| Module | Lines | Feature Flag | Documentation | Description |
|--------|-------|-------------|---------------|-------------|
| [domain_info](domain_info.md) | 524 | `domain-info` | ✅ | WHOIS (TCP), SSL cert, DNS, port scan, security score |
| [domain_dns](domain_dns.md) | 77 | `domain-dns` | ✅ | A, AAAA, MX, NS, SOA, TXT, CNAME records via `dig` |
| [seo_analysis](seo_analysis.md) | 711 | `seo-analysis` | ✅ | 13 categories, schema markup, 13 tracking tools, SEO scoring |
| [web_technologies](web_technologies.md) | 785 | `web-technologies` | ✅ | 10 servers, 8 backend, 7 frontend, 12 JS libs, 8 CSS, 11 CMS, 9 e-commerce, 6 CDN, 8 analytics, 8 WAF, WordPress analysis, security scoring |
| [domain_validator](domain_validator.md) | 437 | `domain-validator` | ✅ | DNS + HTTP + SSL validation, parallel bulk processing, skip patterns, atomic stats |

### Reconnaissance

| Module | Lines | Feature Flag | Documentation | Description |
|--------|-------|-------------|---------------|-------------|
| [subdomain_discovery](subdomain_discovery.md) | 109 | `subdomain-discovery` | ✅ | Subfinder integration, 17 skip patterns, deduplication, multi-part TLD support |
| [contact_spy](contact_spy.md) | 400 | `contact-spy` | ✅ | BFS crawl, email/phone/social extraction (15 platforms incl. TikTok), validation |
| [advanced_content_scanner](advanced_content_scanner.md) | 754 | `advanced-content-scanner` | ✅ | 24 secret patterns, 13 JS vulnerability checks, SSRF detection, sensitive file probing |

### Security Assessment

| Module | Lines | Feature Flag | Documentation | Description |
|--------|-------|-------------|---------------|-------------|
| [security_analysis](security_analysis.md) | 679 | `security-analysis` | ✅ | WAF detection (7 providers), SSL grading (A+ to F), CORS, cookie security, composite score |
| [subdomain_takeover](subdomain_takeover.md) | 379 | `subdomain-takeover` | ✅ | 36-service vulnerability DB, 5 detection cases, DNS (6 types), exploitation difficulty, mitigation |
| [cloudflare_bypass](cloudflare_bypass.md) | 274 | `cloudflare-bypass` | ✅ | IP history lookup, TCP verification, private IP filtering |
| [nmap_zero_day](nmap_zero_day.md) | 249 | `nmap-zero-day` | ✅ | Nmap integration, NVD CVE lookup, Exploit-DB, CVSS severity classification |
| [api_security_scanner](api_security_scanner.md) | 1046 | `api-security-scanner` | ✅ | 9 vulnerability test suites (SQLi, XSS, SSRF, path traversal, CORS, auth, rate limiting, info disclosure, header injection) |
| [geo_analysis](geo_analysis.md) | 189 | `geo-analysis` | ✅ | llms.txt detection, WebMCP HTML features, AI crawler directives |

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `reqwest` | 0.13 | HTTP client (JSON, blocking, rustls) |
| `scraper` | 0.26 | HTML parsing & CSS selectors |
| `serde` / `serde_json` | 1.0 | Serialization / deserialization |
| `regex` | 1.12 | Pattern matching |
| `tokio` | 1.50 | Async runtime (full features) |
| `chrono` | 0.4 | Date/time handling |
| `urlencoding` | 2.1 | URL encoding |

---

## Feature Flags

All modules are behind feature flags for selective compilation:

```toml
[features]
# Intelligence Gathering
domain-info = []
domain-dns = []
seo-analysis = []
web-technologies = []
domain-validator = []

# Reconnaissance
subdomain-discovery = []
contact-spy = []
advanced-content-scanner = []

# Security Assessment
security-analysis = []
subdomain-takeover = []
cloudflare-bypass = []
nmap-zero-day = []
api-security-scanner = []
geo-analysis = []
```

---

## Quick Start

```rust
use web_analyzer::domain_info::get_domain_info;
use web_analyzer::security_analysis::analyze_security;
use web_analyzer::web_technologies::detect_web_technologies;

#[tokio::main]
async fn main() {
    let domain = "example.com";

    // Domain intelligence
    let info = get_domain_info(domain, None).await.unwrap();
    println!("IP: {:?}", info.dns_info.a_records);

    // Security analysis
    let security = analyze_security(domain, None).await.unwrap();
    println!("Score: {}/100 ({})", security.security_score, security.grade);

    // Technology fingerprinting
    let tech = detect_web_technologies(domain).await.unwrap();
    println!("Server: {}, CMS: {:?}", tech.web_server, tech.cms);
}
```

---

## Build

```bash
# Build all modules
cargo build --all-features

# Build specific modules
cargo build --features "domain-info,security-analysis,web-technologies"

# Run tests
cargo test --all-features
```

---

## External Tools

Some modules require external tools:

| Tool | Modules | Install |
|------|---------|---------|
| `dig` | domain_dns, domain_info, domain_validator, subdomain_takeover | `apt install dnsutils` |
| `nmap` | nmap_zero_day | `apt install nmap` |
| `subfinder` | subdomain_discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `openssl` | security_analysis, domain_validator | `apt install openssl` |
| `whois` | domain_info | `apt install whois` |

---

## Project Structure

```
web-analyzer/
├── Cargo.toml
├── src/
│   ├── lib.rs                        # Module registry (feature-gated)
│   ├── payloads.rs                   # Compile-time embedded payloads
│   ├── domain_info.rs                # WHOIS, SSL, DNS, ports
│   ├── domain_dns.rs                 # DNS record queries
│   ├── seo_analysis.rs              # SEO analysis (13 categories)
│   ├── web_technologies.rs          # Tech fingerprinting (16 categories)
│   ├── domain_validator.rs          # Bulk domain validation
│   ├── subdomain_discovery.rs       # Subfinder integration
│   ├── contact_spy.rs              # Contact info extraction
│   ├── advanced_content_scanner.rs  # Secret & vulnerability scanning
│   ├── security_analysis.rs        # Security posture assessment
│   ├── subdomain_takeover.rs       # Takeover vulnerability detection
│   ├── cloudflare_bypass.rs        # Origin IP discovery
│   ├── nmap_zero_day.rs            # CVE & exploit detection
│   ├── api_security_scanner.rs     # API vulnerability testing
│   ├── geo_analysis.rs            # AI/LLM readiness analysis
│   └── *_mobile.rs                 # Mobile graceful fallback mock polyfills
├── docs/
│   ├── readme.md                    # This file
│   └── [module_name].md            # Per-module documentation (14 files)
├── payloads/                        # Static payload files
└── tests/                          # Integration tests
```

---

> **Author:** Keyvan Arasteh ([@keyvanarasteh](https://github.com/keyvanarasteh))
