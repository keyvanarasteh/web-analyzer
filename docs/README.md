# Web Analyzer Documentation Index

> **Crate:** `web-analyzer` v0.1.11
> **Edition:** Rust 2021
> **Primary modules:** 16 default modules plus mobile fallbacks and shared payloads.

Enterprise-grade domain security and intelligence platform. Rust port of
[WebAnalyzer](https://github.com/frkndncr/WebAnalyzer) with feature-gated
modules for reconnaissance, security assessment, domain intelligence, and
React/Next.js vulnerability research.

## Module Index

### Intelligence Gathering

| Module | Feature Flag | Documentation | Description |
|--------|--------------|---------------|-------------|
| [domain_info](domain_info.md) | `domain-info` | Yes | WHOIS, SSL certificates, DNS, port scan, and security scoring. |
| [domain_dns](domain_dns.md) | `domain-dns` | Yes | A, AAAA, MX, NS, SOA, TXT, and CNAME record lookup. |
| [seo_analysis](seo_analysis.md) | `seo-analysis` | Yes | SEO scoring, metadata, schema, sitemap, robots, and tracking analysis. |
| [web_technologies](web_technologies.md) | `web-technologies` | Yes | Technology fingerprinting with progress events for long-running UI scans. |
| [domain_validator](domain_validator.md) | `domain-validator` | Yes | DNS, HTTP, SSL, and bulk validation with per-domain progress events. |

### Reconnaissance

| Module | Feature Flag | Documentation | Description |
|--------|--------------|---------------|-------------|
| [subdomain_discovery](subdomain_discovery.md) | `subdomain-discovery` | Yes | Subfinder integration, deduplication, and mobile-safe fallback export. |
| [contact_spy](contact_spy.md) | `contact-spy` | Yes | BFS contact crawler with email, phone, and social profile extraction. |
| [advanced_content_scanner](advanced_content_scanner.md) | `advanced-content-scanner` | Yes | Secret detection, JS vulnerability checks, crawling, and progress events. |

### Security Assessment

| Module | Feature Flag | Documentation | Description |
|--------|--------------|---------------|-------------|
| [security_analysis](security_analysis.md) | `security-analysis` | Yes | WAF, SSL, CORS, cookie, and header posture assessment. |
| [subdomain_takeover](subdomain_takeover.md) | `subdomain-takeover` | Yes | Takeover fingerprint database and dangling DNS detection. |
| [cloudflare_bypass](cloudflare_bypass.md) | `cloudflare-bypass` | Yes | Origin IP discovery with history lookup and verification progress. |
| [nmap_zero_day](nmap_zero_day.md) | `nmap-zero-day` | Yes | Nmap, NVD CVE lookup, Exploit-DB enrichment, and mobile fallback export. |
| [api_security_scanner](api_security_scanner.md) | `api-security-scanner` | Yes | API vulnerability suites for SQLi, XSS, SSRF, traversal, auth, CORS, and more. |
| [geo_analysis](geo_analysis.md) | `geo-analysis` | Yes | AI crawler readiness, `llms.txt`, and WebMCP feature analysis. |

### React Security

| Module | Feature Flag | Documentation | Description |
|--------|--------------|---------------|-------------|
| `react` | `react2shell` | API docs | React/Next.js reconnaissance, source leak checks, DoS/RCE helpers, and report generation. |
| `react_honeypot` | `react-honeypot` | API docs | React honeypot request analysis, attacker profiling, detection rules, and JSON export. |

## Feature Flags

Default features enable the 16 primary modules:

```toml
[dependencies]
web-analyzer = "0.1.11"
```

Use selective compilation when embedding the crate:

```toml
[dependencies]
web-analyzer = { version = "0.1.11", default-features = false, features = ["domain-info", "security-analysis"] }
```

Primary feature flags:

```toml
domain-info = []
domain-dns = []
seo-analysis = []
web-technologies = []
domain-validator = []
subdomain-discovery = []
contact-spy = []
advanced-content-scanner = []
security-analysis = []
subdomain-takeover = []
cloudflare-bypass = []
nmap-zero-day = []
api-security-scanner = []
geo-analysis = []
react2shell = []
react-honeypot = []
```

Mobile and TLS support flags:

```toml
domain-info-mobile = ["hickory-resolver", "x509-parser", "rustls"]
domain-dns-mobile = ["hickory-resolver"]
domain-validator-mobile = ["hickory-resolver", "x509-parser", "rustls"]
security-analysis-mobile = ["x509-parser", "rustls"]
subdomain-takeover-mobile = ["hickory-resolver"]
rustls = []
```

## Quick Start

```rust
use web_analyzer::domain_info::get_domain_info;
use web_analyzer::security_analysis::analyze_security;
use web_analyzer::web_technologies::detect_web_technologies;

#[tokio::main]
async fn main() {
    let domain = "example.com";

    let info = get_domain_info(domain, None).await.unwrap();
    println!("IP: {:?}", info.dns_info.a_records);

    let security = analyze_security(domain, None).await.unwrap();
    println!("Score: {}/100 ({})", security.security_score, security.grade);

    let tech = detect_web_technologies(domain, None).await.unwrap();
    println!("Server: {}, CMS: {:?}", tech.web_server, tech.cms);
}
```

## Progress Events

Long-running modules accept an optional `tokio::sync::mpsc::Sender<ScanProgress>`
so UI consumers can stream status without changing result payloads. This is now
covered across the major WebQ-facing scan paths, including web technologies,
contact crawling, advanced content scanning, Cloudflare bypass checks, and
bulk domain validation.

## Build

```bash
cargo build --all-features
cargo test --all-features
cargo clippy --all-features -- -D warnings
cargo fmt --all -- --check
```

Android target checks are supported without requiring an Android NDK compiler by
using `reqwest` with `rustls-no-provider` and installing the `ring` provider only
on non-Android targets.

## External Tools

Some desktop modules call external tools when their feature is enabled:

| Tool | Modules | Install |
|------|---------|---------|
| `dig` | `domain_dns`, `domain_info`, `domain_validator`, `subdomain_takeover` | `apt install dnsutils` |
| `nmap` | `nmap_zero_day` | `apt install nmap` |
| `subfinder` | `subdomain_discovery` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `openssl` | `security_analysis`, `domain_validator` | `apt install openssl` |
| `whois` | `domain_info` | `apt install whois` |

Mobile-oriented variants avoid subprocess tools and use pure Rust/network
fallbacks where available.

## Project Structure

```text
web-analyzer/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── payloads.rs
│   ├── *_mobile.rs
│   └── module implementations
├── docs/
│   ├── README.md
│   └── module documentation
├── payloads/
└── tests/
```

## Release Notes

See [CHANGELOG.md](../CHANGELOG.md) for versioned release history.
