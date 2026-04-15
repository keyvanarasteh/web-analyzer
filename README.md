<p align="center">
  <h1 align="center">🔍 Web Analyzer</h1>
  <p align="center">
    <strong>Enterprise Domain Security & Intelligence Platform</strong>
  </p>
  <p align="center">
    High-performance Rust toolkit for web reconnaissance, security assessment, and technology fingerprinting
  </p>
</p>

<p align="center">
  <a href="https://crates.io/crates/web-analyzer"><img src="https://img.shields.io/crates/v/web-analyzer?style=for-the-badge&logo=rust&logoColor=white&color=orange" alt="crates.io"></a>
  <a href="https://docs.rs/web-analyzer"><img src="https://img.shields.io/docsrs/web-analyzer?style=for-the-badge&logo=docs.rs&logoColor=white" alt="docs.rs"></a>
  <a href="https://github.com/keyvanarasteh/web-analyzer/actions"><img src="https://img.shields.io/github/actions/workflow/status/keyvanarasteh/web-analyzer/ci.yml?style=for-the-badge&logo=github&label=CI" alt="CI"></a>
  <a href="https://github.com/keyvanarasteh/web-analyzer/blob/main/LICENSE-MIT"><img src="https://img.shields.io/crates/l/web-analyzer?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/async-tokio-purple?style=flat-square&logo=tokio" alt="Tokio"></a>
  <a href="#"><img src="https://img.shields.io/badge/http-reqwest-blue?style=flat-square" alt="Reqwest"></a>
  <a href="#"><img src="https://img.shields.io/badge/html-scraper-red?style=flat-square" alt="Scraper"></a>
  <a href="#"><img src="https://img.shields.io/badge/serialization-serde-orange?style=flat-square" alt="Serde"></a>
  <a href="#"><img src="https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square&logo=linux" alt="Linux"></a>
</p>

---

## 🚀 Quick Start

```bash
cargo add web-analyzer
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
web-analyzer = "0.1"
tokio = { version = "1", features = ["full"] }
```

```rust
use web_analyzer::domain_info::get_domain_info;

#[tokio::main]
async fn main() {
    let info = get_domain_info("example.com", None).await.unwrap();
    println!("IP: {:?}, Score: {}/100", info.ipv4, info.security_score);
}
```

> **Selective features**: `cargo add web-analyzer --no-default-features --features domain-info,security-analysis`

---


## ✨ Features

- **15 modular analysis modules** organized in 3 security pillars
- **Feature-gated compilation** — include only what you need
- **Fully async** — built on Tokio for concurrent analysis
- **Zero Python dependencies** — pure Rust with system tool integration
- **Real-time UI streaming** — `ScanProgress` MPSC capabilities for high-latency modules
- **Comprehensive output** — all results serialize to JSON via Serde
- **WordPress deep analysis** — version, theme, plugins, user enumeration, XMLRPC
- **36-service subdomain takeover DB** with exploitation difficulty ratings
- **Parallel bulk domain validation** with atomic counters

---

## 📦 Module Overview

### 🔎 Intelligence Gathering

| Module               | Lines | Description                                                                                                               | Docs                           |
| -------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| **domain_info**      | 524   | WHOIS (raw TCP), SSL certificates, DNS, port scanning, security score                                                     | [📖](docs/domain_info.md)      |
| **domain_dns**       | 77    | A, AAAA, MX, NS, SOA, TXT, CNAME records via `dig`                                                                        | [📖](docs/domain_dns.md)       |
| **seo_analysis**     | 711   | 13 analysis categories, schema markup, 13 tracking tools, scoring                                                         | [📖](docs/seo_analysis.md)     |
| **web_technologies** | 785   | 10 servers, 8 backend, 7 frontend, 12 JS libs, 8 CSS, 11 CMS, 9 e-commerce, 6 CDN, 8 analytics, 8 WAF, WordPress analysis | [📖](docs/web_technologies.md) |
| **domain_validator** | 437   | DNS + HTTP + SSL validation, parallel bulk processing, 34 skip patterns                                                   | [📖](docs/domain_validator.md) |

### 🕵️ Reconnaissance

| Module                       | Lines | Description                                                           | Docs                                   |
| ---------------------------- | ----- | --------------------------------------------------------------------- | -------------------------------------- |
| **subdomain_discovery**      | 109   | Subfinder integration, deduplication, multi-part TLD support          | [📖](docs/subdomain_discovery.md)      |
| **contact_spy**              | 400   | BFS crawl, email/phone/social extraction (15 platforms), validation   | [📖](docs/contact_spy.md)              |
| **advanced_content_scanner** | 754   | 24 secret patterns, 13 JS vulnerability checks, SSRF, sensitive files | [📖](docs/advanced_content_scanner.md) |

### 🛡️ Security Assessment

| Module                   | Lines | Description                                                                                 | Docs                               |
| ------------------------ | ----- | ------------------------------------------------------------------------------------------- | ---------------------------------- |
| **security_analysis**    | 679   | WAF detection (7 providers), SSL grading A+ to F, CORS, cookies, composite score            | [📖](docs/security_analysis.md)    |
| **subdomain_takeover**   | 379   | 36-service vulnerability DB, 5 detection cases, exploitation difficulty, mitigation         | [📖](docs/subdomain_takeover.md)   |
| **cloudflare_bypass**    | 274   | Origin IP discovery via history lookup, TCP verification, private IP filter                 | [📖](docs/cloudflare_bypass.md)    |
| **nmap_zero_day**        | 249   | Nmap integration, NVD CVE lookup, Exploit-DB, CVSS severity                                 | [📖](docs/nmap_zero_day.md)        |
| **api_security_scanner** | 1046  | 9 test suites: SQLi, XSS, SSRF, path traversal, CORS, auth, rate limiting, header injection | [📖](docs/api_security_scanner.md) |
| **geo_analysis**         | 189   | llms.txt, WebMCP HTML features, AI crawler directives                                       | [📖](docs/geo_analysis.md)         |

> 📚 **Full documentation index:** [docs/readme.md](docs/readme.md)

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/keyvanarasteh/web-analyzer.git
cd web-analyzer
cargo build --all-features
```

### Usage

```rust
use web_analyzer::domain_info::get_domain_info;
use web_analyzer::security_analysis::analyze_security;
use web_analyzer::web_technologies::detect_web_technologies;
use web_analyzer::subdomain_takeover::check_subdomain_takeover;

#[tokio::main]
async fn main() {
    let domain = "example.com";

    // Domain intelligence
    let info = get_domain_info(domain, None).await.unwrap();
    println!("IP: {:?}", info.dns_info.a_records);

    // Security posture
    let security = analyze_security(domain, None).await.unwrap();
    println!("Grade: {} ({}/100)", security.grade, security.security_score);

    // Technology fingerprinting
    let tech = detect_web_technologies(domain).await.unwrap();
    println!("Server: {} | CMS: {:?}", tech.web_server, tech.cms);

    // Subdomain takeover check
    let subs = vec!["blog.example.com".into(), "shop.example.com".into()];
    let takeover = check_subdomain_takeover(domain, &subs, None).await.unwrap();
    println!("Vulnerable: {}", takeover.statistics.vulnerable_count);
}
```

---

## ⚙️ Feature Flags

Include only what you need:

```toml
[dependencies]
web-analyzer = { version = "0.1.0", features = ["domain-info", "security-analysis"] }
```

<details>
<summary><strong>All feature flags</strong></summary>

```toml
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

</details>

---

## 🔧 External Dependencies

| Tool        | Required By                                                   | Install                                                                    |
| ----------- | ------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `dig`       | domain_dns, domain_info, domain_validator, subdomain_takeover | `sudo apt install dnsutils`                                                |
| `nmap`      | nmap_zero_day                                                 | `sudo apt install nmap`                                                    |
| `subfinder` | subdomain_discovery                                           | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `openssl`   | security_analysis, domain_validator                           | `sudo apt install openssl`                                                 |
| `whois`     | domain_info                                                   | `sudo apt install whois`                                                   |

---

## 🏗️ Build

```bash
# All modules
cargo build --all-features

# Specific modules only
cargo build --features "domain-info,security-analysis,web-technologies"

# Release build
cargo build --all-features --release

# Run tests
cargo test --all-features
```

---

## 📁 Project Structure

```
web-analyzer/
├── Cargo.toml                        # Dependencies & feature flags
├── README.md                         # This file
├── src/
│   ├── lib.rs                        # Module registry (feature-gated)
│   ├── payloads.rs                   # Compile-time embedded payloads
│   │
│   │── domain_info.rs                # WHOIS, SSL, DNS, ports
│   │── domain_dns.rs                 # DNS record queries
│   │── seo_analysis.rs               # SEO (13 categories)
│   │── web_technologies.rs           # Tech fingerprinting (16 categories)
│   │── domain_validator.rs           # Bulk domain validation
│   │
│   │── subdomain_discovery.rs        # Subfinder integration
│   │── contact_spy.rs                # Contact info extraction
│   │── advanced_content_scanner.rs   # Secret & vuln scanning
│   │
│   │── security_analysis.rs          # Security posture assessment
│   │── subdomain_takeover.rs         # Takeover vulnerability detection
│   │── cloudflare_bypass.rs          # Origin IP discovery
│   │── nmap_zero_day.rs              # CVE & exploit detection
│   │── api_security_scanner.rs       # API vulnerability testing
│   └── geo_analysis.rs              # AI/LLM readiness
│
├── docs/                             # Module documentation (14 files)
│   ├── readme.md                     # Documentation index
│   └── [module_name].md
│
├── payloads/                         # Static payload files
└── tests/                            # Integration tests
```

---

## 📊 Stats

| Metric                 | Value |
| ---------------------- | ----- |
| Total modules          | 15    |
| Total Rust lines       | 6,725 |
| Feature flags          | 14    |
| Documentation files    | 14    |
| Vulnerable services DB | 36    |
| WAF providers detected | 8     |
| Secret patterns        | 24    |
| CMS platforms          | 11    |
| Web servers            | 10    |

---

## 👤 Author

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/keyvanarasteh">
        <img src="https://github.com/keyvanarasteh.png" width="80" height="80" style="border-radius:50%" alt="Keyvan Arasteh"><br>
        <sub><b>Keyvan Arasteh</b></sub><br>
        <sub>@keyvanarasteh</sub>
      </a>
    </td>
  </tr>
</table>

---

<p align="center">
  <sub>Built with 🦀 Rust — İstinye University</sub>
</p>
