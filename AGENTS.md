# AGENTS.md

This file provides context for AI coding assistants (Cursor, GitHub Copilot, Claude Code, Gemini, etc.) working with the Web-Analyzer payload module.

## Project Overview

**Web-Analyzer** is a Rust library component designed for high-performance, concurrent OSINT and vulnerability scanning against web targets.

- **Repository**: https://github.com/keyvanarasteh/web-analyzer
- **Crate**: https://crates.io/crates/web-analyzer
- **License**: MIT OR Apache-2.0

## Repository Structure

```
web-analyzer/
├── src/
│   ├── lib.rs                  # Crate root, feature gates, public re-exports
│   ├── error.rs                # WebAnalyzerError enum
│   ├── prelude.rs              # Re-exports common types
│   ├── <analysis-modules>      # e.g., domain_info.rs, security_analysis.rs, contact_spy.rs
├── examples/                   # Runnable examples (e.g., full_audit.rs, security_scan.rs)
├── tests/                      # Integration test suites for each module
```

## Key Modules / Features

| Feature | Description |
|---|---|
| `domain-info` | Exhaustive domain recon (IPs, DNS, SSL, Server headers) |
| `domain-dns` | Detailed DNS queries directly covering A, AAAA, MX, TXT, NS, CAA |
| `seo-analysis` | SEO audits, headings, links, meta tags, meta robots, content score |
| `web-technologies` | CMS detection (WordPress focus), Wappalyzer-like headers inspection |
| `subdomain-discovery` | Bruteforce subdomain enumeration targeting known dev/staging endpoints |
| `contact-spy` | Regex-based email and social media extraction (Linkedin, Twitter, etc) |
| `security-analysis` | Header security posture, WAF detection, SSL verification |
| `subdomain-takeover` | Checks CNAME aliases against known vulnerable SaaS patterns |
| `cloudflare-bypass` | Advanced techniques to reveal origin IP addresses behind WAFs |
| `api-security-scanner`| GraphQL inspection, Swagger/OpenAPI exposure, REST brute-forcing |
| `nmap-zero-day` | Nmap integration via backend processing for port mapping and vulnerabilities |
| `geo-analysis` | Geographical mapping of IP resolving |

## Development Commands

```bash
# Build
cargo build
cargo build --all-features

# Check
cargo clippy --all-features -- -D warnings

# Run tests
cargo test --all-features

# Run examples
cargo run --example full_audit --all-features
```

## Key Patterns
- Feature-gating: Always `#![cfg(feature="...")]` wrap your modules.
- Error Handling: Return `WebAnalyzerError` variants, utilizing `thiserror`.
- Documentation: Extensive `# Example` doctests.

## Important Note to Agents
Do NOT re-introduce `qicro_data_core` or any monorepo specific logic (such as REST handlers, Grpc, WS message wrappers or `Registrable` traits). This crate is functionally standalone and completely decoupled.
