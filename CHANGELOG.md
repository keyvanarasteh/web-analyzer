# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8] - 2026-04-16

### Added
- **Mobile Platform Support**: Full conditional compilation guards (`target_os="android", target_os="ios"`) to seamlessly exclude root-reliant modules like `nmap_zero_day` and local process spawns (`subfinder`).
- **Native OS Fallbacks**: Cross-platform feature variants injected for Mobile execution paths:
  - `domain_info_mobile.rs`: Native WHOIS, Port Scanning, and basic TLS validation via `reqwest` & standard TCP, bypassing CLI `openssl` & `whois`.
  - `domain_dns_mobile.rs`: Pure Rust DNS resolving built on top of `hickory-resolver` replacing `dig`.
  - `domain_validator_mobile.rs`: Swapped backend validation queues across HTTP, SSL, and DNS without subprocess tools.
  - `security_analysis_mobile.rs`: Headers and strict origin checks utilizing `reqwest` redirects.
  - `subdomain_takeover_mobile.rs`: Validated logic parsing for dangling CNAMEs via `hickory-resolver`.
- Seamless concurrency adaptation through native `tokio::task::JoinSet` over previously tied futures blocks on mobile variants.

### Changed
- Refactored `Cargo.toml` separating `-mobile` feature variants (e.g. `domain-info-mobile`, `subdomain-takeover-mobile`).

## [0.1.0] - 2026-04-02

### Added

- **Intelligence Gathering**: `domain_info`, `domain_dns`, `seo_analysis`, `web_technologies`, `domain_validator`
- **Reconnaissance**: `subdomain_discovery`, `contact_spy`, `advanced_content_scanner`
- **Security Assessment**: `security_analysis`, `subdomain_takeover`, `cloudflare_bypass`, `nmap_zero_day`, `api_security_scanner`, `geo_analysis`
- 14 feature flags for individual module compilation
- 10 compile-time embedded payload files (SQLi, XSS, SSRF, XXE, LFI, NoSQL, SSTI, command injection, auth bypass, API endpoints)
- Comprehensive module documentation for all 14 modules
- Integration tests for all modules
- 3 runnable examples: `domain_info`, `security_scan`, `full_audit`

[0.1.8]: https://github.com/keyvanarasteh/web-analyzer/releases/tag/v0.1.8
[0.1.0]: https://github.com/keyvanarasteh/web-analyzer/releases/tag/v0.1.0
