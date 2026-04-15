//! # Web Analyzer
//!
//! **Enterprise domain security & intelligence platform** — a high-performance
//! Rust toolkit for comprehensive web reconnaissance, security assessment, and
//! technology fingerprinting.
//!
//! ## Module Architecture
//!
//! The crate is organized into three security pillars, each gated by
//! individual Cargo feature flags:
//!
//! ### 🔎 Intelligence Gathering
//! - [`domain_info`] — WHOIS, SSL certificates, DNS, port scanning, security score
//! - [`domain_dns`] — A, AAAA, MX, NS, SOA, TXT, CNAME record resolution
//! - [`seo_analysis`] — 13-category SEO audit with composite scoring
//! - [`web_technologies`] — Technology fingerprinting across 16 categories
//! - [`domain_validator`] — Bulk domain validation with parallel processing
//!
//! ### 🕵️ Reconnaissance
//! - [`subdomain_discovery`] — Subfinder integration with deduplication
//! - [`contact_spy`] — BFS crawl for email, phone, and social media extraction
//! - [`advanced_content_scanner`] — Secret pattern detection & JS vulnerability analysis
//!
//! ### 🛡️ Security Assessment
//! - [`security_analysis`] — WAF detection, SSL grading, CORS, cookies, composite score
//! - [`subdomain_takeover`] — 36-service vulnerability database with exploitation ratings
//! - [`cloudflare_bypass`] — Origin IP discovery via history lookup
//! - [`nmap_zero_day`] — Nmap integration with NVD CVE and Exploit-DB lookup
//! - [`api_security_scanner`] — 9 test suites: SQLi, XSS, SSRF, path traversal, and more
//! - [`geo_analysis`] — AI/LLM readiness analysis and crawler directives
//!
//! ## Quick Start
//!
//! ```toml
//! [dependencies]
//! web-analyzer = "0.1"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! ```rust,no_run
//! use web_analyzer::domain_info::get_domain_info;
//!
//! #[tokio::main]
//! async fn main() {
//!     let info = get_domain_info("example.com").await.unwrap();
//!     println!("IP: {:?}", info.ipv4);
//! }
//! ```
//!
//! ## Feature Flags
//!
//! By default, **all modules** are enabled. Disable default features and
//! select only what you need to reduce compile times:
//!
//! ```toml
//! [dependencies]
//! web-analyzer = { version = "0.1", default-features = false, features = ["domain-info", "security-analysis"] }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

/// Error types for the web-analyzer crate.
pub mod error;

use serde::{Deserialize, Serialize};

/// Standardized progress event for async tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub module: String,
    pub percentage: f32,
    pub message: String,
    pub status: String,
}

/// Compile-time embedded payloads from the `payloads/` directory.
pub mod payloads;

// ── Intelligence Gathering ──────────────────────────────────────────

#[cfg(feature = "domain-info")]
#[cfg_attr(docsrs, doc(cfg(feature = "domain-info")))]
pub mod domain_info;

#[cfg(feature = "domain-dns")]
#[cfg_attr(docsrs, doc(cfg(feature = "domain-dns")))]
pub mod domain_dns;

#[cfg(feature = "seo-analysis")]
#[cfg_attr(docsrs, doc(cfg(feature = "seo-analysis")))]
pub mod seo_analysis;

#[cfg(feature = "web-technologies")]
#[cfg_attr(docsrs, doc(cfg(feature = "web-technologies")))]
pub mod web_technologies;

#[cfg(feature = "domain-validator")]
#[cfg_attr(docsrs, doc(cfg(feature = "domain-validator")))]
pub mod domain_validator;

// ── Reconnaissance ──────────────────────────────────────────────────

#[cfg(feature = "subdomain-discovery")]
#[cfg_attr(docsrs, doc(cfg(feature = "subdomain-discovery")))]
pub mod subdomain_discovery;

#[cfg(feature = "contact-spy")]
#[cfg_attr(docsrs, doc(cfg(feature = "contact-spy")))]
pub mod contact_spy;

#[cfg(feature = "advanced-content-scanner")]
#[cfg_attr(docsrs, doc(cfg(feature = "advanced-content-scanner")))]
pub mod advanced_content_scanner;

// ── Security Assessment ─────────────────────────────────────────────

#[cfg(feature = "security-analysis")]
#[cfg_attr(docsrs, doc(cfg(feature = "security-analysis")))]
pub mod security_analysis;

#[cfg(feature = "subdomain-takeover")]
#[cfg_attr(docsrs, doc(cfg(feature = "subdomain-takeover")))]
pub mod subdomain_takeover;

#[cfg(feature = "cloudflare-bypass")]
#[cfg_attr(docsrs, doc(cfg(feature = "cloudflare-bypass")))]
pub mod cloudflare_bypass;

#[cfg(feature = "nmap-zero-day")]
#[cfg_attr(docsrs, doc(cfg(feature = "nmap-zero-day")))]
pub mod nmap_zero_day;

#[cfg(feature = "api-security-scanner")]
#[cfg_attr(docsrs, doc(cfg(feature = "api-security-scanner")))]
pub mod api_security_scanner;

#[cfg(feature = "geo-analysis")]
#[cfg_attr(docsrs, doc(cfg(feature = "geo-analysis")))]
pub mod geo_analysis;
