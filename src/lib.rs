//! WebAnalyzer Rust Port
//! 
//! An enterprise domain security & intelligence platform.

/// Compile-time embedded payloads from the `payloads/` directory.
pub mod payloads;

// Intelligence Gathering

#[cfg(feature = "domain-info")]
pub mod domain_info;

#[cfg(feature = "domain-dns")]
pub mod domain_dns;

#[cfg(feature = "seo-analysis")]
pub mod seo_analysis;

#[cfg(feature = "web-technologies")]
pub mod web_technologies;

#[cfg(feature = "domain-validator")]
pub mod domain_validator;


// Reconnaissance

#[cfg(feature = "subdomain-discovery")]
pub mod subdomain_discovery;

#[cfg(feature = "contact-spy")]
pub mod contact_spy;

#[cfg(feature = "advanced-content-scanner")]
pub mod advanced_content_scanner;


// Security Assessment

#[cfg(feature = "security-analysis")]
pub mod security_analysis;

#[cfg(feature = "subdomain-takeover")]
pub mod subdomain_takeover;

#[cfg(feature = "cloudflare-bypass")]
pub mod cloudflare_bypass;

#[cfg(feature = "nmap-zero-day")]
pub mod nmap_zero_day;

#[cfg(feature = "api-security-scanner")]
pub mod api_security_scanner;

#[cfg(feature = "geo-analysis")]
pub mod geo_analysis;

pub mod rest_handlers;
pub mod ws_handler;

pub mod error;
