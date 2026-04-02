use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;
use tokio::process::Command;

/// Skip patterns for problematic/noise domains
const SKIP_PATTERNS: &[&str] = &[
    "stun.l.google.com",
    ".cloudapp.azure.com",
    "clients6.google.com",
    ".cdn.cloudflare.net",
    "rr1.sn-",
    "rr2.sn-",
    "rr3.sn-",
    "rr4.sn-",
    "rr5.sn-",
    "e-0014.e-msedge",
    "s-part-",
    ".t-msedge.net",
    "perimeterx.map",
    "i.ytimg.com",
    "analytics-alv.google.com",
    "signaler-pa.clients",
    "westus-0.in.applicationinsights",
];

/// Common multi-part TLDs for subdomain detection
const COMMON_TLDS: &[&str] = &[
    "co.uk", "com.tr", "gov.tr", "edu.tr", "org.tr", "net.tr", "co.jp", "co.kr", "co.id", "co.in",
    "com.br", "com.au",
];

// ── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainDiscoveryResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub total_found: usize,
    pub filtered_count: usize,
    pub response_time_ms: u128,
}

// ── Public API ──────────────────────────────────────────────────────────────

pub async fn discover_subdomains(
    domain: &str,
) -> Result<SubdomainDiscoveryResult, Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();

    let output = Command::new("subfinder")
        .arg("-d")
        .arg(domain)
        .arg("-silent")
        .output()
        .await?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);

    // Collect, trim, deduplicate
    let mut seen = HashSet::new();
    let raw: Vec<String> = stdout_str
        .lines()
        .map(|s| s.trim().to_lowercase().to_string())
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .collect();

    let total_found = raw.len();

    // Filter out noise domains
    let subdomains: Vec<String> = raw.into_iter().filter(|s| !should_skip(s)).collect();

    let filtered_count = total_found - subdomains.len();
    let duration = start_time.elapsed().as_millis();

    Ok(SubdomainDiscoveryResult {
        domain: domain.to_string(),
        subdomains,
        total_found,
        filtered_count,
        response_time_ms: duration,
    })
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Check if a domain matches any skip pattern
fn should_skip(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    SKIP_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Detect whether a domain is a subdomain (not the root)
pub fn is_subdomain(domain: &str) -> bool {
    let parts: Vec<&str> = domain.split('.').collect();

    // IP address check
    if parts.iter().all(|p| p.parse::<u8>().is_ok()) || domain.contains(':') {
        return false;
    }

    if parts.len() <= 2 {
        return false;
    }

    // Check multi-part TLDs
    let suffix = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if COMMON_TLDS.contains(&suffix.as_str()) {
        return parts.len() > 3;
    }

    parts.len() > 2
}
