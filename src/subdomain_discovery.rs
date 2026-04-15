use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;
use tokio::process::Command;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};

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
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>
) -> Result<SubdomainDiscoveryResult, Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();

    if let Some(tx) = &progress_tx {
        let _ = tx.send(crate::ScanProgress {
            module: "Subdomain".to_string(),
            percentage: 10.0,
            message: "Spawning high-concurrency subfinder process...".to_string(),
            status: "ongoing".to_string()
        }).await;
    }

    let mut command = Command::new("subfinder");
    command.arg("-d").arg(domain).arg("-silent");
    
    command.stdout(Stdio::piped());
    command.stderr(Stdio::null());

    let mut child = command.spawn()?;
    
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let mut reader = BufReader::new(stdout).lines();

    let mut seen = HashSet::new();
    let mut raw = Vec::new();
    
    let mut total_found = 0;

    while let Some(line) = reader.next_line().await? {
        let s = line.trim().to_lowercase();
        if !s.is_empty() && seen.insert(s.clone()) {
            raw.push(s.clone());
            total_found += 1;
            
            if total_found % 20 == 0 {
                if let Some(tx) = &progress_tx {
                    let _ = tx.send(crate::ScanProgress {
                        module: "Subdomain".to_string(),
                        percentage: 50.0,
                        message: format!("Discovered {} subdomains so far... [Latest: {}]", total_found, s),
                        status: "ongoing".to_string()
                    }).await;
                }
            }
        }
    }

    child.wait().await?;

    if let Some(tx) = &progress_tx {
        let _ = tx.send(crate::ScanProgress {
            module: "Subdomain".to_string(),
            percentage: 90.0,
            message: "Filtering noise and matching results against blocklists...".to_string(),
            status: "ongoing".to_string()
        }).await;
    }

    let subdomains: Vec<String> = raw.into_iter().filter(|s| !should_skip(s)).collect();
    let filtered_count = total_found - subdomains.len();
    let duration = start_time.elapsed().as_millis();

    if let Some(tx) = &progress_tx {
        let _ = tx.send(crate::ScanProgress {
            module: "Subdomain".to_string(),
            percentage: 100.0,
            message: "Subdomain footprint mapping completed successfully.".to_string(),
            status: "completed".to_string()
        }).await;
    }

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
