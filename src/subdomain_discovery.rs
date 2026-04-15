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
pub struct SubdomainDetail {
    pub host: String,
    pub status: Option<u16>,
    pub resolution_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainDiscoveryResult {
    pub domain: String,
    pub subdomains: Vec<SubdomainDetail>,
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

    let raw_subdomains: Vec<String> = raw.into_iter().filter(|s| !should_skip(s)).collect();
    let filtered_count = total_found - raw_subdomains.len();
    
    if let Some(tx) = &progress_tx {
        let _ = tx.send(crate::ScanProgress {
            module: "Subdomain".to_string(),
            percentage: 92.0,
            message: format!("Resolving HTTP status for {} unique subdomains...", raw_subdomains.len()),
            status: "ongoing".to_string()
        }).await;
    }

    use tokio::task::JoinSet;
    use tokio::sync::Semaphore;
    use std::sync::Arc;

    let mut set = JoinSet::new();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .unwrap_or_default();
        
    let semaphore = Arc::new(Semaphore::new(100));

    for host in raw_subdomains.clone() {
        let client_c = client.clone();
        let sem_c = semaphore.clone();
        set.spawn(async move {
            let _permit = sem_c.acquire().await;
            
            // Probing HTTP -> HTTPS
            let url_http = format!("http://{}", host);
            match client_c.get(&url_http).send().await {
                Ok(r) => {
                    SubdomainDetail {
                        host,
                        status: Some(r.status().as_u16()),
                        resolution_error: None,
                    }
                },
                Err(e_http) => {
                    // Try HTTPS if HTTP completely drops
                    let url_https = format!("https://{}", host);
                    match client_c.get(&url_https).send().await {
                        Ok(r) => {
                            SubdomainDetail {
                                host,
                                status: Some(r.status().as_u16()),
                                resolution_error: None,
                            }
                        },
                        Err(e_https) => {
                            SubdomainDetail {
                                host,
                                status: None,
                                resolution_error: Some(format!("HTTP: {} | HTTPS: {}", e_http, e_https)),
                            }
                        }
                    }
                }
            }
        });
    }

    let mut subdomains = Vec::new();
    let total_to_resolve = raw_subdomains.len();
    let mut resolved = 0;

    while let Some(res) = set.join_next().await {
        if let Ok(detail) = res {
            subdomains.push(detail);
            resolved += 1;
            
            if resolved % 25 == 0 {
                if let Some(tx) = &progress_tx {
                    let _ = tx.send(crate::ScanProgress {
                        module: "Subdomain".to_string(),
                        percentage: 92.0 + (7.0 * (resolved as f32 / total_to_resolve as f32).max(0.01)),
                        message: format!("Resolved HTTP status for {}/{} subdomains...", resolved, total_to_resolve),
                        status: "ongoing".to_string()
                    }).await;
                }
            }
        }
    }

    let duration = start_time.elapsed().as_millis();

    if let Some(tx) = &progress_tx {
        let _ = tx.send(crate::ScanProgress {
            module: "Subdomain".to_string(),
            percentage: 100.0,
            message: "Subdomain footprint mapping and HTTP verification completed.".to_string(),
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
