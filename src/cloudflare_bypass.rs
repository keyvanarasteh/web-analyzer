use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Known Cloudflare IPv4 CIDR ranges (simplified to prefix checks)
const CF_PREFIXES: &[&str] = &[
    "173.245.", "103.21.", "103.22.", "103.31.", "141.101.", "108.162.", "190.93.", "188.114.",
    "197.234.", "198.41.", "162.158.", "162.159.", "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "172.64.", "172.65.", "172.66.", "172.67.", "131.0.",
];

/// Headers that may leak origin IPs
const HEADERS_TO_CHECK: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "x-origin-ip",
    "cf-connecting-ip",
    "x-server-ip",
    "server-ip",
    "x-backend-server",
    "x-origin-server",
];

/// IP history lookup sources
const IP_HISTORY_SOURCES: &[(&str, &str)] = &[
    ("ViewDNS", "https://viewdns.info/iphistory/?domain={}"),
    (
        "SecurityTrails",
        "https://securitytrails.com/domain/{}/history/a",
    ),
    ("WhoIs", "https://who.is/whois/{}"),
];

/// Private IP prefixes (RFC 1918 + loopback + link-local)
const PRIVATE_PREFIXES: &[&str] = &[
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "0.", "169.254.",
];

// ── Structs ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundIp {
    pub ip: String,
    pub source: String,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareBypassResult {
    pub domain: String,
    pub cloudflare_protected: bool,
    pub found_ips: Vec<FoundIp>,
    pub scan_time_ms: u128,
}

// ── IP classification helpers ───────────────────────────────────────────────

fn is_cloudflare_ip(ip: &str) -> bool {
    CF_PREFIXES.iter().any(|prefix| ip.starts_with(prefix))
}

fn is_private_ip(ip: &str) -> bool {
    PRIVATE_PREFIXES.iter().any(|prefix| ip.starts_with(prefix))
}

fn is_valid_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn confidence_score(c: &str) -> u8 {
    match c {
        "Very High" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

// ── Main scanner ────────────────────────────────────────────────────────────

pub async fn find_real_ip(
    domain: &str,
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<CloudflareBypassResult, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();

    let clean_domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?;

    let ip_regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    let mut found_ips: Vec<FoundIp> = Vec::new();

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Cloudflare Bypass".into(), percentage: 5.0, message: "Started real IP discovery...".into(), status: "Info".into() }).await; }

    // ── 1. Direct DNS resolution ────────────────────────────────────────
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Cloudflare Bypass".into(), percentage: 10.0, message: "Performing direct DNS resolution...".into(), status: "Info".into() }).await; }
    let dns_ip = tokio::net::lookup_host(format!("{}:80", clean_domain))
        .await
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|a| a.ip().to_string());

    let cloudflare_protected = if let Some(ref ip) = dns_ip {
        is_cloudflare_ip(ip)
    } else {
        false
    };

    if let Some(ref ip) = dns_ip {
        if !is_cloudflare_ip(ip) && !is_private_ip(ip) {
            found_ips.push(FoundIp {
                ip: ip.clone(),
                source: "direct_dns".into(),
                confidence: "Very High".into(),
                description: None,
                status: None,
            });
        }
    }

    // Only run bypass techniques if CF-protected
    if cloudflare_protected {
        // ── 2. Check common + domain-specific subdomains ────────────────
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Cloudflare Bypass".into(), percentage: 30.0, message: "Checking infrastructure subdomains...".into(), status: "Info".into() }).await; }
        let mut subdomains: Vec<String> =
            vec!["direct", "origin", "api", "mail", "cpanel", "server", "ftp"]
                .into_iter()
                .map(|s| s.to_string())
                .collect();

        // Domain-specific subdomains
        let name_part = clean_domain.split('.').next().unwrap_or("");
        if !name_part.is_empty() {
            subdomains.push(format!("origin-{}", name_part));
            subdomains.push(format!("{}-origin", name_part));
            subdomains.push(format!("direct-{}", name_part));
            subdomains.push(format!("{}-direct", name_part));
        }

        for sub in &subdomains {
            let full: String = format!("{}.{}:80", sub, clean_domain);
            if let Ok(addrs) = tokio::net::lookup_host(full.as_str().to_owned()).await {
                let resolved: Vec<_> = addrs.collect();
                if let Some(addr) = resolved.first() {
                    let ip = addr.ip().to_string();
                    if !is_cloudflare_ip(&ip) && !is_private_ip(&ip) && is_valid_ip(&ip) {
                        found_ips.push(FoundIp {
                            ip,
                            source: format!("subdomain_{}", sub),
                            confidence: "Medium".into(),
                            description: None,
                            status: None,
                        });
                    }
                }
            }
        }

        // ── 3. Check response headers for IP leaks ──────────────────────
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Cloudflare Bypass".into(), percentage: 60.0, message: "Analyzing response origin headers...".into(), status: "Info".into() }).await; }
        if let Ok(resp) = client.get(format!("https://{}", clean_domain)).send().await {
            for header in HEADERS_TO_CHECK {
                if let Some(val) = resp.headers().get(*header) {
                    if let Ok(val_str) = val.to_str() {
                        for cap in ip_regex.find_iter(val_str) {
                            let ip = cap.as_str().to_string();
                            if is_valid_ip(&ip) && !is_cloudflare_ip(&ip) && !is_private_ip(&ip) {
                                found_ips.push(FoundIp {
                                    ip,
                                    source: format!("header_{}", header),
                                    confidence: "High".into(),
                                    description: None,
                                    status: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        // ── 4. IP History lookup ────────────────────────────────────────
        if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Cloudflare Bypass".into(), percentage: 75.0, message: "Querying historical DNS databases...".into(), status: "Info".into() }).await; }
        let history_ips = check_ip_history(&client, clean_domain, &ip_regex, &progress_tx).await;
        found_ips.extend(history_ips);
    }

    // ── Deduplicate, keeping highest confidence ─────────────────────────
    let mut best: HashMap<String, FoundIp> = HashMap::new();
    for ip_info in found_ips {
        let key = ip_info.ip.clone();
        let new_score = confidence_score(&ip_info.confidence);
        if let Some(existing) = best.get(&key) {
            if new_score > confidence_score(&existing.confidence) {
                best.insert(key, ip_info);
            }
        } else {
            best.insert(key, ip_info);
        }
    }

    // Sort by confidence (highest first)
    let mut results: Vec<FoundIp> = best.into_values().collect();
    results.sort_by(|a, b| confidence_score(&b.confidence).cmp(&confidence_score(&a.confidence)));

    // ── Verify top 5 IPs ────────────────────────────────────────────────
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Cloudflare Bypass".into(), percentage: 95.0, message: "Verifying active status of top leaked IPs...".into(), status: "Info".into() }).await; }
    for i in 0..results.len().min(5) {
        let status = verify_ip(&results[i].ip).await;
        results[i].status = Some(status);
    }
    for item in results.iter_mut().skip(5) {
        item.status = Some("unverified".into());
    }

    Ok(CloudflareBypassResult {
        domain: clean_domain.to_string(),
        cloudflare_protected,
        found_ips: results,
        scan_time_ms: start.elapsed().as_millis(),
    })
}

// ── IP History ──────────────────────────────────────────────────────────────

async fn check_ip_history(
    client: &Client, 
    domain: &str, 
    ip_regex: &Regex,
    progress_tx: &Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Vec<FoundIp> {
    let mut results = Vec::new();

    for (name, url_template) in IP_HISTORY_SOURCES {
        if let Some(t) = progress_tx { let _ = t.send(crate::ScanProgress { module: "Cloudflare Bypass".into(), percentage: 80.0, message: format!("Querying IP history: {}", name), status: "Info".into() }).await; }
        let url = url_template.replace("{}", domain);
        let resp = match client
            .get(&url)
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("Referer", "https://www.google.com/")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let body = match resp.text().await {
            Ok(t) => t,
            Err(_) => continue,
        };

        let mut seen = HashSet::new();
        for cap in ip_regex.find_iter(&body) {
            let ip = cap.as_str().to_string();
            if is_valid_ip(&ip)
                && !is_cloudflare_ip(&ip)
                && !is_private_ip(&ip)
                && seen.insert(ip.clone())
            {
                results.push(FoundIp {
                    ip,
                    source: format!("history_{}", name),
                    confidence: "Medium".into(),
                    description: None,
                    status: None,
                });
            }
        }
    }

    results
}

// ── IP Verification via TCP connect ─────────────────────────────────────────

async fn verify_ip(ip: &str) -> String {
    let addr = format!("{}:80", ip);
    match tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => "active".into(),
        _ => "inactive".into(),
    }
}
