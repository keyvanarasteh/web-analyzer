use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use regex::Regex;

/// Known Cloudflare IPv4 CIDR ranges (simplified to /16 and /24 checks)
const CF_PREFIXES: &[&str] = &[
    "173.245.", "103.21.", "103.22.", "103.31.", "141.101.",
    "108.162.", "190.93.", "188.114.", "197.234.", "198.41.",
    "162.158.", "162.159.", "104.16.", "104.17.", "104.18.",
    "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.", "172.64.",
    "172.65.", "172.66.", "172.67.", "131.0.",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundIp {
    pub ip: String,
    pub source: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareBypassResult {
    pub domain: String,
    pub cloudflare_protected: bool,
    pub found_ips: Vec<FoundIp>,
}

fn is_cloudflare_ip(ip: &str) -> bool {
    CF_PREFIXES.iter().any(|prefix| ip.starts_with(prefix))
}

pub async fn find_real_ip(domain: &str) -> Result<CloudflareBypassResult, Box<dyn std::error::Error + Send + Sync>> {
    let clean_domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let mut found_ips = Vec::new();

    // 1. Direct DNS resolution
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
        if !is_cloudflare_ip(ip) {
            found_ips.push(FoundIp {
                ip: ip.clone(),
                source: "direct_dns".into(),
                confidence: "Very High".into(),
            });
        }
    }

    // 2. Check common subdomains that might bypass CF
    let subdomains = vec!["direct", "origin", "api", "mail", "cpanel", "server", "ftp"];
    for sub in subdomains {
        let full = format!("{}.{}:80", sub, clean_domain);
        if let Ok(mut addrs) = tokio::net::lookup_host(&full).await {
            if let Some(addr) = addrs.next() {
                let ip = addr.ip().to_string();
                if !is_cloudflare_ip(&ip) {
                    found_ips.push(FoundIp {
                        ip,
                        source: format!("subdomain_{}", sub),
                        confidence: "Medium".into(),
                    });
                }
            }
        }
    }

    // 3. Check response headers for IP leaks
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    let ip_regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    let headers_to_check = [
        "x-forwarded-for", "x-real-ip", "x-origin-ip", "x-server-ip",
        "x-backend-server", "x-origin-server",
    ];

    if let Ok(resp) = client.get(format!("https://{}", clean_domain)).send().await {
        for header in &headers_to_check {
            if let Some(val) = resp.headers().get(*header) {
                if let Ok(val_str) = val.to_str() {
                    for cap in ip_regex.find_iter(val_str) {
                        let ip = cap.as_str().to_string();
                        if !is_cloudflare_ip(&ip) {
                            found_ips.push(FoundIp {
                                ip,
                                source: format!("header_{}", header),
                                confidence: "High".into(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Deduplicate
    let mut seen = std::collections::HashSet::new();
    found_ips.retain(|ip| seen.insert(ip.ip.clone()));

    Ok(CloudflareBypassResult {
        domain: clean_domain.to_string(),
        cloudflare_protected,
        found_ips,
    })
}
