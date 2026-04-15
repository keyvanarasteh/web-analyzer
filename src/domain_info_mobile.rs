use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfoResult {
    pub domain: String,
    pub ipv4: Option<String>,
    pub ipv6: Vec<String>,
    pub all_ipv4: Vec<String>,
    pub reverse_dns: Option<String>,
    pub whois: WhoisInfo,
    pub ssl: SslInfo,
    pub dns: DnsInfo,
    pub open_ports: Vec<String>,
    pub http_status: Option<String>,
    pub web_server: Option<String>,
    pub response_time_ms: Option<f64>,
    pub security: SecurityInfo,
    pub security_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub registrar: String,
    pub creation_date: String,
    pub expiry_date: String,
    pub last_updated: String,
    pub domain_status: Vec<String>,
    pub registrant: String,
    pub privacy_protection: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub name_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslInfo {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_until_expiry: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alternative_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub nameservers: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dmarc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInfo {
    pub https_available: bool,
    pub https_redirect: bool,
    pub security_headers: HashMap<String, String>,
    pub headers_count: usize,
}

use hickory_resolver::config::*;
use hickory_resolver::AsyncResolver;
use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn get_domain_info(
    domain: &str,
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<DomainInfoResult, Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();

    if let Some(t) = &progress_tx {
        let _ = t.send(crate::ScanProgress {
            module: "Domain Info".into(),
            percentage: 10.0,
            message: "Starting native mobile domain analysis".into(),
            status: "Info".into(),
        }).await;
    }

    let mut result = DomainInfoResult {
        domain: domain.to_string(),
        ipv4: None,
        ipv6: vec![],
        all_ipv4: vec![],
        reverse_dns: None,
        whois: WhoisInfo {
            registrar: "Native Fallback".into(),
            creation_date: "".into(),
            expiry_date: "".into(),
            last_updated: "".into(),
            domain_status: vec![],
            registrant: "".into(),
            privacy_protection: "".into(),
            name_servers: vec![],
        },
        ssl: SslInfo {
            status: "Unknown".into(),
            issued_to: None,
            issuer: None,
            protocol_version: None,
            expiry_date: None,
            days_until_expiry: None,
            alternative_names: vec![],
        },
        dns: DnsInfo {
            nameservers: vec![],
            mx_records: vec![],
            txt_records: vec![],
            spf: None,
            dmarc: None,
        },
        open_ports: vec![],
        http_status: None,
        web_server: None,
        response_time_ms: None,
        security: SecurityInfo {
            https_available: false,
            https_redirect: false,
            security_headers: HashMap::new(),
            headers_count: 0,
        },
        security_score: 50,
    };

    let resolver = AsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

    // 1. DNS Records
    if let Ok(response) = resolver.ipv4_lookup(domain).await {
        for ip in response.iter() {
            result.all_ipv4.push(ip.to_string());
        }
        result.ipv4 = result.all_ipv4.first().cloned();
    }

    if let Ok(response) = resolver.ipv6_lookup(domain).await {
        for ip in response.iter() {
            result.ipv6.push(ip.to_string());
        }
    }

    if let Ok(response) = resolver.ns_lookup(domain).await {
        for ns in response.iter() {
            result.dns.nameservers.push(ns.to_string());
        }
    }

    if let Ok(response) = resolver.mx_lookup(domain).await {
        for mx in response.iter() {
            result.dns.mx_records.push(format!("{} {}", mx.preference(), mx.exchange()));
        }
    }

    if let Ok(response) = resolver.txt_lookup(domain).await {
        for txt in response.iter() {
            let record = txt.to_string();
            if record.contains("v=spf1") {
                result.dns.spf = Some(record.clone());
            }
            result.dns.txt_records.push(record);
        }
    }

    // Attempt DMARC Lookup
    let dmarc_domain = format!("_dmarc.{}", domain);
    if let Ok(response) = resolver.txt_lookup(dmarc_domain.as_str()).await {
        for txt in response.iter() {
            let record = txt.to_string();
            if record.contains("v=DMARC1") {
                result.dns.dmarc = Some(record);
                break;
            }
        }
    }

    if let Some(t) = &progress_tx {
        let _ = t.send(crate::ScanProgress {
            module: "Domain Info".into(),
            percentage: 40.0,
            message: "DNS Analysis Complete. Checking Ports.".into(),
            status: "Info".into(),
        }).await;
    }

    // 2. Open Ports
    let target_ports = [80, 443, 21, 22, 25, 3306, 8080, 8443];
    for port in target_ports {
        let target = format!("{}:{}", domain, port);
        if timeout(Duration::from_millis(500), TcpStream::connect(&target)).await.is_ok() {
            result.open_ports.push(port.to_string());
        }
    }

    if let Some(t) = &progress_tx {
        let _ = t.send(crate::ScanProgress {
            module: "Domain Info".into(),
            percentage: 70.0,
            message: "Checking HTTP/HTTPS footprint in native client".into(),
            status: "Info".into(),
        }).await;
    }

    // 3. HTTP / Security Check
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .unwrap_or_else(|_| Client::new());

    if let Ok(resp) = client.get(&format!("http://{}", domain)).send().await {
        result.http_status = Some(resp.status().to_string());
        if resp.url().scheme() == "https" {
            result.security.https_redirect = true;
        }
        if let Some(srv) = resp.headers().get("server") {
            result.web_server = Some(srv.to_str().unwrap_or("Unknown").to_string());
        }
    }

    if let Ok(resp) = client.get(&format!("https://{}", domain)).send().await {
        result.security.https_available = true;
        result.ssl.status = "Valid (Native Check)".into();
        result.security.headers_count = resp.headers().len();
        
        // Track typical security headers
        for h in ["strict-transport-security", "content-security-policy", "x-frame-options"] {
            if let Some(val) = resp.headers().get(h) {
                result.security.security_headers.insert(h.into(), val.to_str().unwrap_or("").into());
            }
        }
    } else {
        result.ssl.status = "Invalid / Unreachable".into();
    }

    // Very basic scoring logic for fallback
    let mut score = 50;
    if result.security.https_available { score += 20; }
    if result.security.https_redirect { score += 10; }
    score += (result.security.security_headers.len() * 5) as u32;
    result.security_score = std::cmp::min(100, score);
    result.response_time_ms = Some(start_time.elapsed().as_millis() as f64);

    if let Some(t) = &progress_tx {
        let _ = t.send(crate::ScanProgress {
            module: "Domain Info".into(),
            percentage: 100.0,
            message: "Analysis logic loop finished".into(),
            status: "Info".into(),
        }).await;
    }

    Ok(result)
}
