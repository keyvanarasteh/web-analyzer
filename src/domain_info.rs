use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ── WHOIS server database ───────────────────────────────────────────────────

const WHOIS_SERVERS: &[(&str, &str)] = &[
    ("com", "whois.verisign-grs.com"), ("net", "whois.verisign-grs.com"),
    ("org", "whois.pir.org"), ("info", "whois.afilias.net"),
    ("biz", "whois.biz"), ("us", "whois.nic.us"),
    ("uk", "whois.nic.uk"), ("de", "whois.denic.de"),
    ("fr", "whois.nic.fr"), ("it", "whois.nic.it"),
    ("nl", "whois.domain-registry.nl"), ("eu", "whois.eu"),
    ("ru", "whois.tcinet.ru"), ("cn", "whois.cnnic.cn"),
    ("jp", "whois.jprs.jp"), ("br", "whois.registro.br"),
    ("au", "whois.auda.org.au"), ("ca", "whois.cira.ca"),
    ("in", "whois.registry.in"), ("tr", "whois.nic.tr"),
    ("co", "whois.nic.co"), ("io", "whois.nic.io"),
    ("me", "whois.nic.me"), ("tv", "whois.nic.tv"),
    ("cc", "whois.nic.cc"),
];

/// Common ports for scanning
const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"), (22, "SSH"), (25, "SMTP"), (80, "HTTP"),
    (443, "HTTPS"), (3306, "MySQL"), (5432, "PostgreSQL"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
];

/// Security headers to check
const SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security", "x-frame-options",
    "x-content-type-options", "x-xss-protection",
    "content-security-policy",
];

/// Privacy keywords in WHOIS output
const PRIVACY_KEYWORDS: &[&str] = &[
    "redacted", "privacy", "gdpr", "protected", "proxy", "private",
];

// ── Data Structures ─────────────────────────────────────────────────────────

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

// ── Main function ───────────────────────────────────────────────────────────

pub async fn get_domain_info(domain: &str) -> Result<DomainInfoResult, Box<dyn std::error::Error + Send + Sync>> {
    let clean = clean_domain(domain);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0")
        .build()?;

    // ── IP Resolution ───────────────────────────────────────────────────
    let (mut ipv4, mut all_ipv4, mut ipv6) = (None, vec![], vec![]);

    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", clean)).await {
        for addr in addrs {
            match addr.ip() {
                std::net::IpAddr::V4(ip) => { all_ipv4.push(ip.to_string()); }
                std::net::IpAddr::V6(ip) => { ipv6.push(ip.to_string()); }
            }
        }
    }
    if !all_ipv4.is_empty() { ipv4 = Some(all_ipv4[0].clone()); }

    // ── Reverse DNS ─────────────────────────────────────────────────────
    let reverse_dns = if let Some(ref ip) = ipv4 {
        reverse_dns_lookup(ip).await
    } else { None };

    // ── Run concurrent tasks ────────────────────────────────────────────
    let whois_fut = query_whois(&clean);
    let ssl_fut = check_ssl(&clean);
    let dns_fut = get_dns_records(&clean);
    let ports_fut = scan_ports(ipv4.as_deref());
    let http_fut = check_http_status(&client, &clean);
    let security_fut = check_security(&client, &clean);

    let (whois, ssl, dns, open_ports, http_info, security) =
        tokio::join!(whois_fut, ssl_fut, dns_fut, ports_fut, http_fut, security_fut);

    // ── Security Score ──────────────────────────────────────────────────
    let score = calculate_security_score(&ssl, &dns, &security);

    Ok(DomainInfoResult {
        domain: clean,
        ipv4, ipv6, all_ipv4,
        reverse_dns,
        whois,
        ssl,
        dns,
        open_ports,
        http_status: http_info.0,
        web_server: http_info.1,
        response_time_ms: http_info.2,
        security,
        security_score: score,
    })
}

// ── Domain cleaning ─────────────────────────────────────────────────────────

fn clean_domain(domain: &str) -> String {
    let d = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace("www.", "");
    d.split('/').next().unwrap_or(&d)
        .split(':').next().unwrap_or(&d)
        .to_string()
}

// ── Reverse DNS ─────────────────────────────────────────────────────────────

async fn reverse_dns_lookup(ip: &str) -> Option<String> {
    let output = tokio::process::Command::new("dig")
        .args(["+short", "-x", ip])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text.trim_end_matches('.').to_string()) }
}

// ── WHOIS via TCP socket ────────────────────────────────────────────────────

fn get_whois_server(domain: &str) -> &'static str {
    let tld = domain.split('.').last().unwrap_or("");
    WHOIS_SERVERS.iter()
        .find(|(t, _)| *t == tld)
        .map(|(_, s)| *s)
        .unwrap_or("whois.iana.org")
}

async fn query_whois_tcp(domain: &str, server: &str) -> Option<String> {
    let addr = format!("{}:43", server);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&addr),
    ).await.ok()?.ok()?;

    stream.write_all(format!("{}\r\n", domain).as_bytes()).await.ok()?;

    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(10),
        stream.read_to_end(&mut buf),
    ).await;

    Some(String::from_utf8_lossy(&buf).to_string())
}

async fn query_whois(domain: &str) -> WhoisInfo {
    let mut info = WhoisInfo {
        registrar: "Unknown".into(),
        creation_date: "Unknown".into(),
        expiry_date: "Unknown".into(),
        last_updated: "Unknown".into(),
        domain_status: vec![],
        registrant: "Unknown".into(),
        privacy_protection: "Unknown".into(),
        name_servers: vec![],
    };

    let server = get_whois_server(domain);
    let output = match query_whois_tcp(domain, server).await {
        Some(o) if !o.is_empty() => o,
        _ => return info,
    };

    // Follow referral
    let final_output = if let Some(caps) = Regex::new(r"(?i)Registrar WHOIS Server:\s*(.+)")
        .ok().and_then(|r| r.captures(&output))
    {
        let referral = caps.get(1).unwrap().as_str().trim()
            .replace("whois://", "").replace("http://", "").replace("https://", "");
        query_whois_tcp(domain, &referral).await.unwrap_or(output)
    } else { output };

    // Parse registrar
    for pat in &[r"(?i)Registrar:\s*(.+)", r"(?i)Registrar Name:\s*(.+)", r"(?i)Registrar Organization:\s*(.+)"] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            info.registrar = m.get(1).unwrap().as_str().trim().to_string();
            break;
        }
    }

    // Parse creation date
    for pat in &[r"(?i)Creation Date:\s*(.+)", r"(?i)Created Date:\s*(.+)", r"(?i)Created:\s*(.+)", r"(?i)Registration Time:\s*(.+)"] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            info.creation_date = m.get(1).unwrap().as_str().trim().split('\n').next().unwrap_or("").to_string();
            break;
        }
    }

    // Parse expiry date
    for pat in &[r"(?i)Registry Expiry Date:\s*(.+)", r"(?i)Registrar Registration Expiration Date:\s*(.+)", r"(?i)Expir(?:y|ation) Date:\s*(.+)", r"(?i)expires:\s*(.+)", r"(?i)Expiration Time:\s*(.+)"] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            info.expiry_date = m.get(1).unwrap().as_str().trim().split('\n').next().unwrap_or("").to_string();
            break;
        }
    }

    // Parse updated date
    for pat in &[r"(?i)Updated Date:\s*(.+)", r"(?i)Last Updated:\s*(.+)", r"(?i)last-update:\s*(.+)", r"(?i)Modified Date:\s*(.+)"] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            info.last_updated = m.get(1).unwrap().as_str().trim().split('\n').next().unwrap_or("").to_string();
            break;
        }
    }

    // Parse domain status
    if let Ok(rx) = Regex::new(r"(?i)(?:Domain )?Status:\s*(.+)") {
        info.domain_status = rx.captures_iter(&final_output)
            .filter_map(|c| c.get(1).map(|m| m.as_str().trim().split_whitespace().next().unwrap_or("").to_string()))
            .filter(|s| !s.is_empty())
            .take(3)
            .collect();
    }
    if info.domain_status.is_empty() { info.domain_status.push("Unknown".into()); }

    // Parse registrant
    for pat in &[r"(?i)Registrant Name:\s*(.+)", r"(?i)Registrant:\s*(.+)", r"(?i)Registrant Organization:\s*(.+)"] {
        if let Some(m) = Regex::new(pat).ok().and_then(|r| r.captures(&final_output)) {
            let val = m.get(1).unwrap().as_str().trim().split('\n').next().unwrap_or("").to_string();
            if !val.is_empty() { info.registrant = val; break; }
        }
    }

    // Privacy protection
    let lower = final_output.to_lowercase();
    info.privacy_protection = if PRIVACY_KEYWORDS.iter().any(|k| lower.contains(k)) {
        "Active".into()
    } else { "Inactive".into() };

    // Name servers
    if let Ok(rx) = Regex::new(r"(?i)Name Server:\s*(.+)") {
        info.name_servers = rx.captures_iter(&final_output)
            .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_lowercase()))
            .take(4)
            .collect();
    }

    info
}

// ── SSL Certificate ─────────────────────────────────────────────────────────

async fn check_ssl(domain: &str) -> SslInfo {
    // Use openssl s_client to get certificate info
    let output = match tokio::process::Command::new("openssl")
        .args(["s_client", "-connect", &format!("{}:443", domain), "-servername", domain])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return SslInfo { status: "Error".into(), issued_to: None, issuer: None, protocol_version: None, expiry_date: None, days_until_expiry: None, alternative_names: vec![] },
    };

    if output.contains("CONNECTED") {
        let mut ssl = SslInfo {
            status: "Valid".into(),
            issued_to: None, issuer: None, protocol_version: None,
            expiry_date: None, days_until_expiry: None, alternative_names: vec![],
        };

        // Extract subject CN
        if let Some(m) = Regex::new(r"subject=.*?CN\s*=\s*([^\n/,]+)").ok().and_then(|r| r.captures(&output)) {
            ssl.issued_to = Some(m.get(1).unwrap().as_str().trim().to_string());
        }

        // Extract issuer CN
        if let Some(m) = Regex::new(r"issuer=.*?CN\s*=\s*([^\n/,]+)").ok().and_then(|r| r.captures(&output)) {
            ssl.issuer = Some(m.get(1).unwrap().as_str().trim().to_string());
        }

        // Extract protocol
        if let Some(m) = Regex::new(r"Protocol\s*:\s*(.+)").ok().and_then(|r| r.captures(&output)) {
            ssl.protocol_version = Some(m.get(1).unwrap().as_str().trim().to_string());
        }

        // Get dates via openssl x509
        if let Ok(cert_output) = tokio::process::Command::new("sh")
            .args(["-c", &format!("echo | openssl s_client -connect {}:443 -servername {} 2>/dev/null | openssl x509 -noout -dates -subject -ext subjectAltName 2>/dev/null", domain, domain)])
            .output()
            .await
        {
            let cert_text = String::from_utf8_lossy(&cert_output.stdout);

            if let Some(m) = Regex::new(r"notAfter=(.+)").ok().and_then(|r| r.captures(&cert_text)) {
                ssl.expiry_date = Some(m.get(1).unwrap().as_str().trim().to_string());
            }

            // Extract SANs
            if let Some(san_section) = cert_text.split("X509v3 Subject Alternative Name:").nth(1) {
                let names: Vec<String> = Regex::new(r"DNS:([^,\s]+)")
                    .ok()
                    .map(|r| r.captures_iter(san_section).filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).take(5).collect())
                    .unwrap_or_default();
                ssl.alternative_names = names;
            }
        }

        ssl
    } else {
        SslInfo { status: "HTTPS not available".into(), issued_to: None, issuer: None, protocol_version: None, expiry_date: None, days_until_expiry: None, alternative_names: vec![] }
    }
}

// ── DNS Records via dig ─────────────────────────────────────────────────────

async fn dig_query(domain: &str, rtype: &str) -> Vec<String> {
    tokio::process::Command::new("dig")
        .args(["+short", rtype, domain])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|t| t.lines().filter(|l| !l.trim().is_empty() && !l.starts_with(';')).map(|l| l.trim().to_string()).collect())
        .unwrap_or_default()
}

async fn get_dns_records(domain: &str) -> DnsInfo {
    let (ns, mx, txt) = tokio::join!(
        dig_query(domain, "NS"),
        dig_query(domain, "MX"),
        dig_query(domain, "TXT"),
    );

    let spf = txt.iter().find(|t| t.contains("v=spf1")).cloned();
    let dmarc_records = dig_query(&format!("_dmarc.{}", domain), "TXT").await;
    let dmarc = dmarc_records.into_iter().find(|t| t.contains("v=DMARC1"));

    DnsInfo { nameservers: ns, mx_records: mx, txt_records: txt, spf, dmarc }
}

// ── Port Scanning ───────────────────────────────────────────────────────────

async fn scan_ports(ip: Option<&str>) -> Vec<String> {
    let ip = match ip { Some(ip) => ip, None => return vec![] };

    let mut results = Vec::new();
    let mut handles = Vec::new();

    for &(port, service) in COMMON_PORTS {
        let addr = format!("{}:{}", ip, port);
        handles.push(tokio::spawn(async move {
            match tokio::time::timeout(
                Duration::from_secs(1),
                TcpStream::connect(&addr),
            ).await {
                Ok(Ok(_)) => Some(format!("{}/{}", port, service)),
                _ => None,
            }
        }));
    }

    for handle in handles {
        if let Ok(Some(port_str)) = handle.await {
            results.push(port_str);
        }
    }

    results.sort();
    results
}

// ── HTTP Status Check ───────────────────────────────────────────────────────

async fn check_http_status(client: &Client, domain: &str) -> (Option<String>, Option<String>, Option<f64>) {
    for proto in &["https", "http"] {
        let url = format!("{}://{}", proto, domain);
        let start = Instant::now();
        match client.get(&url).send().await {
            Ok(resp) => {
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                let status_str = format!("{} - {}", resp.status().as_u16(), proto.to_uppercase());
                let server = resp.headers().get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                return (Some(status_str), server, Some((elapsed * 100.0).round() / 100.0));
            }
            Err(_) => continue,
        }
    }
    (None, None, None)
}

// ── Security Check ──────────────────────────────────────────────────────────

async fn check_security(client: &Client, domain: &str) -> SecurityInfo {
    let mut sec = SecurityInfo {
        https_available: false,
        https_redirect: false,
        security_headers: HashMap::new(),
        headers_count: 0,
    };

    // HTTPS + security headers
    if let Ok(resp) = client.get(format!("https://{}", domain)).send().await {
        sec.https_available = true;
        for header in SECURITY_HEADERS {
            if let Some(val) = resp.headers().get(*header) {
                if let Ok(v) = val.to_str() {
                    sec.security_headers.insert(header.to_string(), v.to_string());
                    sec.headers_count += 1;
                }
            }
        }
    }

    // HTTP → HTTPS redirect
    if let Ok(resp) = client.get(format!("http://{}", domain)).send().await {
        let final_url = resp.url().to_string();
        if final_url.starts_with("https://") {
            sec.https_redirect = true;
        }
    }

    sec
}

// ── Security Score (0-100) ──────────────────────────────────────────────────

fn calculate_security_score(ssl: &SslInfo, dns: &DnsInfo, security: &SecurityInfo) -> u32 {
    let mut score: u32 = 0;

    // HTTPS available (+30)
    if security.https_available { score += 30; }

    // HTTPS redirect (+10)
    if security.https_redirect { score += 10; }

    // SSL valid (+20)
    if ssl.status == "Valid" { score += 20; }

    // Security headers (up to +20, 4 points each)
    score += (security.headers_count as u32 * 4).min(20);

    // SPF record (+10)
    if dns.spf.is_some() { score += 10; }

    // DMARC record (+10)
    if dns.dmarc.is_some() { score += 10; }

    score
}
