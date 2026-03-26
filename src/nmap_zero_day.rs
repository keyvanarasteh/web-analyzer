use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio::process::Command;

// ── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cpe: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub source: String,
    pub vuln_type: String,
    pub id: String,
    pub description: String,
    pub severity: SeverityInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityInfo {
    pub level: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapScanResult {
    pub domain: String,
    pub ip: String,
    pub scan_time_secs: f64,
    pub dns_info: DnsInfo,
    pub open_ports: Vec<PortInfo>,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
}

// ── Security sources ────────────────────────────────────────────────────────

const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// ── Main scan function ──────────────────────────────────────────────────────

pub async fn run_nmap_scan(
    domain: &str,
) -> Result<NmapScanResult, Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();

    // ── DNS Resolution ──────────────────────────────────────────────────
    let mut ipv4: Option<String> = None;
    let mut ipv6: Option<String> = None;

    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", domain)).await {
        for addr in addrs {
            match addr.ip() {
                std::net::IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(ip.to_string()),
                std::net::IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(ip.to_string()),
                _ => {}
            }
        }
    }

    let ip = ipv4.clone().unwrap_or_else(|| domain.to_string());

    // ── Nmap Port Scan ──────────────────────────────────────────────────
    let output = Command::new("nmap")
        .args([
            "-sV",
            "-Pn",
            "-A",
            "-T5",
            "--top-ports",
            "1000",
            "-oG",
            "-",
            &ip,
        ])
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut open_ports: Vec<PortInfo> = Vec::new();

    // Parse grepable output: Host: x.x.x.x () Ports: 22/open/tcp//ssh//OpenSSH 8.9/, ...
    for line in stdout.lines() {
        if !line.contains("Ports:") {
            continue;
        }
        if let Some(ports_section) = line.split("Ports: ").nth(1) {
            for port_entry in ports_section.split(',') {
                let parts: Vec<&str> = port_entry.trim().split('/').collect();
                if parts.len() >= 5 && parts[1].trim() == "open" {
                    let port: u16 = parts[0].trim().parse().unwrap_or(0);
                    let service = parts[4].trim().to_string();
                    let product = if parts.len() > 6 && !parts[6].trim().is_empty() {
                        Some(parts[6].trim().to_string())
                    } else {
                        None
                    };
                    let version = if parts.len() > 6 {
                        let p = parts[6].trim();
                        let v = if parts.len() > 7 { parts[7].trim() } else { "" };
                        format!("{} {}", p, v).trim().to_string()
                    } else {
                        String::new()
                    };

                    // Extract CPE from nmap XML output (if available in grepable)
                    let cpe = Vec::new(); // CPE extraction requires XML output mode

                    open_ports.push(PortInfo {
                        port,
                        state: "open".into(),
                        service,
                        version,
                        product,
                        cpe,
                    });
                }
            }
        }
    }

    // ── Vulnerability Lookup (NVD CVE) ──────────────────────────────────
    let vulnerabilities = fetch_vulnerabilities(&open_ports).await;

    let scan_time = start.elapsed().as_secs_f64();

    Ok(NmapScanResult {
        domain: domain.to_string(),
        ip,
        scan_time_secs: scan_time,
        dns_info: DnsInfo { ipv4, ipv6 },
        open_ports,
        vulnerabilities,
    })
}

// ── CVE/Vulnerability Lookup ────────────────────────────────────────────────

async fn fetch_vulnerabilities(ports: &[PortInfo]) -> Vec<VulnerabilityInfo> {
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap_or_else(|_| Client::new());

    let mut all_vulns = Vec::new();

    for port in ports {
        // Build keyword from service + version/product
        let keywords: Vec<&str> = [
            port.service.as_str(),
            port.product.as_deref().unwrap_or(""),
            port.version.as_str(),
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();

        if keywords.is_empty() {
            continue;
        }
        let keyword = keywords.join(" ");

        // ── NVD CVE Query ───────────────────────────────────────────
        let nvd_vulns = query_nvd(&client, &keyword).await;
        all_vulns.extend(nvd_vulns);

        // ── Exploit-DB Query ────────────────────────────────────────
        let exploit_vulns = query_exploit_db(&client, &keyword).await;
        all_vulns.extend(exploit_vulns);
    }

    all_vulns
}

async fn query_nvd(client: &Client, keyword: &str) -> Vec<VulnerabilityInfo> {
    let mut results = Vec::new();

    let encoded = urlencoding::encode(keyword);
    let url = format!("{}?keywordSearch={}&resultsPerPage=10", NVD_API, encoded);
    let resp = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return results,
    };

    let body: Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return results,
    };

    if let Some(vulns) = body.get("vulnerabilities").and_then(|v| v.as_array()) {
        for item in vulns {
            let cve = match item.get("cve") {
                Some(c) => c,
                None => continue,
            };
            let id = cve
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A")
                .to_string();
            let description = cve
                .get("descriptions")
                .and_then(|d| d.as_array())
                .and_then(|arr| arr.first())
                .and_then(|d| d.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("No description available")
                .to_string();

            let severity = calculate_severity(cve);

            results.push(VulnerabilityInfo {
                source: "NVD".into(),
                vuln_type: "CVE".into(),
                id,
                description,
                severity,
            });
        }
    }

    results
}

async fn query_exploit_db(client: &Client, keyword: &str) -> Vec<VulnerabilityInfo> {
    let mut results = Vec::new();

    let encoded = urlencoding::encode(keyword);
    let url = format!("https://www.exploit-db.com/search?q={}", encoded);
    if let Ok(resp) = client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
    {
        if resp.status().is_success() {
            results.push(VulnerabilityInfo {
                source: "Exploit-DB".into(),
                vuln_type: "Exploit".into(),
                id: "N/A".into(),
                description: format!("Potential exploit for {}", keyword),
                severity: SeverityInfo {
                    level: "Unknown".into(),
                    score: 0.0,
                },
            });
        }
    }

    results
}

// ── Severity Calculation (CVSS v3.1) ────────────────────────────────────────

fn calculate_severity(cve: &Value) -> SeverityInfo {
    let base_score = cve
        .get("metrics")
        .and_then(|m| m.get("cvssMetricV31"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|m| m.get("cvssData"))
        .and_then(|d| d.get("baseScore"))
        .and_then(|s| s.as_f64())
        .unwrap_or(0.0);

    let level = if base_score >= 9.0 {
        "Critical"
    } else if base_score >= 7.0 {
        "High"
    } else if base_score >= 4.0 {
        "Medium"
    } else if base_score > 0.0 {
        "Low"
    } else {
        "Unknown"
    };

    SeverityInfo {
        level: level.into(),
        score: base_score,
    }
}

impl qicro_data_core::registry::Registrable for PortInfo {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("PortInfo", "portinfo")
    }
}

impl qicro_data_core::registry::Registrable for VulnerabilityInfo {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("VulnerabilityInfo", "vulnerabilityinfo")
    }
}

impl qicro_data_core::registry::Registrable for SeverityInfo {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("SeverityInfo", "severityinfo")
    }
}

impl qicro_data_core::registry::Registrable for DnsInfo {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("DnsInfo", "dnsinfo")
    }
}

impl qicro_data_core::registry::Registrable for NmapScanResult {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("NmapScanResult", "nmapscanresult")
    }
}
