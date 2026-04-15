use serde::{Deserialize, Serialize};

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

pub async fn run_nmap_scan(
    _domain: &str,
    _progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<NmapScanResult, Box<dyn std::error::Error + Send + Sync>> {
    Err(crate::error::WebAnalyzerError::UnsupportedPlatform("Hardware-level Nmap port scanning is unsupported on mobile endpoints.".into()).into())
}
