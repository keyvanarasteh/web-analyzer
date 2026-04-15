use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCheckResult {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub has_valid_dns: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverVulnerability {
    pub subdomain: String,
    pub service: String,
    pub vulnerability_type: String,
    pub cname: Option<String>,
    pub confidence: String,
    pub description: String,
    pub exploitation_difficulty: String,
    pub mitigation: String,
    pub dns_info: DnsCheckResult,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub subdomains_scanned: usize,
    pub vulnerable_count: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub scan_time_secs: f64,
    pub services_checked: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverResult {
    pub domain: String,
    pub statistics: ScanStatistics,
    pub vulnerable: Vec<TakeoverVulnerability>,
}

pub async fn check_subdomain_takeover(
    _domain: &str,
    _subdomains: &[String],
    _progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<TakeoverResult, Box<dyn std::error::Error + Send + Sync>> {
    Err(crate::error::WebAnalyzerError::UnsupportedPlatform("Mobile integration via native networking is pending implementation.".into()).into())
}
