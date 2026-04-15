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

pub async fn get_domain_info(
    _domain: &str,
    _progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<DomainInfoResult, Box<dyn std::error::Error + Send + Sync>> {
    Err(crate::error::WebAnalyzerError::UnsupportedPlatform("Mobile integration via native networking is pending implementation.".into()).into())
}
