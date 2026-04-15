use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainDiscoveryResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub total_found: usize,
    pub filtered_count: usize,
    pub response_time_ms: u128,
}

pub async fn discover_subdomains(
    _domain: &str,
) -> Result<SubdomainDiscoveryResult, Box<dyn std::error::Error + Send + Sync>> {
    Err(crate::error::WebAnalyzerError::UnsupportedPlatform("Subdomain discovery via Subfinder binary is unsupported on mobile endpoints.".into()).into())
}

pub fn is_subdomain(domain: &str) -> bool {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.iter().all(|p| p.parse::<u8>().is_ok()) || domain.contains(':') {
        return false;
    }
    parts.len() > 2
}
