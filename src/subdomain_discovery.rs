use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainDiscoveryResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub response_time_ms: u128,
}

pub async fn discover_subdomains(domain: &str) -> Result<SubdomainDiscoveryResult, Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();
    
    let output = Command::new("subfinder")
        .arg("-d")
        .arg(domain)
        .arg("-silent")
        .output()
        .await?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    
    let subdomains: Vec<String> = stdout_str
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let duration = start_time.elapsed().as_millis();

    Ok(SubdomainDiscoveryResult {
        domain: domain.to_string(),
        subdomains,
        response_time_ms: duration,
    })
}
