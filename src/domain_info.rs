use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfoResult {
    pub domain: String,
    pub ipv4: Option<String>,
    pub ipv6: Vec<String>,
    pub all_ipv4: Vec<String>,
    pub http_status: Option<String>,
    pub server: Option<String>,
}

pub async fn get_domain_info(domain: &str) -> Result<DomainInfoResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut ipv4 = None;
    let mut all_ipv4 = vec![];
    let mut ipv6 = vec![];

    // Basic DNS A/AAAA resolution natively
    if let Ok(addrs) = format!("{}:80", domain).to_socket_addrs() {
        for addr in addrs {
            match addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    all_ipv4.push(ip.to_string());
                }
                std::net::IpAddr::V6(ip) => {
                    ipv6.push(ip.to_string());
                }
            }
        }
    }
    
    if !all_ipv4.is_empty() {
        ipv4 = Some(all_ipv4[0].clone());
    }
    
    // HTTP check
    let mut http_status = None;
    let mut server = None;
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
        
    if let Ok(res) = client.get(&format!("http://{}", domain)).send().await {
        http_status = Some(res.status().to_string());
        if let Some(serv) = res.headers().get("Server") {
            if let Ok(s) = serv.to_str() {
                server = Some(s.to_string());
            }
        }
    }

    Ok(DomainInfoResult {
        domain: domain.to_string(),
        ipv4,
        ipv6,
        all_ipv4,
        http_status,
        server,
    })
}
