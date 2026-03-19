use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::payloads;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub status_code: u16,
    pub api_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiScanResult {
    pub domain: String,
    pub endpoints_found: Vec<ApiEndpoint>,
    pub total_paths_probed: usize,
}

pub async fn scan_api_endpoints(domain: &str) -> Result<ApiScanResult, Box<dyn std::error::Error + Send + Sync>> {
    let base_url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    // Load API paths from embedded payload file (846 paths)
    let api_paths = payloads::lines(payloads::API_ENDPOINTS);
    let total_paths_probed = api_paths.len();

    let mut endpoints_found = Vec::new();

    for path in &api_paths {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();

            let api_type = if content_type.contains("application/json") {
                "REST/JSON"
            } else if content_type.contains("application/xml") || content_type.contains("text/xml") {
                "REST/XML"
            } else if content_type.contains("graphql") {
                "GraphQL"
            } else if status == 401 || status == 403 {
                "Protected API"
            } else {
                continue; // Not an API endpoint
            };

            endpoints_found.push(ApiEndpoint {
                url,
                status_code: status,
                api_type: api_type.to_string(),
            });
        }
    }

    Ok(ApiScanResult {
        domain: domain.to_string(),
        endpoints_found,
        total_paths_probed,
    })
}
