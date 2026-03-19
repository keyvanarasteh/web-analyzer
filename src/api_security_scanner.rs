use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
}

/// Common API paths to probe
const API_PATHS: &[&str] = &[
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/graphql",
    "/api/users", "/api/auth", "/api/login",
    "/api/health", "/api/status",
    "/swagger", "/openapi.json",
    "/rest", "/rest/v1",
    "/api/config", "/api/info",
];

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

    let mut endpoints_found = Vec::new();

    for path in API_PATHS {
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
    })
}
