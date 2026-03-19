use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebTechResult {
    pub domain: String,
    pub web_server: String,
    pub backend: Vec<String>,
    pub frontend: Vec<String>,
    pub cms: Vec<String>,
    pub cdn: Vec<String>,
    pub is_wordpress: bool,
}

pub async fn detect_web_technologies(domain: &str) -> Result<WebTechResult, Box<dyn std::error::Error + Send + Sync>> {
    let url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()?;

    let res = client.get(&url).send().await?;
    let headers = res.headers().clone();
    let html_content = res.text().await?.to_lowercase();
    
    // Server
    let server = headers.get("server")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let powered_by = headers.get("x-powered-by")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // Backend
    let mut backend = vec![];
    if powered_by.contains("php") || html_content.contains(".php") || html_content.contains("phpsessid") {
        backend.push("PHP".to_string());
    }
    if powered_by.contains("asp.net") || html_content.contains("__viewstate") {
        backend.push("ASP.NET".to_string());
    }
    if html_content.contains("django") || html_content.contains("csrfmiddlewaretoken") {
        backend.push("Python Django".to_string());
    }
    if powered_by.contains("express") {
        backend.push("Node.js".to_string());
    }

    // Frontend
    let mut frontend = vec![];
    if html_content.contains("react") || html_content.contains("data-reactroot") {
        frontend.push("React".to_string());
    }
    if html_content.contains("vue") || html_content.contains("v-app") || html_content.contains("v-cloak") {
        frontend.push("Vue.js".to_string());
    }
    if html_content.contains("angular") || html_content.contains("ng-app") {
        frontend.push("Angular".to_string());
    }
    if html_content.contains("svelte") || html_content.contains("_svelte") {
        frontend.push("Svelte".to_string());
    }

    // CMS
    let mut cms = vec![];
    let mut is_wordpress = false;
    if html_content.contains("wp-content") || html_content.contains("wp-includes") {
        cms.push("WordPress".to_string());
        is_wordpress = true;
    }
    if html_content.contains("shopify") || html_content.contains("shopifycdn") {
        cms.push("Shopify".to_string());
    }
    if html_content.contains("drupal") || html_content.contains("sites/all") {
        cms.push("Drupal".to_string());
    }

    // CDN
    let mut cdn = vec![];
    let server_lower = server.to_lowercase();
    if server_lower.contains("cloudflare") || headers.contains_key("cf-ray") {
        cdn.push("Cloudflare".to_string());
    }
    if server_lower.contains("cloudfront") || headers.get("via").and_then(|h| h.to_str().ok()).unwrap_or("").to_lowercase().contains("cloudfront") {
        cdn.push("AWS CloudFront".to_string());
    }

    Ok(WebTechResult {
        domain: domain.to_string(),
        web_server: server,
        backend,
        frontend,
        cms,
        cdn,
        is_wordpress,
    })
}
