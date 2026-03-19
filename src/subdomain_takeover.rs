use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverVulnerability {
    pub subdomain: String,
    pub service: String,
    pub cname: Option<String>,
    pub confidence: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverResult {
    pub domain: String,
    pub subdomains_checked: usize,
    pub vulnerable: Vec<TakeoverVulnerability>,
}

/// Known vulnerable service fingerprints: (CNAME pattern, error body pattern)
fn vulnerable_services() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("AWS S3", "s3.amazonaws.com", "NoSuchBucket"),
        ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
        ("Heroku", "herokuapp.com", "No such app"),
        ("Vercel", "vercel.app", "404: Not Found"),
        ("Netlify", "netlify.app", "Not found"),
        ("Azure", "azurewebsites.net", "Microsoft Azure App Service"),
        ("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
        ("Fastly", "fastly.net", "Fastly error: unknown domain"),
        ("Pantheon", "pantheonsite.io", "The gods are wise"),
        ("Surge.sh", "surge.sh", "project not found"),
        ("Ghost", "ghost.io", "The thing you were looking for is no longer here"),
        ("Firebase", "firebaseapp.com", "404 Not Found"),
    ]
}

async fn resolve_cname(subdomain: &str) -> Option<String> {
    let output = Command::new("dig")
        .args(["+short", "CNAME", subdomain])
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() { None } else { Some(stdout.trim_end_matches('.').to_string()) }
}

pub async fn check_subdomain_takeover(
    domain: &str,
    subdomains: &[String],
) -> Result<TakeoverResult, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;
    let services = vulnerable_services();
    let mut vulnerable = Vec::new();

    for sub in subdomains {
        let cname = resolve_cname(sub).await;
        if let Some(ref cname_val) = cname {
            for (svc_name, pattern, error_body) in &services {
                if cname_val.to_lowercase().contains(*pattern) {
                    // Try fetching the subdomain to confirm
                    let body = match client.get(format!("https://{}", sub)).send().await {
                        Ok(resp) => resp.text().await.unwrap_or_default(),
                        Err(_) => String::new(),
                    };
                    let confidence = if body.to_lowercase().contains(&error_body.to_lowercase()) {
                        "High"
                    } else {
                        "Medium"
                    };
                    vulnerable.push(TakeoverVulnerability {
                        subdomain: sub.clone(),
                        service: svc_name.to_string(),
                        cname: cname.clone(),
                        confidence: confidence.to_string(),
                        description: format!("CNAME points to {} ({})", svc_name, cname_val),
                    });
                    break;
                }
            }
        }
    }

    Ok(TakeoverResult {
        domain: domain.to_string(),
        subdomains_checked: subdomains.len(),
        vulnerable,
    })
}
