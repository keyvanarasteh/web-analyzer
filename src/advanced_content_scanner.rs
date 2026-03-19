use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFound {
    pub v_type: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerResult {
    pub domain: String,
    pub secrets_found: Vec<String>,
    pub vulnerabilities_found: Vec<VulnerabilityFound>,
}

pub async fn scan_content(domain: &str) -> Result<ScannerResult, Box<dyn std::error::Error + Send + Sync>> {
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
    let html_content = res.text().await?;
    
    let mut secrets = Vec::new();
    let mut vulnerabilities = Vec::new();

    let aws_regex = Regex::new(r#"\bAKIA[0-9A-Z]{16}\b"#).unwrap();
    let google_regex = Regex::new(r#"\bAIza[0-9A-Za-z\-_]{35}\b"#).unwrap();
    let stripe_regex = Regex::new(r#"\b(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,34}\b"#).unwrap();

    if aws_regex.is_match(&html_content) { secrets.push("AWS Access Key".into()); }
    if google_regex.is_match(&html_content) { secrets.push("Google API Key".into()); }
    if stripe_regex.is_match(&html_content) { secrets.push("Stripe API Key".into()); }

    // basic JS vulnerability checks
    if html_content.contains("document.write(") && html_content.contains("location") {
        vulnerabilities.push(VulnerabilityFound {
            v_type: "DOM XSS".into(),
            severity: "High".into(),
            description: "Potential document.write with location source".into(),
        });
    }

    if html_content.contains("innerHTML") && html_content.contains("location") {
        vulnerabilities.push(VulnerabilityFound {
            v_type: "DOM XSS".into(),
            severity: "High".into(),
            description: "Potential innerHTML assignment with location source".into(),
        });
    }
    
    if html_content.contains("Access-Control-Allow-Origin: *") {
         vulnerabilities.push(VulnerabilityFound {
            v_type: "CORS Misconfiguration".into(),
            severity: "Medium".into(),
            description: "Wildcard CORS origin found".into(),
        });
    }

    Ok(ScannerResult {
        domain: domain.to_string(),
        secrets_found: secrets,
        vulnerabilities_found: vulnerabilities,
    })
}
