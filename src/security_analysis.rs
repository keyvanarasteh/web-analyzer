use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    pub detected: bool,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysisResult {
    pub domain: String,
    pub https_available: bool,
    pub waf_detection: WafDetection,
    pub security_headers_score: u32,
    pub missing_headers: Vec<String>,
    pub cors_issues: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub exposed_server_info: Vec<String>,
}

pub async fn analyze_security(domain: &str) -> Result<SecurityAnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
    let url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()?;

    let https_url = if url.starts_with("http://") {
        url.replacen("http://", "https://", 1)
    } else if !url.starts_with("https://") {
        format!("https://{}", url.trim_start_matches("http://"))
    } else {
        url.clone()
    };

    let res = client.get(&https_url).send().await;
    let https_available = res.is_ok();
    
    let actual_res = if let Ok(r) = res {
        r
    } else {
        client.get(&url).send().await?
    };

    let headers = actual_res.headers();

    // 1. WAF Detection
    let mut waf = WafDetection { detected: false, provider: "Unknown".into() };
    if let Some(server) = headers.get("server") {
        let s = server.to_str().unwrap_or("").to_lowercase();
        if s.contains("cloudflare") {
            waf = WafDetection { detected: true, provider: "Cloudflare".into() };
        } else if s.contains("akamaighost") {
            waf = WafDetection { detected: true, provider: "Akamai".into() };
        } else if s.contains("imperva") || headers.contains_key("incap_ses") {
            waf = WafDetection { detected: true, provider: "Imperva".into() };
        } else if headers.contains_key("x-sucuri-id") {
            waf = WafDetection { detected: true, provider: "Sucuri".into() };
        } else if headers.contains_key("x-amz-cf-id") {
            waf = WafDetection { detected: true, provider: "AWS WAF".into() };
        }
    }

    // 2. Security Headers
    let sec_headers = vec![
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options", "x-xss-protection"
    ];
    let mut score = 0;
    let mut missing = Vec::new();

    for h in &sec_headers {
        if headers.contains_key(*h) {
            score += 20;
        } else {
            missing.push(h.to_string());
        }
    }

    // 3. CORS
    let mut cors_issues = Vec::new();
    if let Some(acao) = headers.get("access-control-allow-origin") {
        if acao.to_str().unwrap_or("") == "*" {
            cors_issues.push("Wildcard CORS Origin (*) allowed".into());
        }
    }

    // 4. Server Information Disclosure
    let mut exposed_server_info = Vec::new();
    if let Some(server) = headers.get("server") {
        exposed_server_info.push(format!("Server: {}", server.to_str().unwrap_or("")));
    }
    if let Some(xpb) = headers.get("x-powered-by") {
        exposed_server_info.push(format!("X-Powered-By: {}", xpb.to_str().unwrap_or("")));
    }

    // 5. Allowed Methods (Options request)
    let mut allowed_methods = Vec::new();
    if let Ok(opt_res) = client.request(Method::OPTIONS, &https_url).send().await {
        if let Some(allow) = opt_res.headers().get("allow") {
            let methods = allow.to_str().unwrap_or("");
            for m in methods.split(',') {
                let m = m.trim();
                if !m.is_empty() {
                    allowed_methods.push(m.to_string());
                }
            }
        }
    }

    Ok(SecurityAnalysisResult {
        domain: domain.to_string(),
        https_available,
        waf_detection: waf,
        security_headers_score: score,
        missing_headers: missing,
        cors_issues,
        allowed_methods,
        exposed_server_info,
    })
}
