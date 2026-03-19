use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAnalysisResult {
    pub domain: String,
    pub llms_txt: LlmsTxtResult,
    pub webmcp: WebMcpResult,
    pub ai_crawler_directives: AiCrawlerResult,
    pub geo_score: u32,
    pub geo_grade: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmsTxtResult {
    pub found: bool,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebMcpResult {
    pub found: bool,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCrawlerResult {
    pub status: String,
    pub bots: HashMap<String, String>,
}

pub async fn analyze_geo(domain: &str) -> Result<GeoAnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
    let base_url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    // 1. Check llms.txt
    let llms_paths = vec!["/llms.txt", "/llms-full.txt", "/.well-known/llms.txt"];
    let mut llms_found = Vec::new();
    for path in &llms_paths {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                let ct = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();
                if ct.contains("text/plain") || ct.contains("text/html") {
                    llms_found.push(path.to_string());
                }
            }
        }
    }

    // 2. Check WebMCP
    let mcp_paths = vec!["/.well-known/mcp", "/mcp.json"];
    let mut mcp_found = Vec::new();
    for path in &mcp_paths {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                mcp_found.push(path.to_string());
            }
        }
    }

    // 3. Check AI crawler directives in robots.txt
    let ai_bots = vec![
        "GPTBot", "ChatGPT-User", "ClaudeBot", "Claude-Web",
        "Applebot-Extended", "OAI-SearchBot", "PerplexityBot",
    ];
    let mut directives: HashMap<String, String> = ai_bots.iter().map(|b| (b.to_string(), "Unknown".into())).collect();

    let robots_url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&robots_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                let mut current_agent: Option<String> = None;
                for line in body.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    let lower = line.to_lowercase();
                    if lower.starts_with("user-agent:") {
                        let agent = line.split(':').nth(1).unwrap_or("").trim().to_string();
                        if ai_bots.iter().any(|b| *b == agent) {
                            current_agent = Some(agent);
                        } else {
                            current_agent = None;
                        }
                    } else if let Some(ref agent) = current_agent {
                        if lower.starts_with("disallow:") {
                            let path = line.split(':').nth(1).unwrap_or("").trim();
                            if path == "/" {
                                directives.insert(agent.clone(), "Blocked".into());
                            } else if directives.get(agent).map(|s| s.as_str()) == Some("Unknown") {
                                directives.insert(agent.clone(), "Partially Blocked".into());
                            }
                        } else if lower.starts_with("allow:") {
                            if directives.get(agent).map(|s| s.as_str()) == Some("Unknown") {
                                directives.insert(agent.clone(), "Allowed".into());
                            }
                        }
                    }
                }
                // Mark remaining unknowns
                for (_, v) in directives.iter_mut() {
                    if *v == "Unknown" { *v = "Allowed (Implicit)".into(); }
                }
            }
        }
    }

    let blocked_count = directives.values().filter(|v| v.contains("Blocked")).count();
    let crawler_status = if blocked_count > ai_bots.len() / 2 { "Restrictive" } else { "Permissive" };

    // Score calculation
    let mut score: u32 = 0;
    if !llms_found.is_empty() {
        score += 20 + (llms_found.len() as u32 * 10).min(20);
    }
    if !mcp_found.is_empty() {
        score += 30;
    }
    if crawler_status == "Permissive" {
        score += 20;
    }

    let grade = match score {
        80..=100 => "A (Excellent)".into(),
        60..=79 => "B (Good)".into(),
        40..=59 => "C (Fair)".into(),
        20..=39 => "D (Poor)".into(),
        _ => "F (None)".into(),
    };

    Ok(GeoAnalysisResult {
        domain: domain.to_string(),
        llms_txt: LlmsTxtResult { found: !llms_found.is_empty(), files: llms_found },
        webmcp: WebMcpResult { found: !mcp_found.is_empty(), endpoints: mcp_found },
        ai_crawler_directives: AiCrawlerResult { status: crawler_status.to_string(), bots: directives },
        geo_score: score,
        geo_grade: grade,
    })
}
