use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ── Data Structures ─────────────────────────────────────────────────────────

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
    pub html_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCrawlerResult {
    pub status: String,
    pub bots: HashMap<String, String>,
}

// ── AI bot list ─────────────────────────────────────────────────────────────

const AI_BOTS: &[&str] = &[
    "GPTBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Claude-Web",
    "Applebot-Extended",
    "OAI-SearchBot",
    "PerplexityBot",
];

// ── Main function ───────────────────────────────────────────────────────────

pub async fn analyze_geo(
    domain: &str,
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<GeoAnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
    let base_url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    // ── 1. Check llms.txt ───────────────────────────────────────────────
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Geo Analysis".into(), percentage: 10.0, message: "Checking for llms.txt presence...".into(), status: "Info".into() }).await; }
    let llms_paths = ["/llms.txt", "/llms-full.txt", "/.well-known/llms.txt"];
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

    // ── 2. Check WebMCP endpoints + HTML features ───────────────────────
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Geo Analysis".into(), percentage: 40.0, message: "Scanning for Model Context Protocol (MCP) endpoints...".into(), status: "Info".into() }).await; }
    let mcp_paths = ["/.well-known/mcp", "/mcp.json"];
    let mut mcp_found = Vec::new();
    for path in &mcp_paths {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                mcp_found.push(path.to_string());
            }
        }
    }

    // Check HTML for navigator.modelContext or WebMCP references
    let mut html_features = Vec::new();
    if let Ok(resp) = client.get(&base_url).send().await {
        if resp.status().is_success() {
            if let Ok(html) = resp.text().await {
                if html.contains("navigator.modelContext") {
                    html_features.push("navigator.modelContext API".to_string());
                }
                let lower = html.to_lowercase();
                if lower.contains("webmcp") || lower.contains("model context protocol") {
                    html_features
                        .push("WebMCP/Model Context Protocol references in HTML".to_string());
                }
            }
        }
    }

    let mcp_has_anything = !mcp_found.is_empty() || !html_features.is_empty();

    // ── 3. Check AI crawler directives in robots.txt ────────────────────
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Geo Analysis".into(), percentage: 70.0, message: "Analyzing AI crawler directives in robots.txt...".into(), status: "Info".into() }).await; }
    let mut directives: HashMap<String, String> = AI_BOTS
        .iter()
        .map(|b| (b.to_string(), "Unknown".into()))
        .collect();

    let robots_url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&robots_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                let mut current_agent: Option<String> = None;
                for line in body.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let lower = line.to_lowercase();

                    if lower.starts_with("user-agent:") {
                        let agent = line.split(':').nth(1).unwrap_or("").trim().to_string();
                        if AI_BOTS.iter().any(|b| *b == agent) {
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
                        } else if lower.starts_with("allow:")
                            && directives.get(agent).map(|s| s.as_str()) == Some("Unknown") {
                                directives.insert(agent.clone(), "Allowed".into());
                            }
                    }
                }
                // Mark remaining unknowns as implicit allow
                for (_, v) in directives.iter_mut() {
                    if *v == "Unknown" {
                        *v = "Allowed (Implicit)".into();
                    }
                }
            }
        }
    }

    let blocked_count = directives
        .values()
        .filter(|v| v.contains("Blocked"))
        .count();
    let crawler_status = if blocked_count > AI_BOTS.len() / 2 {
        "Restrictive"
    } else {
        "Permissive"
    };

    // ── Score calculation ────────────────────────────────────────────────
    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Geo Analysis".into(), percentage: 90.0, message: "Calculating Geofencing AI readiness score...".into(), status: "Info".into() }).await; }
    let mut score: u32 = 0;

    // llms.txt (up to 40 pts)
    if !llms_found.is_empty() {
        score += 20 + (llms_found.len() as u32 * 10).min(20);
    }

    // WebMCP (up to 40 pts)
    if mcp_has_anything {
        score += 20;
        if !mcp_found.is_empty() {
            score += 10;
        }
        if !html_features.is_empty() {
            score += 10;
        }
    }

    // AI crawlers (20 pts)
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
        llms_txt: LlmsTxtResult {
            found: !llms_found.is_empty(),
            files: llms_found,
        },
        webmcp: WebMcpResult {
            found: mcp_has_anything,
            endpoints: mcp_found,
            html_features,
        },
        ai_crawler_directives: AiCrawlerResult {
            status: crawler_status.to_string(),
            bots: directives,
        },
        geo_score: score,
        geo_grade: grade,
    })
}
