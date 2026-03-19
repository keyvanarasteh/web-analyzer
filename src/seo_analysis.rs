use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeoAnalysisResult {
    pub domain: String,
    pub title: String,
    pub meta_description: Option<String>,
    pub h1_count: usize,
    pub internal_links: usize,
    pub external_links: usize,
    pub load_time_ms: u128,
    pub has_google_analytics: bool,
    pub seo_score: u32,
}

pub async fn analyze_advanced_seo(domain: &str) -> Result<SeoAnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
    let url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let start = Instant::now();
    let res = client.get(&url).send().await?;
    let load_time_ms = start.elapsed().as_millis();
    
    let html_text = res.text().await?;
    let document = Html::parse_document(&html_text);

    let title_selector = Selector::parse("title").unwrap();
    let title = document
        .select(&title_selector)
        .next()
        .map(|el| el.text().collect::<String>())
        .unwrap_or_else(|| "Missing".to_string());

    let meta_desc_selector = Selector::parse("meta[name=\"description\"]").unwrap();
    let meta_description = document
        .select(&meta_desc_selector)
        .next()
        .and_then(|el| el.value().attr("content").map(|s| s.to_string()));

    let h1_selector = Selector::parse("h1").unwrap();
    let h1_count = document.select(&h1_selector).count();

    let link_selector = Selector::parse("a[href]").unwrap();
    let mut internal_links = 0;
    let mut external_links = 0;
    
    let base_domain = domain.replace("https://", "").replace("http://", "").replace("www.", "");
    
    for link in document.select(&link_selector) {
        if let Some(href) = link.value().attr("href") {
            if href.starts_with("http") && !href.contains(&base_domain) {
                external_links += 1;
            } else if !href.starts_with("mailto:") && !href.starts_with("tel:") {
                internal_links += 1;
            }
        }
    }

    let ga_regex = Regex::new(r#"gtag\(['"]config['"],\s*['"]G-[A-Z0-9]+['"]"#).unwrap();
    let ua_regex = Regex::new(r#"gtag\(['"]config['"],\s*['"]UA-[0-9-]+['"]"#).unwrap();
    
    let has_google_analytics = ga_regex.is_match(&html_text) || ua_regex.is_match(&html_text);

    let mut score = 0;
    if title != "Missing" && title.len() >= 30 && title.len() <= 60 { score += 20; }
    else if title != "Missing" { score += 10; }
    
    if meta_description.is_some() { score += 20; }
    if h1_count == 1 { score += 20; }
    else if h1_count > 1 { score += 10; }
    
    if load_time_ms < 1000 { score += 20; }
    else if load_time_ms < 3000 { score += 10; }
    
    if has_google_analytics { score += 20; }

    Ok(SeoAnalysisResult {
        domain: domain.to_string(),
        title,
        meta_description,
        h1_count,
        internal_links,
        external_links,
        load_time_ms,
        has_google_analytics,
        seo_score: score,
    })
}
