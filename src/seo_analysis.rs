use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Tracking tool detection patterns ────────────────────────────────────────

const TRACKING_TOOLS: &[(&str, &[&str])] = &[
    (
        "Google Tag Manager",
        &["googletagmanager.com/gtm.js", "dataLayer"],
    ),
    (
        "Google Ads",
        &["googleads.g.doubleclick.net", "googlesyndication.com"],
    ),
    ("Facebook Pixel", &["connect.facebook.net", "fbq("]),
    (
        "LinkedIn Insight",
        &["snap.licdn.com", "_linkedin_partner_id"],
    ),
    ("TikTok Pixel", &["analytics.tiktok.com", "ttq."]),
    ("Hotjar", &["static.hotjar.com", "hjid"]),
    ("Mixpanel", &["cdn.mxpnl.com", "mixpanel.init"]),
    ("Segment", &["cdn.segment.com", "analytics.load"]),
    ("Intercom", &["widget.intercom.io"]),
    ("Zendesk", &["static.zdassets.com"]),
    ("Crisp", &["client.crisp.chat"]),
];

/// SEO resources to check
const SEO_RESOURCES: &[&str] = &["robots.txt", "sitemap.xml", "humans.txt", "ads.txt"];

// ── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeoAnalysisResult {
    pub domain: String,
    pub basic_seo: BasicSeoResult,
    pub content_analysis: ContentAnalysisResult,
    pub technical_seo: TechnicalSeoResult,
    pub social_media: SocialMediaResult,
    pub analytics: HashMap<String, String>,
    pub performance: PerformanceResult,
    pub mobile_accessibility: MobileAccessibilityResult,
    pub seo_resources: HashMap<String, String>,
    pub schema_markup: SchemaMarkupResult,
    pub link_analysis: LinkAnalysisResult,
    pub image_seo: ImageSeoResult,
    pub page_speed_factors: PageSpeedResult,
    pub seo_score: SeoScoreResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TitleAnalysis {
    pub text: String,
    pub length: usize,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaDescAnalysis {
    pub text: String,
    pub length: usize,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicSeoResult {
    pub title: TitleAnalysis,
    pub meta_description: MetaDescAnalysis,
    pub meta_keywords: String,
    pub canonical_url: String,
    pub meta_robots: String,
    pub viewport: String,
    pub language: String,
    pub charset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadingInfo {
    pub count: usize,
    pub texts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeywordInfo {
    pub word: String,
    pub count: usize,
    pub density: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAnalysisResult {
    pub headings: HashMap<String, HeadingInfo>,
    pub heading_issues: Vec<String>,
    pub word_count: usize,
    pub word_count_status: String,
    pub paragraphs: usize,
    pub text_to_html_ratio: String,
    pub top_keywords: Vec<KeywordInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnicalSeoResult {
    pub page_size_bytes: usize,
    pub http_status: u16,
    pub redirects: usize,
    pub internal_links: usize,
    pub external_links: usize,
    pub structured_data_count: usize,
    pub has_breadcrumbs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialMediaResult {
    pub open_graph: HashMap<String, String>,
    pub twitter_cards: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceResult {
    pub load_time_secs: f64,
    pub load_time_status: String,
    pub content_size_kb: f64,
    pub compression: String,
    pub server: String,
    pub cache_control: String,
    pub etag: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AltAttributeResult {
    pub total_images: usize,
    pub images_with_alt: usize,
    pub missing_alt: usize,
    pub alt_coverage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileAccessibilityResult {
    pub viewport_present: bool,
    pub mobile_friendly: bool,
    pub alt_attributes: AltAttributeResult,
    pub aria_labels: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaMarkupResult {
    pub json_ld_count: usize,
    pub json_ld_types: Vec<String>,
    pub microdata_items: usize,
    pub total_structured_data: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkAnalysisResult {
    pub total_links: usize,
    pub internal_links: usize,
    pub external_links: usize,
    pub nofollow_links: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSeoResult {
    pub total_images: usize,
    pub lazy_loaded: usize,
    pub with_alt_text: usize,
    pub with_title: usize,
    pub optimization_score: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageSpeedResult {
    pub css_files: usize,
    pub js_files: usize,
    pub inline_styles: usize,
    pub inline_scripts: usize,
    pub compression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeoScoreResult {
    pub score: u32,
    pub max_score: u32,
    pub percentage: String,
    pub grade: String,
}

// ── Main function ───────────────────────────────────────────────────────────

pub async fn analyze_advanced_seo(
    domain: &str,
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<SeoAnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
    let url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "SEO Analysis".into(), percentage: 5.0, message: "Fetching homepage HTML...".into(), status: "Info".into() }).await; }

    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;

    let start = Instant::now();
    let resp = client.get(&url).send().await?;
    let load_time = start.elapsed().as_secs_f64();

    let status_code = resp.status().as_u16();
    let redirects = resp.url().to_string() != url; // simplified
    let headers = resp.headers().clone();
    let content_bytes = resp.bytes().await?;
    let content_size = content_bytes.len();
    let html_text = String::from_utf8_lossy(&content_bytes).to_string();
    let base_domain = domain
        .replace("https://", "")
        .replace("http://", "")
        .replace("www.", "");

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "SEO Analysis".into(), percentage: 20.0, message: "HTML fetched. Searching for SEO resources (sitemap, robots)...".into(), status: "Success".into() }).await; }

    // ── 8. SEO Resources (await before parsing HTML to avoid Send bounds) ──
    let seo_resources = check_seo_resources(&client, domain).await;

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "SEO Analysis".into(), percentage: 40.0, message: "Parsing HTML document...".into(), status: "Info".into() }).await; }

    let document = Html::parse_document(&html_text);

    // ── 1. Basic SEO ────────────────────────────────────────────────────
    let basic_seo = analyze_basic_seo(&document);

    // ── 2. Content Analysis ─────────────────────────────────────────────
    let content_analysis = analyze_content(&document);

    // ── 3. Technical SEO ────────────────────────────────────────────────
    let technical_seo = analyze_technical(
        &document,
        status_code,
        content_size,
        redirects as usize,
        &base_domain,
    );

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "SEO Analysis".into(), percentage: 60.0, message: "Analyzing Social Media & Analytics...".into(), status: "Info".into() }).await; }

    // ── 4. Social Media Tags ────────────────────────────────────────────
    let social_media = analyze_social_tags(&document);

    // ── 5. Analytics & Tracking ─────────────────────────────────────────
    let analytics = analyze_analytics(&html_text);

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "SEO Analysis".into(), percentage: 80.0, message: "Calculating SEO Core Web Factors...".into(), status: "Info".into() }).await; }

    // ── 6. Performance ──────────────────────────────────────────────────
    let performance = analyze_performance(&headers, load_time, content_size);

    // ── 7. Mobile & Accessibility ───────────────────────────────────────
    let mobile_accessibility = analyze_mobile(&document);

    // ── 9. Schema Markup ────────────────────────────────────────────────
    let schema_markup = analyze_schema(&document, &html_text);

    // ── 10. Link Analysis ───────────────────────────────────────────────
    let link_analysis = analyze_links(&document, &base_domain);

    // ── 11. Image SEO ───────────────────────────────────────────────────
    let image_seo = analyze_images(&document);

    // ── 12. Page Speed Factors ──────────────────────────────────────────
    let page_speed_factors = analyze_speed_factors(&document, &headers);

    // ── 13. SEO Score ───────────────────────────────────────────────────
    let seo_score = calculate_seo_score(
        &basic_seo,
        &content_analysis,
        &seo_resources,
        &schema_markup,
        &performance,
        &mobile_accessibility,
    );

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "SEO Analysis".into(), percentage: 100.0, message: "SEO Analysis successfully completed.".into(), status: "Success".into() }).await; }

    Ok(SeoAnalysisResult {
        domain: domain.to_string(),
        basic_seo,
        content_analysis,
        technical_seo,
        social_media,
        analytics,
        performance,
        mobile_accessibility,
        seo_resources,
        schema_markup,
        link_analysis,
        image_seo,
        page_speed_factors,
        seo_score,
    })
}

// ── 1. Basic SEO ────────────────────────────────────────────────────────────

fn analyze_basic_seo(doc: &Html) -> BasicSeoResult {
    let title_sel = Selector::parse("title").unwrap();
    let title_text = doc
        .select(&title_sel)
        .next()
        .map(|el| el.text().collect::<String>().trim().to_string())
        .unwrap_or_default();

    let title_len = title_text.len();
    let title_status = if title_text.is_empty() {
        "Missing"
    } else if title_len < 30 {
        "Too short"
    } else if title_len > 60 {
        "Too long"
    } else {
        "Good"
    };

    let desc = get_meta_content(doc, "name", "description");
    let desc_len = if desc == "Not Found" { 0 } else { desc.len() };
    let desc_status = if desc == "Not Found" {
        "Missing"
    } else if desc_len < 120 {
        "Too short"
    } else if desc_len > 160 {
        "Too long"
    } else {
        "Good"
    };

    BasicSeoResult {
        title: TitleAnalysis {
            text: if title_text.is_empty() {
                "Missing".into()
            } else {
                title_text
            },
            length: title_len,
            status: title_status.into(),
        },
        meta_description: MetaDescAnalysis {
            text: desc.clone(),
            length: desc_len,
            status: desc_status.into(),
        },
        meta_keywords: get_meta_content(doc, "name", "keywords"),
        canonical_url: get_link_href(doc, "canonical"),
        meta_robots: get_meta_content(doc, "name", "robots"),
        viewport: get_meta_content(doc, "name", "viewport"),
        language: doc
            .root_element()
            .value()
            .attr("lang")
            .unwrap_or("Not specified")
            .to_string(),
        charset: get_charset(doc),
    }
}

fn get_meta_content(doc: &Html, attr: &str, value: &str) -> String {
    let selector_str = format!("meta[{}=\"{}\"]", attr, value);
    if let Ok(sel) = Selector::parse(&selector_str) {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(content) = el.value().attr("content") {
                return content.trim().to_string();
            }
        }
    }
    "Not Found".into()
}

fn get_link_href(doc: &Html, rel: &str) -> String {
    let selector_str = format!("link[rel=\"{}\"]", rel);
    if let Ok(sel) = Selector::parse(&selector_str) {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(href) = el.value().attr("href") {
                return href.trim().to_string();
            }
        }
    }
    "Not Found".into()
}

fn get_charset(doc: &Html) -> String {
    if let Ok(sel) = Selector::parse("meta[charset]") {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(cs) = el.value().attr("charset") {
                return cs.to_string();
            }
        }
    }
    if let Ok(sel) = Selector::parse("meta[http-equiv=\"Content-Type\"]") {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(content) = el.value().attr("content") {
                if let Some(cs) = Regex::new(r"charset=([^;]+)")
                    .ok()
                    .and_then(|r| r.captures(content))
                {
                    return cs.get(1).unwrap().as_str().to_string();
                }
            }
        }
    }
    "Unknown".into()
}

// ── 2. Content Analysis ─────────────────────────────────────────────────────

fn analyze_content(doc: &Html) -> ContentAnalysisResult {
    let mut headings = HashMap::new();
    let mut hierarchy: Vec<(u8, String)> = Vec::new();

    let h_selectors = [
        (1u8, Selector::parse("h1").unwrap()),
        (2, Selector::parse("h2").unwrap()),
        (3, Selector::parse("h3").unwrap()),
        (4, Selector::parse("h4").unwrap()),
        (5, Selector::parse("h5").unwrap()),
        (6, Selector::parse("h6").unwrap()),
    ];

    for (i, sel) in &h_selectors {
        let elements: Vec<_> = doc.select(sel).collect();
        if !elements.is_empty() {
            let texts: Vec<String> = elements
                .iter()
                .take(3)
                .map(|e| {
                    let t = e.text().collect::<String>();
                    t.trim().chars().take(100).collect()
                })
                .collect();
            headings.insert(
                format!("H{}", i),
                HeadingInfo {
                    count: elements.len(),
                    texts,
                },
            );
            for e in &elements {
                let t = e.text().collect::<String>().trim().to_string();
                hierarchy.push((*i, t));
            }
        }
    }

    let heading_issues = check_heading_issues(&hierarchy);

    let text = doc.root_element().text().collect::<String>();
    let words: Vec<&str> = text.split_whitespace().collect();
    let word_count = words.len();

    let p_sel = Selector::parse("p").unwrap();
    let paragraphs = doc.select(&p_sel).count();

    let html_len = doc.html().len();
    let text_len = text.len();
    let ratio = if html_len > 0 {
        (text_len as f64 / html_len as f64) * 100.0
    } else {
        0.0
    };

    let top_keywords = analyze_keyword_density(&words);

    ContentAnalysisResult {
        headings,
        heading_issues,
        word_count,
        word_count_status: if word_count >= 300 {
            "Good"
        } else {
            "Too short"
        }
        .into(),
        paragraphs,
        text_to_html_ratio: format!("{:.1}%", ratio),
        top_keywords,
    }
}

fn check_heading_issues(hierarchy: &[(u8, String)]) -> Vec<String> {
    let mut issues = Vec::new();
    if hierarchy.is_empty() {
        issues.push("No headings found".into());
        return issues;
    }

    let h1_count = hierarchy.iter().filter(|(l, _)| *l == 1).count();
    if h1_count == 0 {
        issues.push("Missing H1 tag".into());
    } else if h1_count > 1 {
        issues.push(format!("Multiple H1 tags ({})", h1_count));
    }

    let mut prev = 0u8;
    for &(level, _) in hierarchy {
        if prev > 0 && level > prev + 1 {
            issues.push(format!(
                "Skipped heading level (from H{} to H{})",
                prev, level
            ));
        }
        prev = level;
    }
    issues
}

fn analyze_keyword_density(words: &[&str]) -> Vec<KeywordInfo> {
    let total = words.len();
    if total == 0 {
        return vec![];
    }

    let mut freq: HashMap<String, usize> = HashMap::new();
    for &w in words {
        let lower = w.to_lowercase();
        if lower.len() > 3 {
            *freq.entry(lower).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = freq.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    sorted
        .into_iter()
        .take(5)
        .map(|(word, count)| KeywordInfo {
            word,
            count,
            density: format!("{:.2}%", (count as f64 / total as f64) * 100.0),
        })
        .collect()
}

// ── 3. Technical SEO ────────────────────────────────────────────────────────

fn analyze_technical(
    doc: &Html,
    status: u16,
    size: usize,
    redirects: usize,
    base_domain: &str,
) -> TechnicalSeoResult {
    let link_sel = Selector::parse("a[href]").unwrap();
    let mut internal = 0;
    let mut external = 0;

    for el in doc.select(&link_sel) {
        if let Some(href) = el.value().attr("href") {
            if href.starts_with("http") && !href.contains(base_domain) {
                external += 1;
            } else if !href.starts_with("mailto:")
                && !href.starts_with("tel:")
                && !href.starts_with('#')
            {
                internal += 1;
            }
        }
    }

    let json_ld = Selector::parse("script[type=\"application/ld+json\"]")
        .ok()
        .map(|s| doc.select(&s).count())
        .unwrap_or(0);
    let microdata = Selector::parse("[itemtype]")
        .ok()
        .map(|s| doc.select(&s).count())
        .unwrap_or(0);

    let breadcrumb = Selector::parse("[typeof=\"BreadcrumbList\"]")
        .ok()
        .map(|s| doc.select(&s).next().is_some())
        .unwrap_or(false)
        || doc.html().to_lowercase().contains("breadcrumb");

    TechnicalSeoResult {
        page_size_bytes: size,
        http_status: status,
        redirects,
        internal_links: internal,
        external_links: external,
        structured_data_count: json_ld + microdata,
        has_breadcrumbs: breadcrumb,
    }
}

// ── 4. Social Media Tags ────────────────────────────────────────────────────

fn analyze_social_tags(doc: &Html) -> SocialMediaResult {
    let og_keys = [
        "og:title",
        "og:description",
        "og:image",
        "og:url",
        "og:type",
        "og:site_name",
    ];
    let tw_keys = [
        "twitter:card",
        "twitter:title",
        "twitter:description",
        "twitter:image",
        "twitter:site",
    ];

    let mut og = HashMap::new();
    for key in &og_keys {
        og.insert(key.to_string(), get_meta_content(doc, "property", key));
    }

    let mut tw = HashMap::new();
    for key in &tw_keys {
        tw.insert(key.to_string(), get_meta_content(doc, "name", key));
    }

    SocialMediaResult {
        open_graph: og,
        twitter_cards: tw,
    }
}

// ── 5. Analytics & Tracking ─────────────────────────────────────────────────

fn analyze_analytics(html: &str) -> HashMap<String, String> {
    let mut results = HashMap::new();

    // Google Analytics
    let has_ga4 = Regex::new(r#"gtag\(['"]config['"],\s*['"]G-[A-Z0-9]+['"]\)"#)
        .ok()
        .map(|r| r.is_match(html))
        .unwrap_or(false);
    let has_ua = Regex::new(r#"gtag\(['"]config['"],\s*['"]UA-[0-9-]+['"]\)"#)
        .ok()
        .map(|r| r.is_match(html))
        .unwrap_or(false);
    results.insert(
        "Google Analytics GA4".into(),
        if has_ga4 { "Found" } else { "Not Found" }.into(),
    );
    results.insert(
        "Google Analytics UA".into(),
        if has_ua { "Found" } else { "Not Found" }.into(),
    );

    // Other tracking tools
    let lower = html.to_lowercase();
    for &(name, patterns) in TRACKING_TOOLS {
        let found = patterns.iter().any(|p| lower.contains(&p.to_lowercase()));
        results.insert(
            name.to_string(),
            if found { "Found" } else { "Not Found" }.into(),
        );
    }

    results
}

// ── 6. Performance ──────────────────────────────────────────────────────────

fn analyze_performance(
    headers: &reqwest::header::HeaderMap,
    load_time: f64,
    size: usize,
) -> PerformanceResult {
    let status = if load_time < 1.0 {
        "Excellent"
    } else if load_time < 3.0 {
        "Good"
    } else {
        "Poor"
    };

    PerformanceResult {
        load_time_secs: (load_time * 100.0).round() / 100.0,
        load_time_status: status.into(),
        content_size_kb: (size as f64 / 1024.0 * 100.0).round() / 100.0,
        compression: headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("None")
            .into(),
        server: headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("Unknown")
            .into(),
        cache_control: headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("Not Set")
            .into(),
        etag: headers.contains_key("etag"),
    }
}

// ── 7. Mobile & Accessibility ───────────────────────────────────────────────

fn analyze_mobile(doc: &Html) -> MobileAccessibilityResult {
    let viewport_content = get_meta_content(doc, "name", "viewport");
    let has_viewport = viewport_content != "Not Found";
    let mobile_friendly = viewport_content.contains("width=device-width");

    let img_sel = Selector::parse("img").unwrap();
    let images: Vec<_> = doc.select(&img_sel).collect();
    let total = images.len();
    let with_alt = images
        .iter()
        .filter(|i| i.value().attr("alt").is_some())
        .count();

    let aria_sel = Selector::parse("[aria-label]").unwrap();
    let aria_count = doc.select(&aria_sel).count();

    MobileAccessibilityResult {
        viewport_present: has_viewport,
        mobile_friendly,
        alt_attributes: AltAttributeResult {
            total_images: total,
            images_with_alt: with_alt,
            missing_alt: total - with_alt,
            alt_coverage: if total > 0 {
                format!("{:.1}%", (with_alt as f64 / total as f64) * 100.0)
            } else {
                "0%".into()
            },
        },
        aria_labels: aria_count,
    }
}

// ── 8. SEO Resources ────────────────────────────────────────────────────────

async fn check_seo_resources(client: &Client, domain: &str) -> HashMap<String, String> {
    let mut results = HashMap::new();
    for &file in SEO_RESOURCES {
        let url = format!("https://{}/{}", domain, file);
        let found = match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => "Found",
            _ => "Not Found",
        };
        results.insert(file.to_string(), found.into());
    }
    results
}

// ── 9. Schema Markup ────────────────────────────────────────────────────────

fn analyze_schema(doc: &Html, html: &str) -> SchemaMarkupResult {
    let json_ld_sel = Selector::parse("script[type=\"application/ld+json\"]").unwrap();
    let json_lds: Vec<_> = doc.select(&json_ld_sel).collect();
    let json_ld_count = json_lds.len();

    let mut types = Vec::new();
    for script in &json_lds {
        let text = script.text().collect::<String>();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
            extract_types(&val, &mut types);
        }
    }

    let microdata = Selector::parse("[itemtype]")
        .ok()
        .map(|s| doc.select(&s).count())
        .unwrap_or(0);

    // Also check for inline JSON-LD in raw HTML (in case scraper misses it)
    let additional = Regex::new(r#""@type"\s*:\s*"([^"]+)""#)
        .ok()
        .map(|r| {
            r.captures_iter(html)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    for t in additional {
        if !types.contains(&t) {
            types.push(t);
        }
    }

    SchemaMarkupResult {
        json_ld_count,
        json_ld_types: types,
        microdata_items: microdata,
        total_structured_data: json_ld_count + microdata,
    }
}

fn extract_types(val: &serde_json::Value, types: &mut Vec<String>) {
    match val {
        serde_json::Value::Object(map) => {
            if let Some(t) = map.get("@type").and_then(|v| v.as_str()) {
                types.push(t.to_string());
            }
            for (_, v) in map {
                extract_types(v, types);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_types(v, types);
            }
        }
        _ => {}
    }
}

// ── 10. Link Analysis ───────────────────────────────────────────────────────

fn analyze_links(doc: &Html, base_domain: &str) -> LinkAnalysisResult {
    let link_sel = Selector::parse("a[href]").unwrap();
    let mut internal = 0;
    let mut external = 0;
    let mut nofollow = 0;
    let mut total = 0;

    for el in doc.select(&link_sel) {
        total += 1;
        if let Some(href) = el.value().attr("href") {
            if href.starts_with("http") && !href.contains(base_domain) {
                external += 1;
            } else if !href.starts_with("mailto:")
                && !href.starts_with("tel:")
                && !href.starts_with('#')
            {
                internal += 1;
            }
        }
        if let Some(rel) = el.value().attr("rel") {
            if rel.contains("nofollow") {
                nofollow += 1;
            }
        }
    }

    LinkAnalysisResult {
        total_links: total,
        internal_links: internal,
        external_links: external,
        nofollow_links: nofollow,
    }
}

// ── 11. Image SEO ───────────────────────────────────────────────────────────

fn analyze_images(doc: &Html) -> ImageSeoResult {
    let img_sel = Selector::parse("img").unwrap();
    let images: Vec<_> = doc.select(&img_sel).collect();
    let total = images.len();
    let lazy = images
        .iter()
        .filter(|i| i.value().attr("loading") == Some("lazy"))
        .count();
    let alt = images
        .iter()
        .filter(|i| i.value().attr("alt").is_some())
        .count();
    let title = images
        .iter()
        .filter(|i| i.value().attr("title").is_some())
        .count();

    let opt_score = if total > 0 {
        format!("{:.1}%", ((lazy + alt) as f64 / (total * 2) as f64) * 100.0)
    } else {
        "0%".into()
    };

    ImageSeoResult {
        total_images: total,
        lazy_loaded: lazy,
        with_alt_text: alt,
        with_title: title,
        optimization_score: opt_score,
    }
}

// ── 12. Page Speed Factors ──────────────────────────────────────────────────

fn analyze_speed_factors(doc: &Html, headers: &reqwest::header::HeaderMap) -> PageSpeedResult {
    let css_sel = Selector::parse("link[rel=\"stylesheet\"]").unwrap();
    let js_sel = Selector::parse("script[src]").unwrap();
    let style_sel = Selector::parse("style").unwrap();
    let inline_js_sel = Selector::parse("script:not([src])").unwrap();

    PageSpeedResult {
        css_files: doc.select(&css_sel).count(),
        js_files: doc.select(&js_sel).count(),
        inline_styles: doc.select(&style_sel).count(),
        inline_scripts: doc.select(&inline_js_sel).count(),
        compression: headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("None")
            .into(),
    }
}

// ── 13. SEO Score ───────────────────────────────────────────────────────────

fn calculate_seo_score(
    basic: &BasicSeoResult,
    content: &ContentAnalysisResult,
    resources: &HashMap<String, String>,
    schema: &SchemaMarkupResult,
    perf: &PerformanceResult,
    mobile: &MobileAccessibilityResult,
) -> SeoScoreResult {
    let mut score: u32 = 0;

    // Basic SEO (30 pts)
    if basic.title.status == "Good" {
        score += 10;
    }
    if basic.meta_description.status == "Good" {
        score += 10;
    }
    if basic.canonical_url != "Not Found" {
        score += 5;
    }
    if basic.viewport != "Not Found" {
        score += 5;
    }

    // Content (20 pts)
    if content.word_count_status == "Good" {
        score += 10;
    }
    if content.headings.contains_key("H1") {
        score += 10;
    }

    // Technical (20 pts)
    if resources.get("robots.txt").map(|s| s.as_str()) == Some("Found") {
        score += 5;
    }
    if resources.get("sitemap.xml").map(|s| s.as_str()) == Some("Found") {
        score += 5;
    }
    if schema.total_structured_data > 0 {
        score += 10;
    }

    // Performance (15 pts)
    match perf.load_time_status.as_str() {
        "Excellent" | "Good" => score += 15,
        _ => {}
    }

    // Security (10 pts) — counted from headers presence (simplified)
    score += 5; // base

    // Mobile (5 pts)
    if mobile.mobile_friendly {
        score += 5;
    }

    let max_score = 100u32;
    let pct = (score as f64 / max_score as f64) * 100.0;
    let grade = if pct >= 90.0 {
        "A+"
    } else if pct >= 80.0 {
        "A"
    } else if pct >= 70.0 {
        "B"
    } else if pct >= 60.0 {
        "C"
    } else if pct >= 50.0 {
        "D"
    } else {
        "F"
    };

    SeoScoreResult {
        score,
        max_score,
        percentage: format!("{:.1}%", pct),
        grade: grade.into(),
    }
}
