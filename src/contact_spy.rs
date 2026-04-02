use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

// ── Structs ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialProfile {
    pub platform: String,
    pub username: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactSpyResult {
    pub domain: String,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub social_media: Vec<SocialProfile>,
    pub social_media_by_platform: HashMap<String, Vec<SocialProfile>>,
    pub pages_scanned: usize,
    pub total_emails: usize,
    pub total_phones: usize,
    pub total_social_media: usize,
}

// ── Invalid social media usernames ──────────────────────────────────────────

const INVALID_USERNAMES: &[&str] = &[
    "share", "sharer", "intent", "oauth", "login", "register", "signup", "api", "www", "mobile",
    "m", "help", "support", "about", "privacy", "terms", "contact", "home", "index", "main",
    "page", "site", "web", "app", "download", "install", "get", "go", "redirect", "link", "url",
    "http", "https", "com", "org", "net", "plugins", "dialog", "p", "explore", "accounts",
];

// ── Skip extensions and directories ─────────────────────────────────────────

const SKIP_EXTENSIONS: &[&str] = &[
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".doc", ".mp4", ".css", ".js", ".svg", ".ico",
    ".woff", ".ttf",
];

const SKIP_DIRS: &[&str] = &[
    "/assets/",
    "/images/",
    "/css/",
    "/js/",
    "/fonts/",
    "/media/",
    "/wp-content/uploads/",
    "/static/",
];

// ── Email false positive filters ────────────────────────────────────────────

const EMAIL_SKIP_PATTERNS: &[&str] = &[
    "example.",
    "test@",
    "noreply@",
    "no-reply@",
    "admin@example",
    "user@example",
    "email@example",
    "name@example",
    ".jpg@",
    ".png@",
    "wixpress.",
    "sentry.",
    "webpack.",
];

// ── Phone false positive patterns (regex) ───────────────────────────────────

const PHONE_FALSE_POSITIVES: &[&str] = &[
    r"^(19|20)\d{6,8}$",                // Date patterns (1900-2099)
    r"^(\d)\1{6,}$",                    // Same digit repeated 7+ times
    r"^(123|456|789|987|654|321){2,}$", // Sequential numbers
];

// ── Main function ───────────────────────────────────────────────────────────

pub async fn crawl_contacts(
    domain: &str,
    max_pages: usize,
) -> Result<ContactSpyResult, Box<dyn std::error::Error + Send + Sync>> {
    let base_url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let clean_domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(domain);

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;

    let email_regex = Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap();
    let phone_regex = Regex::new(r"[\+]?[\d\s\-\(\)\.]{8,20}").unwrap();

    let social_patterns = build_social_patterns();
    let phone_fp_regexes: Vec<Regex> = PHONE_FALSE_POSITIVES
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    let mut all_emails: HashSet<String> = HashSet::new();
    let mut all_phones: HashSet<String> = HashSet::new();
    let mut all_social: Vec<SocialProfile> = Vec::new();
    let mut seen_profiles: HashSet<String> = HashSet::new();

    let mut visited: HashSet<String> = HashSet::new();
    let mut to_visit: Vec<String> = vec![base_url.clone()];

    // ── BFS Crawl ───────────────────────────────────────────────────────
    while let Some(current_url) = to_visit.pop() {
        if visited.len() >= max_pages {
            break;
        }
        if visited.contains(&current_url) {
            continue;
        }
        visited.insert(current_url.clone());

        let resp = match client.get(&current_url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let html = match resp.text().await {
            Ok(t) => t,
            Err(_) => continue,
        };
        let doc = Html::parse_document(&html);

        // Remove script/style content — extract clean text
        let text_sel = Selector::parse("body").unwrap();
        let link_sel = Selector::parse("a[href]").unwrap();

        // Collect clean text (excluding script/style)
        let mut clean_text = String::new();
        if let Some(body) = doc.select(&text_sel).next() {
            for node in body.text() {
                clean_text.push(' ');
                clean_text.push_str(node);
            }
        }

        // Collect all href values for social media extraction
        let mut all_hrefs = String::new();
        for el in doc.select(&link_sel) {
            if let Some(href) = el.value().attr("href") {
                all_hrefs.push(' ');
                all_hrefs.push_str(href);
            }
        }

        let full_text = format!("{} {}", clean_text, all_hrefs);

        // ── Extract emails ──────────────────────────────────────────────
        for mat in email_regex.find_iter(&full_text) {
            let email = mat.as_str().to_lowercase();
            if email.len() > 5
                && email.chars().filter(|c| *c == '@').count() == 1
                && !EMAIL_SKIP_PATTERNS.iter().any(|skip| email.contains(skip))
            {
                all_emails.insert(email);
            }
        }

        // ── Extract phones (from clean text only) ───────────────────────
        for mat in phone_regex.find_iter(&clean_text) {
            let raw = mat.as_str().trim();
            let digits: String = raw
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '+')
                .collect();
            let digits_only: String = digits.replace('+', "");

            if is_valid_phone(&digits_only, &phone_fp_regexes)
                && (digits.starts_with('+') || digits_only.len() >= 10) {
                    all_phones.insert(digits);
                }
        }

        // ── Extract social media ────────────────────────────────────────
        for (platform, regex) in &social_patterns {
            for caps in regex.captures_iter(&full_text) {
                let username = caps
                    .get(caps.len() - 1)
                    .or_else(|| caps.get(1))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                if username.is_empty() {
                    continue;
                }
                if !is_valid_social_username(&username, platform) {
                    continue;
                }

                let profile_id = format!("{}:{}", platform, username.to_lowercase());
                if !seen_profiles.insert(profile_id) {
                    continue;
                }

                let full_url = caps
                    .get(0)
                    .map(|m| {
                        let u = m.as_str().to_string();
                        if u.starts_with("http") {
                            u
                        } else {
                            format!("https://{}", u)
                        }
                    })
                    .unwrap_or_default();

                all_social.push(SocialProfile {
                    platform: platform.to_string(),
                    username,
                    url: full_url,
                    found_on: Some(current_url.clone()),
                });
            }
        }

        // ── Discover new links for crawling ─────────────────────────────
        if visited.len() < max_pages {
            for el in doc.select(&link_sel) {
                if let Some(href) = el.value().attr("href") {
                    if let Some(abs_url) = resolve_url(&base_url, href) {
                        if is_valid_crawl_url(&abs_url, clean_domain) && !visited.contains(&abs_url)
                        {
                            to_visit.push(abs_url);
                        }
                    }
                }
            }
        }
    }

    // ── Group social by platform ────────────────────────────────────────
    let mut by_platform: HashMap<String, Vec<SocialProfile>> = HashMap::new();
    for profile in &all_social {
        by_platform
            .entry(profile.platform.clone())
            .or_default()
            .push(profile.clone());
    }

    let total_emails = all_emails.len();
    let total_phones = all_phones.len();
    let total_social = all_social.len();

    Ok(ContactSpyResult {
        domain: clean_domain.to_string(),
        emails: all_emails.into_iter().collect(),
        phones: all_phones.into_iter().collect(),
        social_media: all_social,
        social_media_by_platform: by_platform,
        pages_scanned: visited.len(),
        total_emails,
        total_phones,
        total_social_media: total_social,
    })
}

// ── Social media patterns ───────────────────────────────────────────────────

fn build_social_patterns() -> Vec<(String, Regex)> {
    vec![
        (
            "Facebook".into(),
            Regex::new(r"(?i)facebook\.com/([a-zA-Z0-9._-]+)").unwrap(),
        ),
        (
            "Twitter".into(),
            Regex::new(r"(?i)(?:twitter\.com|x\.com)/([a-zA-Z0-9._-]+)")
                .unwrap(),
        ),
        (
            "Instagram".into(),
            Regex::new(r"(?i)instagram\.com/([a-zA-Z0-9._-]+)").unwrap(),
        ),
        (
            "LinkedIn".into(),
            Regex::new(r"(?i)linkedin\.com/(?:in|company)/([a-zA-Z0-9._-]+)").unwrap(),
        ),
        (
            "YouTube".into(),
            Regex::new(r"(?i)youtube\.com/(?:channel/|user/|c/|@)([a-zA-Z0-9._-]+)").unwrap(),
        ),
        (
            "GitHub".into(),
            Regex::new(r"(?i)github\.com/([a-zA-Z0-9._-]+)").unwrap(),
        ),
        (
            "TikTok".into(),
            Regex::new(r"(?i)tiktok\.com/@([a-zA-Z0-9._-]+)").unwrap(),
        ),
    ]
}

// ── Validation helpers ──────────────────────────────────────────────────────

fn is_valid_phone(digits: &str, fp_regexes: &[Regex]) -> bool {
    if digits.len() < 7 || digits.len() > 15 {
        return false;
    }
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if fp_regexes.iter().any(|rx| rx.is_match(digits)) {
        return false;
    }
    true
}

fn is_valid_social_username(username: &str, platform: &str) -> bool {
    if username.len() < 2 {
        return false;
    }
    if INVALID_USERNAMES.contains(&username.to_lowercase().as_str()) {
        return false;
    }

    // Platform-specific length limits
    match platform {
        "Twitter" => username.len() <= 15 && !username.starts_with('_'),
        "Instagram" => username.len() <= 30,
        "LinkedIn" => username.len() <= 100,
        "GitHub" => username.len() <= 39 && !username.starts_with('-'),
        "YouTube" => username.len() <= 100,
        "Facebook" => username.len() <= 50,
        "TikTok" => username.len() <= 24,
        _ => true,
    }
}

fn is_valid_crawl_url(url: &str, base_domain: &str) -> bool {
    let lower = url.to_lowercase();

    // Must contain the domain
    if !lower.contains(base_domain) {
        return false;
    }

    // Skip static assets
    if SKIP_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        return false;
    }
    if SKIP_DIRS.iter().any(|dir| lower.contains(dir)) {
        return false;
    }

    // Skip fragments and javascript
    if url.starts_with('#') || url.starts_with("javascript:") || url.starts_with("mailto:") {
        return false;
    }

    true
}

fn resolve_url(base: &str, href: &str) -> Option<String> {
    if href.starts_with("javascript:")
        || href.starts_with('#')
        || href.starts_with("mailto:")
        || href.starts_with("tel:")
    {
        return None;
    }
    if href.starts_with("//") {
        return Some(format!("https:{}", href));
    }
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    // Relative URL
    let base_trimmed = if let Some(idx) = base.rfind('/') {
        &base[..idx + 1]
    } else {
        base
    };
    Some(format!("{}{}", base_trimmed, href.trim_start_matches('/')))
}
