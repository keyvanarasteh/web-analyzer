use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialProfile {
    pub platform: String,
    pub username: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactSpyResult {
    pub domain: String,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub social_media: Vec<SocialProfile>,
    pub pages_scanned: usize,
}

pub async fn crawl_contacts(domain: &str, _max_pages: usize) -> Result<ContactSpyResult, Box<dyn std::error::Error + Send + Sync>> {
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
    let lower_html = html_content.to_lowercase();

    let mut emails = HashSet::new();
    let mut phones = HashSet::new();
    let mut social_media = Vec::new();

    let email_regex = Regex::new(r#"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#).unwrap();
    let phone_regex = Regex::new(r#"[\+]?[\d\s\-\(\)\.]{8,20}"#).unwrap();

    // Extract emails
    for mat in email_regex.find_iter(&html_content) {
        let email = mat.as_str().to_lowercase();
        if !email.contains("example.") && !email.contains("test@") && email.len() > 5 {
            emails.insert(email);
        }
    }

    // Extract basic phones (rough)
    for mat in phone_regex.find_iter(&html_content) {
        let phone = mat.as_str().trim().to_string();
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() >= 10 && digits.len() <= 15 {
            phones.insert(phone);
        }
    }

    // Social media
    let platforms = vec![
        ("Facebook", Regex::new(r#"facebook\.com/([^/\"'\?]+)"#).unwrap()),
        ("Twitter", Regex::new(r#"(twitter\.com|x\.com)/([^/\"'\?]+)"#).unwrap()),
        ("Instagram", Regex::new(r#"instagram\.com/([^/\"'\?]+)"#).unwrap()),
        ("LinkedIn", Regex::new(r#"linkedin\.com/(in|company)/([^/\"'\?]+)"#).unwrap()),
        ("YouTube", Regex::new(r#"youtube\.com/(channel/|user/|c/|@)([^/\"'\?]+)"#).unwrap()),
        ("GitHub", Regex::new(r#"github\.com/([^/\"'\?]+)"#).unwrap()),
    ];

    let mut seen_profiles = HashSet::new();
    for (platform, regex) in platforms {
        for caps in regex.captures_iter(&lower_html) {
            if let Some(user_match) = caps.get(caps.len() - 1) { // get the last capture group
                let username = user_match.as_str().to_string();
                let full_url = caps.get(0).unwrap().as_str().to_string();
                let profile_id = format!("{}:{}", platform, username);
                
                if seen_profiles.insert(profile_id) {
                    social_media.push(SocialProfile {
                        platform: platform.to_string(),
                        username,
                        url: format!("https://{}", full_url),
                    });
                }
            }
        }
    }

    Ok(ContactSpyResult {
        domain: domain.to_string(),
        emails: emails.into_iter().collect(),
        phones: phones.into_iter().collect(),
        social_media,
        pages_scanned: 1,
    })
}
