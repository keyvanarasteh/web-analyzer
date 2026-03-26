use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;

// ── Vulnerable Service Database (36 services) ───────────────────────────────

struct VulnService {
    name: &'static str,
    cname_pattern: &'static str,
    error_pattern: &'static str,
    additional: &'static str,
}

const VULNERABLE_SERVICES: &[VulnService] = &[
    VulnService {
        name: "AWS S3 Bucket",
        cname_pattern: "s3.amazonaws.com",
        error_pattern: "NoSuchBucket",
        additional: "The specified bucket does not exist",
    },
    VulnService {
        name: "AWS CloudFront",
        cname_pattern: "cloudfront.net",
        error_pattern: "The request could not be satisfied",
        additional: "Bad request",
    },
    VulnService {
        name: "GitHub Pages",
        cname_pattern: "github.io",
        error_pattern: "There isn't a GitHub Pages site here",
        additional: "404: Not Found",
    },
    VulnService {
        name: "Heroku",
        cname_pattern: "herokuapp.com",
        error_pattern: "No such app",
        additional: "heroku",
    },
    VulnService {
        name: "Vercel",
        cname_pattern: "vercel.app",
        error_pattern: "404: Not Found",
        additional: "The deployment could not be found",
    },
    VulnService {
        name: "Netlify",
        cname_pattern: "netlify.app",
        error_pattern: "Not found",
        additional: "netlify",
    },
    VulnService {
        name: "Azure App Service",
        cname_pattern: "azurewebsites.net",
        error_pattern: "Microsoft Azure App Service",
        additional: "404 Not Found",
    },
    VulnService {
        name: "Azure TrafficManager",
        cname_pattern: "trafficmanager.net",
        error_pattern: "Page not found",
        additional: "Not found",
    },
    VulnService {
        name: "Zendesk",
        cname_pattern: "zendesk.com",
        error_pattern: "Help Center Closed",
        additional: "Zendesk",
    },
    VulnService {
        name: "Shopify",
        cname_pattern: "myshopify.com",
        error_pattern: "Sorry, this shop is currently unavailable",
        additional: "Shopify",
    },
    VulnService {
        name: "Fastly",
        cname_pattern: "fastly.net",
        error_pattern: "Fastly error: unknown domain",
        additional: "Fastly",
    },
    VulnService {
        name: "Pantheon",
        cname_pattern: "pantheonsite.io",
        error_pattern: "The gods are wise",
        additional: "404 Not Found",
    },
    VulnService {
        name: "Tumblr",
        cname_pattern: "tumblr.com",
        error_pattern: "There's nothing here",
        additional: "Tumblr",
    },
    VulnService {
        name: "WordPress",
        cname_pattern: "wordpress.com",
        error_pattern: "Do you want to register",
        additional: "WordPress",
    },
    VulnService {
        name: "Acquia",
        cname_pattern: "acquia-sites.com",
        error_pattern: "No site found",
        additional: "The requested URL was not found",
    },
    VulnService {
        name: "Ghost",
        cname_pattern: "ghost.io",
        error_pattern: "The thing you were looking for is no longer here",
        additional: "Ghost",
    },
    VulnService {
        name: "Cargo",
        cname_pattern: "cargocollective.com",
        error_pattern: "404 Not Found",
        additional: "Cargo",
    },
    VulnService {
        name: "Webflow",
        cname_pattern: "webflow.io",
        error_pattern: "The page you are looking for doesn't exist",
        additional: "Webflow",
    },
    VulnService {
        name: "Surge.sh",
        cname_pattern: "surge.sh",
        error_pattern: "404 Not Found",
        additional: "Surge",
    },
    VulnService {
        name: "Squarespace",
        cname_pattern: "squarespace.com",
        error_pattern: "Website Expired",
        additional: "Squarespace",
    },
    VulnService {
        name: "Fly.io",
        cname_pattern: "fly.dev",
        error_pattern: "404 Not Found",
        additional: "Fly.io",
    },
    VulnService {
        name: "Brightcove",
        cname_pattern: "bcvp0rtal.com",
        error_pattern: "Brightcove Error",
        additional: "Brightcove",
    },
    VulnService {
        name: "Unbounce",
        cname_pattern: "unbounce.com",
        error_pattern: "The requested URL was not found",
        additional: "Unbounce",
    },
    VulnService {
        name: "Strikingly",
        cname_pattern: "strikinglydns.com",
        error_pattern: "404 Not Found",
        additional: "Strikingly",
    },
    VulnService {
        name: "UptimeRobot",
        cname_pattern: "stats.uptimerobot.com",
        error_pattern: "404 Not Found",
        additional: "UptimeRobot",
    },
    VulnService {
        name: "UserVoice",
        cname_pattern: "uservoice.com",
        error_pattern: "This UserVoice is currently being set up",
        additional: "UserVoice",
    },
    VulnService {
        name: "Pingdom",
        cname_pattern: "stats.pingdom.com",
        error_pattern: "404 Not Found",
        additional: "Pingdom",
    },
    VulnService {
        name: "Desk",
        cname_pattern: "desk.com",
        error_pattern: "Please try again",
        additional: "Desk",
    },
    VulnService {
        name: "Tilda",
        cname_pattern: "tilda.ws",
        error_pattern: "404 Not Found",
        additional: "Tilda",
    },
    VulnService {
        name: "Helpjuice",
        cname_pattern: "helpjuice.com",
        error_pattern: "404 Not Found",
        additional: "Helpjuice",
    },
    VulnService {
        name: "HelpScout",
        cname_pattern: "helpscoutdocs.com",
        error_pattern: "No settings were found",
        additional: "HelpScout",
    },
    VulnService {
        name: "Campaign Monitor",
        cname_pattern: "createsend.com",
        error_pattern: "404 Not Found",
        additional: "Campaign Monitor",
    },
    VulnService {
        name: "Digital Ocean",
        cname_pattern: "digitalocean.app",
        error_pattern: "404 Not Found",
        additional: "Digital Ocean",
    },
    VulnService {
        name: "AWS Elastic Beanstalk",
        cname_pattern: "elasticbeanstalk.com",
        error_pattern: "404 Not Found",
        additional: "Elastic Beanstalk",
    },
    VulnService {
        name: "Readthedocs",
        cname_pattern: "readthedocs.io",
        error_pattern: "Not Found",
        additional: "readthedocs",
    },
    VulnService {
        name: "Firebase",
        cname_pattern: "firebaseapp.com",
        error_pattern: "404 Not Found",
        additional: "Firebase",
    },
];

// ── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCheckResult {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub has_valid_dns: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverVulnerability {
    pub subdomain: String,
    pub service: String,
    pub vulnerability_type: String,
    pub cname: Option<String>,
    pub confidence: String,
    pub description: String,
    pub exploitation_difficulty: String,
    pub mitigation: String,
    pub dns_info: DnsCheckResult,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub subdomains_scanned: usize,
    pub vulnerable_count: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub scan_time_secs: f64,
    pub services_checked: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverResult {
    pub domain: String,
    pub statistics: ScanStatistics,
    pub vulnerable: Vec<TakeoverVulnerability>,
}

// ── Main Function ───────────────────────────────────────────────────────────

pub async fn check_subdomain_takeover(
    domain: &str,
    subdomains: &[String],
) -> Result<TakeoverResult, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;

    let start = std::time::Instant::now();
    let mut vulnerable = Vec::new();

    for sub in subdomains {
        if let Some(vuln) = check_single_subdomain(&client, sub).await {
            vulnerable.push(vuln);
        }
    }

    // Sort by confidence: High → Medium → Low
    vulnerable.sort_by(|a, b| {
        let order = |c: &str| -> u8 {
            match c {
                "High" => 0,
                "Medium" => 1,
                _ => 2,
            }
        };
        order(&a.confidence).cmp(&order(&b.confidence))
    });

    let high = vulnerable.iter().filter(|v| v.confidence == "High").count();
    let medium = vulnerable
        .iter()
        .filter(|v| v.confidence == "Medium")
        .count();
    let low = vulnerable.iter().filter(|v| v.confidence == "Low").count();

    Ok(TakeoverResult {
        domain: domain.to_string(),
        statistics: ScanStatistics {
            subdomains_scanned: subdomains.len(),
            vulnerable_count: vulnerable.len(),
            high_confidence: high,
            medium_confidence: medium,
            low_confidence: low,
            scan_time_secs: start.elapsed().as_secs_f64(),
            services_checked: VULNERABLE_SERVICES.len(),
        },
        vulnerable,
    })
}

// ── Per-Subdomain Check ─────────────────────────────────────────────────────

async fn check_single_subdomain(client: &Client, subdomain: &str) -> Option<TakeoverVulnerability> {
    // 1. DNS configuration
    let dns = check_dns(subdomain).await;

    // 2. HTTP status + body
    let (http_status, body) = fetch_http(client, subdomain).await;

    let body_lower = body.to_lowercase();

    // ── Case 1: CNAME matches a service AND body contains error fingerprint ──
    for cname in &dns.cname_records {
        let cname_lower = cname.to_lowercase();
        for svc in VULNERABLE_SERVICES {
            if cname_lower.contains(svc.cname_pattern) {
                let has_error = body_lower.contains(&svc.error_pattern.to_lowercase())
                    || body_lower.contains(&svc.additional.to_lowercase());

                if has_error {
                    return Some(TakeoverVulnerability {
                        subdomain: subdomain.to_string(),
                        service: svc.name.to_string(),
                        vulnerability_type: "CNAME Error Pattern".into(),
                        cname: Some(cname.clone()),
                        confidence: "High".into(),
                        description: format!("CNAME points to {} ({}) and returns error indicating resource doesn't exist.", svc.name, cname),
                        exploitation_difficulty: assess_difficulty("CNAME Error Pattern", svc.name),
                        mitigation: suggest_mitigation("CNAME Error Pattern", svc.name),
                        dns_info: dns,
                        http_status,
                    });
                }
            }
        }
    }

    // ── Case 2: Dangling CNAME (points somewhere that doesn't resolve) ──
    if !dns.cname_records.is_empty() && dns.a_records.is_empty() && http_status.is_none() {
        for cname in &dns.cname_records {
            let resolves = resolve_a(cname).await;
            if !resolves {
                // Try to identify the service
                let mut service = "Unknown".to_string();
                let cname_lower = cname.to_lowercase();
                for svc in VULNERABLE_SERVICES {
                    if cname_lower.contains(svc.cname_pattern) {
                        service = svc.name.to_string();
                        break;
                    }
                }
                let conf = if service != "Unknown" {
                    "High"
                } else {
                    "Medium"
                };

                return Some(TakeoverVulnerability {
                    subdomain: subdomain.to_string(),
                    service: service.clone(),
                    vulnerability_type: "Dangling CNAME".into(),
                    cname: Some(cname.clone()),
                    confidence: conf.into(),
                    description: format!(
                        "CNAME points to {} which doesn't resolve to an IP.",
                        cname
                    ),
                    exploitation_difficulty: assess_difficulty("Dangling CNAME", &service),
                    mitigation: suggest_mitigation("Dangling CNAME", &service),
                    dns_info: dns,
                    http_status,
                });
            }
        }
    }

    // ── Case 3: Dangling NS ──
    for ns in &dns.ns_records {
        let resolves = resolve_a(ns).await;
        if !resolves {
            return Some(TakeoverVulnerability {
                subdomain: subdomain.to_string(),
                service: "Unknown".into(),
                vulnerability_type: "Dangling NS".into(),
                cname: None,
                confidence: "Medium".into(),
                description: format!("NS record points to {} which doesn't resolve.", ns),
                exploitation_difficulty: "Medium".into(),
                mitigation: suggest_mitigation("Dangling NS", "Unknown"),
                dns_info: dns,
                http_status,
            });
        }
    }

    // ── Case 4: Valid DNS but third-party service returns error ──
    if dns.has_valid_dns {
        if let Some(status) = http_status {
            if [404, 500, 502, 503].contains(&status) {
                let dns_str = format!("{:?}", dns).to_lowercase();
                let third_party = ["aws", "amazon", "azure", "heroku", "github", "vercel"];
                let is_3rd = third_party.iter().any(|p| dns_str.contains(p));

                let conf = if is_3rd { "Medium" } else { "Low" };
                return Some(TakeoverVulnerability {
                    subdomain: subdomain.to_string(),
                    service: "Unknown".into(),
                    vulnerability_type: "Third-Party Service Error".into(),
                    cname: dns.cname_records.first().cloned(),
                    confidence: conf.into(),
                    description: format!("Valid DNS but returns HTTP {} error.", status),
                    exploitation_difficulty: "Hard".into(),
                    mitigation: suggest_mitigation("Third-Party Service Error", "Unknown"),
                    dns_info: dns,
                    http_status: Some(status),
                });
            }
        }
    }

    // ── Case 5: Missing SPF with MX records ──
    if !dns.mx_records.is_empty() {
        let has_spf = dns.txt_records.iter().any(|t| t.contains("v=spf1"));
        if !has_spf {
            return Some(TakeoverVulnerability {
                subdomain: subdomain.to_string(),
                service: "Unknown".into(),
                vulnerability_type: "Missing SPF".into(),
                cname: None,
                confidence: "Low".into(),
                description: "Has MX records but no SPF record — potential email spoofing risk."
                    .into(),
                exploitation_difficulty: "Medium".into(),
                mitigation: suggest_mitigation("Missing SPF", "Unknown"),
                dns_info: dns,
                http_status,
            });
        }
    }

    None
}

// ── DNS Checks ──────────────────────────────────────────────────────────────

async fn check_dns(subdomain: &str) -> DnsCheckResult {
    let (a, aaaa, cname, mx, txt, ns) = tokio::join!(
        dig_query(subdomain, "A"),
        dig_query(subdomain, "AAAA"),
        dig_query(subdomain, "CNAME"),
        dig_query(subdomain, "MX"),
        dig_query(subdomain, "TXT"),
        dig_query(subdomain, "NS"),
    );

    let has_valid = !a.is_empty()
        || !aaaa.is_empty()
        || !cname.is_empty()
        || !mx.is_empty()
        || !txt.is_empty()
        || !ns.is_empty();

    DnsCheckResult {
        a_records: a,
        aaaa_records: aaaa,
        cname_records: cname,
        mx_records: mx,
        txt_records: txt,
        ns_records: ns,
        has_valid_dns: has_valid,
    }
}

async fn dig_query(domain: &str, rtype: &str) -> Vec<String> {
    let output = match Command::new("dig")
        .args(["+short", rtype, domain])
        .output()
        .await
    {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn resolve_a(host: &str) -> bool {
    let output = match Command::new("dig")
        .args(["+short", "A", host])
        .output()
        .await
    {
        Ok(o) => o,
        Err(_) => return false,
    };
    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    !result.is_empty()
}

// ── HTTP Fetch ──────────────────────────────────────────────────────────────

async fn fetch_http(client: &Client, subdomain: &str) -> (Option<u16>, String) {
    // Try HTTPS first
    if let Ok(resp) = client.get(format!("https://{}", subdomain)).send().await {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return (Some(status), body.chars().take(1000).collect());
    }
    // Fallback to HTTP
    if let Ok(resp) = client.get(format!("http://{}", subdomain)).send().await {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return (Some(status), body.chars().take(1000).collect());
    }
    (None, String::new())
}

// ── Exploitation Difficulty ─────────────────────────────────────────────────

fn assess_difficulty(vuln_type: &str, service: &str) -> String {
    match vuln_type {
        "CNAME Error Pattern" => {
            let easy = ["GitHub Pages", "Heroku", "Vercel", "Netlify", "Surge.sh"];
            let medium = ["AWS S3 Bucket", "Firebase", "Ghost", "WordPress"];
            if easy.iter().any(|s| *s == service) {
                "Easy".into()
            } else if medium.iter().any(|s| *s == service) {
                "Medium".into()
            } else {
                "Hard".into()
            }
        }
        "Dangling CNAME" => {
            if service != "Unknown" {
                "Medium".into()
            } else {
                "Hard".into()
            }
        }
        "Dangling NS" => "Medium".into(),
        _ => "Hard".into(),
    }
}

// ── Mitigation Suggestions ──────────────────────────────────────────────────

fn suggest_mitigation(vuln_type: &str, service: &str) -> String {
    match vuln_type {
        "CNAME Error Pattern" => format!("Remove the CNAME record or reclaim the resource on {}. Ensure you've properly set up the service before pointing DNS records to it.", service),
        "Dangling CNAME" => "Remove the CNAME record pointing to a non-existent endpoint. If the service is still needed, recreate the resource at the target.".into(),
        "Dangling NS" => "Update NS records to point to valid nameservers. Remove delegations to nameservers that no longer exist.".into(),
        "Third-Party Service Error" => "Verify the resource exists on the target service. If no longer used, remove the DNS record.".into(),
        "Missing SPF" => "Add an SPF record to protect against email spoofing. Example: 'v=spf1 mx -all'".into(),
        _ => "Review DNS configuration and remove references to services or resources no longer in use.".into(),
    }
}

impl qicro_data_core::registry::Registrable for DnsCheckResult {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("DnsCheckResult", "dnscheckresult")
    }
}

impl qicro_data_core::registry::Registrable for TakeoverVulnerability {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("TakeoverVulnerability", "takeovervulnerability")
    }
}

impl qicro_data_core::registry::Registrable for ScanStatistics {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("ScanStatistics", "scanstatistics")
    }
}

impl qicro_data_core::registry::Registrable for TakeoverResult {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("TakeoverResult", "takeoverresult")
    }
}
