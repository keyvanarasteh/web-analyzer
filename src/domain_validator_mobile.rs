use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub domain: String,
    pub valid: bool,
    pub skip_reason: Option<String>,
    pub dns_valid: bool,
    pub http_valid: bool,
    pub ssl_valid: bool,
    pub dns_info: Option<DnsValidation>,
    pub http_info: Option<HttpValidation>,
    pub ssl_info: Option<SslValidation>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsValidation {
    pub ip_addresses: Vec<String>,
    pub mx_exists: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpValidation {
    pub http_reachable: bool,
    pub https_reachable: bool,
    pub http_status: Option<u16>,
    pub https_status: Option<u16>,
    pub redirects_to_https: bool,
    pub response_time_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslValidation {
    pub ssl_available: bool,
    pub protocol_version: String,
    pub cipher_suite: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStats {
    pub total: usize,
    pub valid: usize,
    pub invalid: usize,
    pub skipped: usize,
    pub dns_failed: usize,
    pub http_failed: usize,
    pub ssl_failed: usize,
    pub success_rate: f64,
    pub processing_time_secs: f64,
    pub domains_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkValidationResult {
    pub stats: ValidationStats,
    pub valid_domains: Vec<String>,
    pub results: Vec<ValidationResult>,
}

use hickory_resolver::config::*;
use hickory_resolver::AsyncResolver;
use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

pub async fn validate_domain(domain: &str) -> ValidationResult {
    let mut result = ValidationResult {
        domain: domain.to_string(),
        valid: false,
        skip_reason: None,
        dns_valid: false,
        http_valid: false,
        ssl_valid: false,
        dns_info: None,
        http_info: None,
        ssl_info: None,
        errors: vec![],
    };

    // 1. DNS Check
    let mut dns_info = DnsValidation {
        ip_addresses: vec![],
        mx_exists: false,
    };
    
    let resolver = AsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    
    if let Ok(response) = resolver.ipv4_lookup(domain).await {
        for ip in response.iter() {
            dns_info.ip_addresses.push(ip.to_string());
        }
    }
    
    if let Ok(response) = resolver.ipv6_lookup(domain).await {
        for ip in response.iter() {
            dns_info.ip_addresses.push(ip.to_string());
        }
    }
    
    if let Ok(response) = resolver.mx_lookup(domain).await {
        dns_info.mx_exists = response.iter().next().is_some();
    }
    
    result.dns_valid = !dns_info.ip_addresses.is_empty();
    result.dns_info = Some(dns_info);

    if !result.dns_valid {
        result.errors.push("DNS Resolution failed. No A/AAAA records.".into());
        return result; // Fast omit
    }

    // 2. HTTP/HTTPS Check
    let start_http = Instant::now();
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .unwrap_or_else(|_| Client::new());

    let mut http_info = HttpValidation {
        http_reachable: false,
        https_reachable: false,
        http_status: None,
        https_status: None,
        redirects_to_https: false,
        response_time_ms: 0,
    };

    if let Ok(resp) = client.get(&format!("http://{}", domain)).send().await {
        http_info.http_reachable = true;
        http_info.http_status = Some(resp.status().as_u16());
        if resp.url().scheme() == "https" {
            http_info.redirects_to_https = true;
        }
    }

    if let Ok(resp) = client.get(&format!("https://{}", domain)).send().await {
        http_info.https_reachable = true;
        http_info.https_status = Some(resp.status().as_u16());
    }

    http_info.response_time_ms = start_http.elapsed().as_millis();
    result.http_valid = http_info.http_reachable || http_info.https_reachable;
    
    if !result.http_valid {
        result.errors.push("Host is unreachable via HTTP/HTTPS.".into());
    }
    
    result.http_info = Some(http_info.clone());

    // 3. SSL Check Extrapolation (via Reqwest connection success assuming certs are valid)
    // Detailed parsing requires x509-parser over pure TCP, but basic validation is supported natively here.
    let ssl_client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| Client::new());

    if let Ok(_) = ssl_client.get(&format!("https://{}", domain)).send().await {
        result.ssl_valid = true;
        result.ssl_info = Some(SslValidation {
            ssl_available: true,
            protocol_version: "TLS".into(), // Generalized for mobile stub
            cipher_suite: "Standard".into(),
        });
    } else if http_info.https_reachable {
        result.errors.push("SSL Certificate is invalid or untrusted.".into());
    }

    result.valid = result.dns_valid && result.http_valid;
    result
}

pub async fn validate_domains_bulk(domains: &[String], max_concurrency: usize) -> BulkValidationResult {
    let start_time = Instant::now();
    let total = domains.len();
    
    let mut set = JoinSet::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrency));

    for d in domains {
        let domain = d.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        set.spawn(async move {
            let res = validate_domain(&domain).await;
            drop(permit);
            res
        });
    }

    let mut results = Vec::new();
    let mut valid_count = 0;
    let mut invalid_count = 0;
    let mut skipped_count = 0;
    let mut dns_failed = 0;
    let mut http_failed = 0;
    let mut ssl_failed = 0;
    let mut valid_domains = Vec::new();

    while let Some(res_ok) = set.join_next().await {
        if let Ok(res) = res_ok {
            if res.valid {
                valid_count += 1;
                valid_domains.push(res.domain.clone());
            } else if res.skip_reason.is_some() {
                skipped_count += 1;
            } else {
                invalid_count += 1;
                if !res.dns_valid { dns_failed += 1; }
                if !res.http_valid { http_failed += 1; }
                if !res.ssl_valid { ssl_failed += 1; }
            }
            results.push(res);
        }
    }

    let processing_time_secs = start_time.elapsed().as_secs_f64();
    let success_rate = if total > 0 { (valid_count as f64 / total as f64) * 100.0 } else { 0.0 };
    let domains_per_sec = if processing_time_secs > 0.0 { total as f64 / processing_time_secs } else { 0.0 };

    BulkValidationResult {
        stats: ValidationStats {
            total,
            valid: valid_count,
            invalid: invalid_count,
            skipped: skipped_count,
            dns_failed,
            http_failed,
            ssl_failed,
            success_rate,
            processing_time_secs,
            domains_per_sec,
        },
        valid_domains,
        results,
    }
}
