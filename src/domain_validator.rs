use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::Command;

// ── Constants ───────────────────────────────────────────────────────────────

const SKIP_PATTERNS: &[&str] = &[
    "stun.l.google.com", ".cloudapp.azure.com", "clients6.google.com",
    ".cdn.cloudflare.net", "rr1.sn-", "rr2.sn-", "rr3.sn-", "rr4.sn-", "rr5.sn-",
    "e-0014.e-msedge", "s-part-", ".t-msedge.net", "perimeterx.map",
    "i.ytimg.com", "analytics-alv.google.com", "signaler-pa.clients",
    "westus-0.in.applicationinsights",
];

const INTERNAL_PATTERNS: &[&str] = &[
    "localhost", "127.0.0.1", "0.0.0.0", "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
];

// ── Data Structures ─────────────────────────────────────────────────────────

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

// ── Shared Counters ─────────────────────────────────────────────────────────

struct AtomicStats {
    valid: AtomicUsize,
    invalid: AtomicUsize,
    skipped: AtomicUsize,
    dns_failed: AtomicUsize,
    http_failed: AtomicUsize,
    ssl_failed: AtomicUsize,
}

impl AtomicStats {
    fn new() -> Self {
        Self {
            valid: AtomicUsize::new(0), invalid: AtomicUsize::new(0),
            skipped: AtomicUsize::new(0), dns_failed: AtomicUsize::new(0),
            http_failed: AtomicUsize::new(0), ssl_failed: AtomicUsize::new(0),
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Validate a single domain comprehensively (DNS → HTTP → SSL)
pub async fn validate_domain(domain: &str) -> ValidationResult {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .unwrap_or_else(|_| Client::new());

    validate_single(&client, domain).await
}

/// Validate multiple domains in parallel with configurable concurrency
pub async fn validate_domains_bulk(
    domains: &[String],
    max_concurrency: usize,
) -> BulkValidationResult {
    let start = Instant::now();
    let total = domains.len();

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .redirect(reqwest::redirect::Policy::limited(5))
        .pool_max_idle_per_host(max_concurrency)
        .build()
        .unwrap_or_else(|_| Client::new());

    let stats = Arc::new(AtomicStats::new());
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrency));

    let mut handles = Vec::with_capacity(total);

    for domain in domains {
        let client = client.clone();
        let domain = domain.clone();
        let stats = Arc::clone(&stats);
        let sem = Arc::clone(&semaphore);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let result = validate_single(&client, &domain).await;

            // Update counters
            if result.skip_reason.is_some() {
                stats.skipped.fetch_add(1, Ordering::Relaxed);
            } else if result.valid {
                stats.valid.fetch_add(1, Ordering::Relaxed);
            } else {
                stats.invalid.fetch_add(1, Ordering::Relaxed);
                if !result.dns_valid { stats.dns_failed.fetch_add(1, Ordering::Relaxed); }
                if !result.http_valid && result.dns_valid { stats.http_failed.fetch_add(1, Ordering::Relaxed); }
                if !result.ssl_valid && result.dns_valid { stats.ssl_failed.fetch_add(1, Ordering::Relaxed); }
            }

            result
        }));
    }

    // Collect results
    let mut results = Vec::with_capacity(total);
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let valid_count = stats.valid.load(Ordering::Relaxed);

    let valid_domains: Vec<String> = results.iter()
        .filter(|r| r.valid)
        .map(|r| r.domain.clone())
        .collect();

    BulkValidationResult {
        stats: ValidationStats {
            total,
            valid: valid_count,
            invalid: stats.invalid.load(Ordering::Relaxed),
            skipped: stats.skipped.load(Ordering::Relaxed),
            dns_failed: stats.dns_failed.load(Ordering::Relaxed),
            http_failed: stats.http_failed.load(Ordering::Relaxed),
            ssl_failed: stats.ssl_failed.load(Ordering::Relaxed),
            success_rate: if total > 0 { (valid_count as f64 / total as f64) * 100.0 } else { 0.0 },
            processing_time_secs: elapsed,
            domains_per_sec: if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 },
        },
        valid_domains,
        results,
    }
}

// ── Single Domain Validation ────────────────────────────────────────────────

async fn validate_single(client: &Client, domain: &str) -> ValidationResult {
    let mut result = ValidationResult {
        domain: domain.to_string(),
        valid: false, skip_reason: None,
        dns_valid: false, http_valid: false, ssl_valid: false,
        dns_info: None, http_info: None, ssl_info: None,
        errors: vec![],
    };

    // 1. Skip check
    if let Some(reason) = should_skip(domain) {
        result.skip_reason = Some(reason);
        return result;
    }

    // 2. DNS validation
    match validate_dns(domain).await {
        Ok(dns) => {
            result.dns_valid = true;
            result.dns_info = Some(dns);
        }
        Err(e) => {
            result.errors.push(format!("DNS: {}", e));
            return result; // Skip HTTP/SSL if DNS fails
        }
    }

    // 3. HTTP validation
    match validate_http(client, domain).await {
        Ok(http) => {
            result.http_valid = http.http_reachable || http.https_reachable;
            if !result.http_valid {
                result.errors.push("HTTP: No HTTP/HTTPS connectivity".into());
            }
            result.http_info = Some(http);
        }
        Err(e) => {
            result.errors.push(format!("HTTP: {}", e));
        }
    }

    // 4. SSL validation
    match validate_ssl(domain).await {
        Ok(ssl) => {
            result.ssl_valid = ssl.ssl_available;
            result.ssl_info = Some(ssl);
        }
        Err(e) => {
            result.errors.push(format!("SSL: {}", e));
        }
    }

    // Overall: valid if DNS + HTTP pass
    result.valid = result.dns_valid && result.http_valid;
    result
}

// ── Skip Check ──────────────────────────────────────────────────────────────

fn should_skip(domain: &str) -> Option<String> {
    let lower = domain.to_lowercase();

    // Skip patterns
    for &pattern in SKIP_PATTERNS {
        if lower.contains(pattern) {
            return Some(format!("Matches skip pattern: {}", pattern));
        }
    }

    // IP address
    if domain.parse::<IpAddr>().is_ok() {
        return Some("IP address detected".into());
    }

    // Internal/localhost
    for &internal in INTERNAL_PATTERNS {
        if lower.contains(internal) {
            return Some("Internal/localhost domain".into());
        }
    }

    // Length
    if domain.len() < 4 || domain.len() > 253 {
        return Some("Invalid domain length".into());
    }

    // Must contain at least one dot
    if !domain.contains('.') {
        return Some("No TLD detected".into());
    }

    None
}

// ── DNS Validation ──────────────────────────────────────────────────────────

async fn validate_dns(domain: &str) -> Result<DnsValidation, String> {
    // Resolve A records via dig
    let a_output = Command::new("dig")
        .args(["+short", "A", domain])
        .output()
        .await
        .map_err(|e| format!("dig failed: {}", e))?;

    let a_records: Vec<String> = String::from_utf8_lossy(&a_output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.parse::<IpAddr>().is_ok())
        .collect();

    if a_records.is_empty() {
        return Err("No A records found (NXDOMAIN or empty)".into());
    }

    // Check MX records
    let mx_output = Command::new("dig")
        .args(["+short", "MX", domain])
        .output()
        .await
        .unwrap_or_else(|_| std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: vec![], stderr: vec![],
        });

    let mx_exists = !String::from_utf8_lossy(&mx_output.stdout).trim().is_empty();

    Ok(DnsValidation { ip_addresses: a_records, mx_exists })
}

// ── HTTP Validation ─────────────────────────────────────────────────────────

async fn validate_http(client: &Client, domain: &str) -> Result<HttpValidation, String> {
    let mut info = HttpValidation {
        http_reachable: false, https_reachable: false,
        http_status: None, https_status: None,
        redirects_to_https: false, response_time_ms: 0,
    };

    let start = Instant::now();

    // HTTPS first (more common)
    match client.head(format!("https://{}", domain)).send().await {
        Ok(resp) => {
            info.https_reachable = true;
            info.https_status = Some(resp.status().as_u16());
            info.response_time_ms = start.elapsed().as_millis();

            if resp.status().as_u16() < 500 {
                return Ok(info);
            }
        }
        Err(_) => {}
    }

    // HTTP fallback
    // Build a separate client that doesn't follow redirects for HTTP check
    let no_redirect_client = Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .unwrap_or_else(|_| Client::new());

    match no_redirect_client.head(format!("http://{}", domain)).send().await {
        Ok(resp) => {
            info.http_reachable = true;
            info.http_status = Some(resp.status().as_u16());

            // Check for HTTPS redirect
            let status = resp.status().as_u16();
            if [301, 302, 307, 308].contains(&status) {
                if let Some(location) = resp.headers().get("location") {
                    if let Ok(loc) = location.to_str() {
                        if loc.starts_with("https://") {
                            info.redirects_to_https = true;
                        }
                    }
                }
            }
        }
        Err(_) => {}
    }

    if info.response_time_ms == 0 {
        info.response_time_ms = start.elapsed().as_millis();
    }

    Ok(info)
}

// ── SSL Validation ──────────────────────────────────────────────────────────

async fn validate_ssl(domain: &str) -> Result<SslValidation, String> {
    let output = Command::new("openssl")
        .args([
            "s_client", "-connect", &format!("{}:443", domain),
            "-servername", domain, "-brief",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("openssl failed: {}", e))?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}\n{}", stdout, stderr);

    if combined.contains("CONNECTION ESTABLISHED") || combined.contains("Protocol") {
        // Extract protocol version
        let protocol = combined.lines()
            .find(|l| l.contains("Protocol version:") || l.starts_with("Protocol"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Unknown".into());

        // Extract cipher
        let cipher = combined.lines()
            .find(|l| l.contains("Ciphersuite:") || l.contains("Cipher"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Unknown".into());

        Ok(SslValidation { ssl_available: true, protocol_version: protocol, cipher_suite: cipher })
    } else if output.status.success() || combined.contains("Verify") {
        // openssl connected even without -brief details
        Ok(SslValidation { ssl_available: true, protocol_version: "TLS".into(), cipher_suite: "Unknown".into() })
    } else {
        Err(format!("SSL connection failed"))
    }
}

impl qicro_data_core::registry::Registrable for ValidationResult {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("ValidationResult", "validationresult")
    }
}

impl qicro_data_core::registry::Registrable for DnsValidation {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("DnsValidation", "dnsvalidation")
    }
}

impl qicro_data_core::registry::Registrable for HttpValidation {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("HttpValidation", "httpvalidation")
    }
}

impl qicro_data_core::registry::Registrable for SslValidation {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("SslValidation", "sslvalidation")
    }
}

impl qicro_data_core::registry::Registrable for ValidationStats {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("ValidationStats", "validationstats")
    }
}

impl qicro_data_core::registry::Registrable for BulkValidationResult {
    fn model_meta() -> qicro_data_core::registry::ModelMeta {
        qicro_data_core::registry::ModelMeta::new("BulkValidationResult", "bulkvalidationresult")
    }
}
