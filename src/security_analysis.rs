use regex::Regex;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ── WAF signature database ──────────────────────────────────────────────────

struct WafSignature {
    name: &'static str,
    headers: &'static [&'static str],
    server: &'static [&'static str],
}

const WAF_SIGNATURES: &[WafSignature] = &[
    WafSignature {
        name: "Cloudflare",
        headers: &["cf-ray", "cf-cache-status", "__cfduid"],
        server: &["cloudflare"],
    },
    WafSignature {
        name: "Akamai",
        headers: &["akamai-transformed", "akamai-cache-status"],
        server: &["akamaighost"],
    },
    WafSignature {
        name: "Imperva Incapsula",
        headers: &["x-iinfo", "incap_ses"],
        server: &["imperva"],
    },
    WafSignature {
        name: "Sucuri",
        headers: &["x-sucuri-id", "x-sucuri-cache"],
        server: &["sucuri"],
    },
    WafSignature {
        name: "Barracuda",
        headers: &["barra"],
        server: &["barracuda"],
    },
    WafSignature {
        name: "F5 BIG-IP",
        headers: &["f5-http-lb", "bigip"],
        server: &["bigip", "f5"],
    },
    WafSignature {
        name: "AWS WAF",
        headers: &["x-amz-cf-id", "x-amzn-requestid"],
        server: &["awselb"],
    },
];

/// Security headers with importance levels
const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "Critical"),
    ("content-security-policy", "Critical"),
    ("x-frame-options", "High"),
    ("x-content-type-options", "Medium"),
    ("x-xss-protection", "Medium"),
    ("referrer-policy", "Medium"),
    ("permissions-policy", "Medium"),
];

/// Error patterns for vulnerability scanning
const ERROR_PATTERNS: &[(&str, &str)] = &[
    ("fatal error", "PHP Fatal Error"),
    ("warning.*mysql", "MySQL Warning"),
    ("error.*sql", "SQL Error"),
];

// ── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysisResult {
    pub domain: String,
    pub https_available: bool,
    pub https_redirect: bool,
    pub waf_detection: WafDetectionResult,
    pub security_headers: SecurityHeadersResult,
    pub ssl_analysis: SslAnalysisResult,
    pub cors_policy: CorsPolicyResult,
    pub cookie_security: CookieSecurityResult,
    pub http_methods: HttpMethodsResult,
    pub server_information: ServerInfoResult,
    pub vulnerability_scan: VulnScanResult,
    pub security_score: SecurityScoreResult,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafMatch {
    pub provider: String,
    pub confidence: String,
    pub detection_methods: Vec<String>,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetectionResult {
    pub detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_waf: Option<WafMatch>,
    pub all_detected: Vec<WafMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderAnalysis {
    pub present: bool,
    pub value: String,
    pub importance: String,
    pub security_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersResult {
    pub headers: HashMap<String, HeaderAnalysis>,
    pub score: u32,
    pub missing_critical: Vec<String>,
    pub missing_high: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslAnalysisResult {
    pub ssl_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    pub cipher_strength: String,
    pub overall_grade: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsPolicyResult {
    pub configured: bool,
    pub headers: HashMap<String, String>,
    pub issues: Vec<String>,
    pub security_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieSecurityResult {
    pub cookies_present: bool,
    pub security_issues: Vec<String>,
    pub security_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMethodsResult {
    pub methods_detected: bool,
    pub allowed_methods: Vec<String>,
    pub dangerous_methods: Vec<String>,
    pub security_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoResult {
    pub server_headers: HashMap<String, String>,
    pub information_disclosure: Vec<String>,
    pub disclosure_count: usize,
    pub security_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFound {
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanResult {
    pub vulnerabilities_found: usize,
    pub vulnerabilities: Vec<VulnerabilityFound>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScoreResult {
    pub overall_score: u32,
    pub grade: String,
    pub risk_level: String,
    pub score_breakdown: HashMap<String, u32>,
}

// ── Main function ───────────────────────────────────────────────────────────

pub async fn analyze_security(
    domain: &str,
) -> Result<SecurityAnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
    let clean = if domain.starts_with("http://") || domain.starts_with("https://") {
        domain
            .split("//")
            .nth(1)
            .unwrap_or(domain)
            .split('/')
            .next()
            .unwrap_or(domain)
            .to_string()
    } else {
        domain.to_string()
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;

    // ── HTTP + HTTPS requests ───────────────────────────────────────────
    let http_url = format!("http://{}", clean);
    let https_url = format!("https://{}", clean);

    // Check HTTPS redirect from HTTP (no-follow)
    let redir_client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0")
        .build()?;

    let mut https_redirect = false;
    if let Ok(resp) = redir_client.get(&http_url).send().await {
        let status = resp.status().as_u16();
        if [301, 302, 307, 308].contains(&status) {
            if let Some(loc) = resp.headers().get("location") {
                if let Ok(l) = loc.to_str() {
                    if l.starts_with("https://") {
                        https_redirect = true;
                    }
                }
            }
        }
    }

    // Primary response (prefer HTTPS)
    let https_resp = client.get(&https_url).send().await;
    let https_available = https_resp.is_ok();

    let primary = if let Ok(r) = https_resp {
        r
    } else {
        client.get(&http_url).send().await?
    };

    let resp_url = primary.url().to_string();
    let headers = primary.headers().clone();
    let body_text = primary.text().await.unwrap_or_default();

    // ── 1. WAF Detection ────────────────────────────────────────────────
    let waf_detection = detect_waf(&headers);

    // ── 2. Security Headers ─────────────────────────────────────────────
    let security_headers = analyze_security_headers(&headers);

    // ── 3. SSL Analysis ─────────────────────────────────────────────────
    let ssl_analysis = analyze_ssl(&clean).await;

    // ── 4. CORS Policy ──────────────────────────────────────────────────
    let cors_policy = analyze_cors(&headers);

    // ── 5. Cookie Security ──────────────────────────────────────────────
    let cookie_security = analyze_cookies(&headers);

    // ── 6. HTTP Methods ─────────────────────────────────────────────────
    let http_methods = detect_methods(&client, &https_url).await;

    // ── 7. Server Information ───────────────────────────────────────────
    let server_information = analyze_server_info(&headers);

    // ── 8. Vulnerability Scan ───────────────────────────────────────────
    let vulnerability_scan = perform_vuln_scan(&resp_url, &body_text);

    // ── 9. Score & Recommendations ──────────────────────────────────────
    let security_score = calculate_score(
        &security_headers,
        &ssl_analysis,
        &waf_detection,
        &vulnerability_scan,
    );
    let recommendations = generate_recommendations(
        &security_headers,
        &ssl_analysis,
        &waf_detection,
        https_available,
        https_redirect,
    );

    Ok(SecurityAnalysisResult {
        domain: clean,
        https_available,
        https_redirect,
        waf_detection,
        security_headers,
        ssl_analysis,
        cors_policy,
        cookie_security,
        http_methods,
        server_information,
        vulnerability_scan,
        security_score,
        recommendations,
    })
}

// ── WAF Detection ───────────────────────────────────────────────────────────

fn detect_waf(headers: &reqwest::header::HeaderMap) -> WafDetectionResult {
    let headers_str = format!("{:?}", headers).to_lowercase();
    let server_header = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let mut detected = Vec::new();

    for sig in WAF_SIGNATURES {
        let mut confidence: u32 = 0;
        let mut methods = Vec::new();

        for h in sig.headers {
            if headers_str.contains(h) {
                confidence += 40;
                methods.push(format!("Header: {}", h));
            }
        }
        for s in sig.server {
            if server_header.contains(s) {
                confidence += 30;
                methods.push(format!("Server: {}", s));
            }
        }

        if confidence > 0 {
            let conf_str = if confidence >= 50 {
                "High"
            } else if confidence >= 30 {
                "Medium"
            } else {
                "Low"
            };
            detected.push(WafMatch {
                provider: sig.name.to_string(),
                confidence: conf_str.into(),
                detection_methods: methods,
                score: confidence,
            });
        }
    }

    detected.sort_by(|a, b| b.score.cmp(&a.score));

    WafDetectionResult {
        detected: !detected.is_empty(),
        primary_waf: detected.first().cloned(),
        all_detected: detected,
    }
}

// ── Security Headers ────────────────────────────────────────────────────────

fn analyze_security_headers(headers: &reqwest::header::HeaderMap) -> SecurityHeadersResult {
    let mut analysis = HashMap::new();
    let mut total_score: u32 = 0;
    let mut max_score: u32 = 0;
    let mut missing_critical = Vec::new();
    let mut missing_high = Vec::new();

    for &(name, importance) in SECURITY_HEADERS {
        let present = headers.get(name).is_some();
        let value = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("Not Set")
            .to_string();

        let security_level = if present {
            "Good".into()
        } else if importance == "Critical" {
            "Critical".into()
        } else {
            "Medium".into()
        };

        let weight = match importance {
            "Critical" => 30,
            "High" => 20,
            _ => 10,
        };
        max_score += weight;
        if present {
            total_score += weight;
        } else if importance == "Critical" {
            missing_critical.push(name.to_string());
        } else if importance == "High" {
            missing_high.push(name.to_string());
        }

        analysis.insert(
            name.to_string(),
            HeaderAnalysis {
                present,
                value,
                importance: importance.into(),
                security_level,
            },
        );
    }

    let score = if max_score > 0 {
        total_score * 100 / max_score
    } else {
        0
    };

    SecurityHeadersResult {
        headers: analysis,
        score,
        missing_critical,
        missing_high,
    }
}

// ── SSL/TLS Analysis ────────────────────────────────────────────────────────

async fn analyze_ssl(domain: &str) -> SslAnalysisResult {
    let output = match tokio::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("{}:443", domain),
            "-servername",
            domain,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => {
            return SslAnalysisResult {
                ssl_available: false,
                protocol_version: None,
                cipher_suite: None,
                cipher_strength: "Unknown".into(),
                overall_grade: "F".into(),
                subject: None,
                issuer: None,
            }
        }
    };

    if !output.contains("CONNECTED") {
        return SslAnalysisResult {
            ssl_available: false,
            protocol_version: None,
            cipher_suite: None,
            cipher_strength: "Unknown".into(),
            overall_grade: "F".into(),
            subject: None,
            issuer: None,
        };
    }

    let protocol = Regex::new(r"Protocol\s*:\s*(.+)")
        .ok()
        .and_then(|r| r.captures(&output))
        .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()));

    let cipher_suite = Regex::new(r"Cipher\s*:\s*(.+)")
        .ok()
        .and_then(|r| r.captures(&output))
        .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()));

    let subject = Regex::new(r"subject=.*?CN\s*=\s*([^\n/,]+)")
        .ok()
        .and_then(|r| r.captures(&output))
        .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()));

    let issuer = Regex::new(r"issuer=.*?CN\s*=\s*([^\n/,]+)")
        .ok()
        .and_then(|r| r.captures(&output))
        .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()));

    // Cipher strength
    let cipher_strength = match &cipher_suite {
        Some(c) if c.contains("AES256") || c.contains("CHACHA20") || c.contains("TLS_AES_256") => {
            "Strong"
        }
        Some(c) if c.contains("AES128") => "Medium",
        Some(c) if c.contains("DES") || c.contains("RC4") || c.contains("NULL") => "Weak",
        _ => "Unknown",
    };

    // Grade
    let proto_str = protocol.as_deref().unwrap_or("");
    let grade = if proto_str.contains("TLSv1.3") {
        "A+"
    } else if proto_str.contains("TLSv1.2") && cipher_strength == "Strong" {
        "A"
    } else if proto_str.contains("TLSv1.2") {
        "B"
    } else if proto_str.contains("TLSv1.1") || proto_str.contains("TLSv1") {
        "C"
    } else {
        "F"
    };

    SslAnalysisResult {
        ssl_available: true,
        protocol_version: protocol,
        cipher_suite,
        cipher_strength: cipher_strength.into(),
        overall_grade: grade.into(),
        subject,
        issuer,
    }
}

// ── CORS Policy ─────────────────────────────────────────────────────────────

fn analyze_cors(headers: &reqwest::header::HeaderMap) -> CorsPolicyResult {
    let cors_keys = [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-credentials",
    ];

    let mut cors_headers = HashMap::new();
    let mut configured = false;
    let mut issues = Vec::new();

    for &key in &cors_keys {
        let val = headers
            .get(key)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("Not Set")
            .to_string();
        if val != "Not Set" {
            configured = true;
        }
        cors_headers.insert(key.to_string(), val);
    }

    let origin = cors_headers
        .get("access-control-allow-origin")
        .map(|s| s.as_str())
        .unwrap_or("Not Set");
    let creds = cors_headers
        .get("access-control-allow-credentials")
        .map(|s| s.as_str())
        .unwrap_or("Not Set");

    if origin == "*" && creds == "true" {
        issues.push("Critical: Wildcard origin with credentials allowed".into());
    } else if origin == "*" {
        issues.push("Warning: Wildcard origin allows all domains".into());
    }

    let security_level = if issues.is_empty() {
        "High"
    } else if issues.len() <= 1 {
        "Medium"
    } else {
        "Low"
    };

    CorsPolicyResult {
        configured,
        headers: cors_headers,
        issues,
        security_level: security_level.into(),
    }
}

// ── Cookie Security ─────────────────────────────────────────────────────────

fn analyze_cookies(headers: &reqwest::header::HeaderMap) -> CookieSecurityResult {
    let cookie_val = match headers.get("set-cookie").and_then(|v| v.to_str().ok()) {
        Some(c) => c.to_string(),
        None => {
            return CookieSecurityResult {
                cookies_present: false,
                security_issues: vec![],
                security_score: 100,
            }
        }
    };

    let mut issues = Vec::new();
    if !cookie_val.contains("Secure") {
        issues.push("Missing Secure flag".into());
    }
    if !cookie_val.contains("HttpOnly") {
        issues.push("Missing HttpOnly flag".into());
    }
    if !cookie_val.contains("SameSite") {
        issues.push("Missing SameSite attribute".into());
    }

    let score = 100u32.saturating_sub(issues.len() as u32 * 25);

    CookieSecurityResult {
        cookies_present: true,
        security_issues: issues,
        security_score: score,
    }
}

// ── HTTP Methods ────────────────────────────────────────────────────────────

async fn detect_methods(client: &Client, url: &str) -> HttpMethodsResult {
    let dangerous = ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"];

    match client.request(Method::OPTIONS, url).send().await {
        Ok(resp) => {
            let allow = resp
                .headers()
                .get("allow")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let methods: Vec<String> = allow
                .split(',')
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty())
                .collect();

            let found_dangerous: Vec<String> = methods
                .iter()
                .filter(|m| dangerous.contains(&m.to_uppercase().as_str()))
                .cloned()
                .collect();

            let risk = if !found_dangerous.is_empty() {
                "High"
            } else {
                "Low"
            };

            HttpMethodsResult {
                methods_detected: true,
                allowed_methods: methods,
                dangerous_methods: found_dangerous,
                security_risk: risk.into(),
            }
        }
        Err(_) => HttpMethodsResult {
            methods_detected: false,
            allowed_methods: vec![],
            dangerous_methods: vec![],
            security_risk: "Unknown".into(),
        },
    }
}

// ── Server Information ──────────────────────────────────────────────────────

fn analyze_server_info(headers: &reqwest::header::HeaderMap) -> ServerInfoResult {
    let disclosure_headers = [
        ("server", "Web server version disclosed"),
        ("x-powered-by", "Technology stack disclosed"),
    ];

    let mut server_headers = HashMap::new();
    let mut issues = Vec::new();

    for &(header, issue) in &disclosure_headers {
        if let Some(val) = headers.get(header).and_then(|v| v.to_str().ok()) {
            server_headers.insert(header.to_string(), val.to_string());
            issues.push(issue.to_string());
        }
    }

    let count = issues.len();
    let level = if count > 2 {
        "High"
    } else if count > 0 {
        "Medium"
    } else {
        "Good"
    };

    ServerInfoResult {
        server_headers,
        information_disclosure: issues,
        disclosure_count: count,
        security_level: level.into(),
    }
}

// ── Vulnerability Scan ──────────────────────────────────────────────────────

fn perform_vuln_scan(resp_url: &str, body: &str) -> VulnScanResult {
    let mut vulns = Vec::new();

    // HTTPS enforcement
    if !resp_url.starts_with("https://") {
        vulns.push(VulnerabilityFound {
            vuln_type: "Insecure Transport".into(),
            severity: "High".into(),
            description: "Site not enforcing HTTPS".into(),
        });
    }

    // Error patterns in body
    for &(pattern, desc) in ERROR_PATTERNS {
        if let Ok(rx) = Regex::new(&format!("(?i){}", pattern)) {
            if rx.is_match(body) {
                vulns.push(VulnerabilityFound {
                    vuln_type: "Information Disclosure".into(),
                    severity: "Low".into(),
                    description: format!("{} detected in response", desc),
                });
            }
        }
    }

    let risk = calculate_risk_level(&vulns);

    VulnScanResult {
        vulnerabilities_found: vulns.len(),
        vulnerabilities: vulns,
        risk_level: risk,
    }
}

fn calculate_risk_level(vulns: &[VulnerabilityFound]) -> String {
    if vulns.is_empty() {
        return "Low".into();
    }
    let total: u32 = vulns
        .iter()
        .map(|v| match v.severity.as_str() {
            "High" => 3,
            "Medium" => 2,
            _ => 1,
        })
        .sum();

    if total >= 6 {
        "Critical".into()
    } else if total >= 4 {
        "High".into()
    } else if total >= 2 {
        "Medium".into()
    } else {
        "Low".into()
    }
}

// ── Security Score (weighted composite) ─────────────────────────────────────

fn calculate_score(
    headers: &SecurityHeadersResult,
    ssl: &SslAnalysisResult,
    waf: &WafDetectionResult,
    vulns: &VulnScanResult,
) -> SecurityScoreResult {
    let mut breakdown = HashMap::new();
    let mut total: f64 = 100.0;

    // Security Headers (40%)
    let h_score = headers.score;
    breakdown.insert("security_headers".into(), h_score);
    total -= (100.0 - h_score as f64) * 0.4;

    // SSL (30%)
    let ssl_score: u32 = match ssl.overall_grade.as_str() {
        "A+" => 100,
        "A" => 90,
        "B" => 75,
        "C" => 60,
        "D" => 40,
        _ => 0,
    };
    breakdown.insert("ssl_tls".into(), ssl_score);
    total -= (100.0 - ssl_score as f64) * 0.3;

    // WAF (15%)
    let waf_score: u32 = if waf.detected { 100 } else { 60 };
    breakdown.insert("waf_protection".into(), waf_score);
    total -= (100.0 - waf_score as f64) * 0.15;

    // Vulnerabilities (15%)
    let vuln_score = 100u32.saturating_sub(vulns.vulnerabilities_found as u32 * 20);
    breakdown.insert("vulnerabilities".into(), vuln_score);
    total -= (100.0 - vuln_score as f64) * 0.15;

    let final_score = total.clamp(0.0, 100.0) as u32;

    let grade = if final_score >= 95 {
        "A+"
    } else if final_score >= 90 {
        "A"
    } else if final_score >= 80 {
        "B"
    } else if final_score >= 70 {
        "C"
    } else if final_score >= 60 {
        "D"
    } else {
        "F"
    };

    let risk = if final_score >= 85 {
        "Low Risk"
    } else if final_score >= 70 {
        "Medium Risk"
    } else if final_score >= 50 {
        "High Risk"
    } else {
        "Critical Risk"
    };

    SecurityScoreResult {
        overall_score: final_score,
        grade: grade.into(),
        risk_level: risk.into(),
        score_breakdown: breakdown,
    }
}

// ── Recommendations ─────────────────────────────────────────────────────────

fn generate_recommendations(
    headers: &SecurityHeadersResult,
    ssl: &SslAnalysisResult,
    waf: &WafDetectionResult,
    https_available: bool,
    https_redirect: bool,
) -> Vec<String> {
    let mut recs = Vec::new();

    if !headers.missing_critical.is_empty() {
        recs.push(format!(
            "CRITICAL: Implement missing security headers: {}",
            headers.missing_critical.join(", ")
        ));
    }
    if !headers.missing_high.is_empty() {
        recs.push(format!(
            "HIGH: Add security headers: {}",
            headers.missing_high.join(", ")
        ));
    }

    match ssl.overall_grade.as_str() {
        "D" | "F" => recs.push("CRITICAL: Upgrade SSL/TLS configuration".into()),
        "C" => recs.push("MEDIUM: Consider improving SSL/TLS configuration".into()),
        _ => {}
    }

    if !waf.detected {
        recs.push("MEDIUM: Consider implementing a Web Application Firewall (WAF)".into());
    }

    if !https_available {
        recs.push("CRITICAL: Enable HTTPS for secure communication".into());
    } else if !https_redirect {
        recs.push("MEDIUM: Implement automatic HTTP to HTTPS redirect".into());
    }

    recs.truncate(10);
    recs
}
