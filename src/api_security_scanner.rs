use reqwest::Client;
use regex::Regex;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::payloads;

// ── Result structs ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub status_code: u16,
    pub api_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub vuln_type: String,
    pub subtype: String,
    pub endpoint: String,
    pub parameter: String,
    pub payload: String,
    pub severity: String,
    pub confidence: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiScanResult {
    pub domain: String,
    pub endpoints_found: Vec<ApiEndpoint>,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub total_paths_probed: usize,
    pub endpoints_tested: usize,
}

// ── HTML killwords — definitive NOT-API indicators ──────────────────────────

const HTML_KILLERS: &[&str] = &[
    "<!doctype html", "<html", "<head>", "<body>", "<title>",
    "<div", "<form", "<table", "<script", "not found</title>",
    "404 not found", "404 - not found", "page not found", "file not found",
    "apache/2.", "nginx/", "microsoft-iis", "server error",
    "access denied", "forbidden", "directory listing", "index of /",
    "<h1>404</h1>", "<h1>error</h1>",
];

// ── Swagger/OpenAPI documentation indicators ────────────────────────────────

const DOC_INDICATORS: &[&str] = &[
    "\"openapi\":", "\"swagger\":", "\"info\":", "\"paths\":",
    "\"components\":", "\"definitions\":", "\"host\":",
    "\"basepath\":", "\"schemes\":", "\"consumes\":", "\"produces\":",
];

const DOC_URL_HINTS: &[&str] = &[
    "openapi", "swagger", "docs", "spec", "schema", "definition",
    ".json", ".yaml", ".yml",
];

// ── API-specific response headers ───────────────────────────────────────────

const API_HEADERS: &[&str] = &[
    "x-api-version", "x-api-key", "x-rate-limit", "x-ratelimit",
    "x-request-id", "x-correlation-id", "x-trace-id",
];

const FRAMEWORK_SERVERS: &[&str] = &[
    "express", "koa", "fastify", "spring", "django",
    "flask", "tornado", "rails", "sinatra", "fastapi",
];

// ── Auth error patterns (regex) ─────────────────────────────────────────────

const AUTH_ERROR_PATTERNS: &[&str] = &[
    r#""error"\s*:\s*"(unauthorized|forbidden|invalid.*token|missing.*auth)"#,
    r#""message"\s*:\s*"(unauthorized|forbidden|authentication|authorization)"#,
    r#""code"\s*:\s*"(401|403|auth_required|token_invalid)"#,
    r#""status"\s*:\s*"(unauthorized|forbidden|error)","#,
    r#""access_token""#,
    r#""api_key""#,
    r#""authentication.*required""#,
    r#""invalid.*credentials""#,
];

// ── RESTful API structure patterns ──────────────────────────────────────────

const API_STRUCTURE_PATTERNS: &[&str] = &[
    r#"^\s*\{\s*"data"\s*:\s*[\{\[]"#,
    r#"^\s*\{\s*"result"\s*:\s*[\{\[]"#,
    r#"^\s*\{\s*"results"\s*:\s*\["#,
    r#"^\s*\{\s*"items"\s*:\s*\["#,
    r#"^\s*\{\s*"records"\s*:\s*\["#,
    r#"^\s*\{\s*"version"\s*:\s*"[^"]*""#,
    r#"^\s*\{\s*"api_version"\s*:\s*"[^"]*""#,
    r#"^\s*\{\s*"timestamp"\s*:\s*\d+"#,
    r#"^\s*\{\s*"error"\s*:\s*\{\s*"code""#,
    r#"^\s*\{\s*"error"\s*:\s*\{\s*"message""#,
    r#"^\s*\{\s*"errors"\s*:\s*\[.*"message""#,
    r#"^\s*\{\s*"success"\s*:\s*(true|false)"#,
    r#"^\s*\{\s*"status"\s*:\s*"(up|down|ok|healthy|error|fail|success)""#,
    r#"^\s*\{\s*"health"\s*:\s*"(up|down|ok)""#,
];

// ── SQL error patterns ──────────────────────────────────────────────────────

const SQL_ERROR_PATTERNS: &[&str] = &[
    r"You have an error in your SQL syntax",
    r"MySQL server version for the right syntax",
    r"PostgreSQL.*ERROR.*syntax error",
    r"ORA-[0-9]{5}.*invalid identifier",
    r"SQLite error.*syntax error",
    r"SQLException.*invalid column name",
    r"mysql_fetch_array\(\).*expects parameter",
    r"Warning.*mysql_.*\(\).*supplied argument",
];

// ── JS API endpoint extraction patterns ─────────────────────────────────────

const JS_API_PATTERNS: &[&str] = &[
    r#"fetch\s*\(\s*['"`](/[^'"`\s]+)['"`]"#,
    r#"axios\.[a-z]+\s*\(\s*['"`](/[^'"`\s]+)['"`]"#,
    r#"\$\.ajax\([^)]*url\s*:\s*['"`](/[^'"`\s]+)['"`]"#,
    r#"\$\.get\s*\(\s*['"`](/[^'"`\s]+)['"`]"#,
    r#"\$\.post\s*\(\s*['"`](/[^'"`\s]+)['"`]"#,
    r#"apiUrl\s*[:=]\s*['"`](/[^'"`\s]+)['"`]"#,
    r#"API_URL\s*[:=]\s*['"`](/[^'"`\s]+)['"`]"#,
    r#"baseURL\s*[:=]\s*['"`](/[^'"`\s]+)['"`]"#,
    r#"endpoint\s*[:=]\s*['"`](/[^'"`\s]+)['"`]"#,
];

// ── Main scanner ────────────────────────────────────────────────────────────

pub async fn scan_api_endpoints(domain: &str) -> Result<ApiScanResult, Box<dyn std::error::Error + Send + Sync>> {
    let base_url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?;

    // ── Phase 1: Endpoint Discovery ─────────────────────────────────────
    let mut verified_endpoints: Vec<ApiEndpoint> = Vec::new();

    // 1a. Probe paths from embedded api_endpoints.txt
    let api_paths = payloads::lines(payloads::API_ENDPOINTS);
    let total_paths_probed = api_paths.len();

    for path in &api_paths {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        if let Some(endpoint) = verify_endpoint(&client, &url).await {
            verified_endpoints.push(endpoint);
        }
    }

    // 1b. Extract endpoints from JavaScript on main page
    let js_endpoints = extract_js_endpoints(&client, &base_url).await;
    for url in &js_endpoints {
        if !verified_endpoints.iter().any(|e| e.url == *url) {
            if let Some(endpoint) = verify_endpoint(&client, url).await {
                verified_endpoints.push(endpoint);
            }
        }
    }

    // 1c. Extract API paths from robots.txt and sitemap.xml
    let robots_endpoints = extract_robots_sitemap_endpoints(&client, &base_url).await;
    for url in &robots_endpoints {
        if !verified_endpoints.iter().any(|e| e.url == *url) {
            if let Some(endpoint) = verify_endpoint(&client, url).await {
                verified_endpoints.push(endpoint);
            }
        }
    }

    // 1d. Scrape Swagger/OpenAPI documentation for real paths
    let doc_endpoints = scrape_documentation_endpoints(&client, &base_url).await;
    for url in &doc_endpoints {
        if !verified_endpoints.iter().any(|e| e.url == *url) {
            if let Some(endpoint) = verify_endpoint(&client, url).await {
                verified_endpoints.push(endpoint);
            }
        }
    }

    // 1e. Check common API subdomains
    let subdomain_endpoints = check_api_subdomains(&client, domain).await;
    for url in &subdomain_endpoints {
        if !verified_endpoints.iter().any(|e| e.url == *url) {
            if let Some(endpoint) = verify_endpoint(&client, url).await {
                verified_endpoints.push(endpoint);
            }
        }
    }

    // ── Phase 2: Vulnerability Testing ──────────────────────────────────
    let mut vulnerabilities: Vec<VulnerabilityFinding> = Vec::new();
    let endpoints_tested = verified_endpoints.len();

    for ep in &verified_endpoints {
        let mut findings = test_endpoint(&client, &ep.url).await;
        vulnerabilities.append(&mut findings);

        // Early exit on excessive criticals
        let critical_count = vulnerabilities.iter()
            .filter(|v| v.severity == "CRITICAL")
            .count();
        if critical_count >= 10 {
            break;
        }
    }

    Ok(ApiScanResult {
        domain: domain.to_string(),
        endpoints_found: verified_endpoints,
        vulnerabilities,
        total_paths_probed,
        endpoints_tested,
    })
}

// ── Advanced API endpoint verification ──────────────────────────────────────

async fn verify_endpoint(client: &Client, url: &str) -> Option<ApiEndpoint> {
    // Try GET first, then OPTIONS, HEAD — majority voting
    let methods = ["GET", "OPTIONS", "HEAD"];
    let mut votes: Vec<(String, u16)> = Vec::new(); // (api_type, status)

    for method in &methods {
        let req = match *method {
            "GET" => client.get(url),
            "OPTIONS" => client.request(reqwest::Method::OPTIONS, url),
            "HEAD" => client.head(url),
            _ => continue,
        };

        let resp = match req.send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();

        // Immediate disqualifiers
        if matches!(status, 404 | 502 | 503 | 500) {
            continue;
        }

        let headers: Vec<(String, String)> = resp.headers().iter()
            .map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_lowercase()))
            .collect();

        let content_type = headers.iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        // For HEAD/OPTIONS we can't read body, just check headers
        if *method != "GET" {
            if let Some(api_type) = detect_api_from_headers(content_type, &headers, status) {
                votes.push((api_type, status));
            }
            continue;
        }

        // GET — full body analysis
        let body = match resp.text().await {
            Ok(t) => t,
            Err(_) => continue,
        };

        if body.trim().len() < 5 {
            continue;
        }

        let sample = if body.len() > 5000 { &body[..5000] } else { &body };
        let sample_lower = sample.to_lowercase();

        // HTML killer filter
        if HTML_KILLERS.iter().any(|k| sample_lower.contains(k)) {
            continue;
        }

        // Documentation file detection
        let is_doc_url = DOC_URL_HINTS.iter().any(|h| url.to_lowercase().contains(h));
        if is_doc_url {
            let doc_score: usize = DOC_INDICATORS.iter()
                .filter(|d| sample_lower.contains(*d))
                .count();
            if doc_score >= 3 {
                continue; // Skip API documentation files
            }
        }

        // Content-type based definitive detection
        let ct_api = if content_type.contains("application/json") {
            // Verify valid JSON
            if serde_json::from_str::<serde_json::Value>(sample).is_ok() {
                Some("REST/JSON".to_string())
            } else { None }
        } else if content_type.contains("application/xml") || content_type.contains("text/xml") {
            Some("REST/XML".to_string())
        } else if content_type.contains("graphql") {
            Some("GraphQL".to_string())
        } else if content_type.contains("application/vnd.api+json") {
            Some("JSON:API".to_string())
        } else if content_type.contains("application/hal+json") {
            Some("HAL+JSON".to_string())
        } else if content_type.contains("application/problem+json") {
            Some("Problem Details".to_string())
        } else {
            None
        };

        if let Some(api_type) = ct_api {
            votes.push((api_type, status));
            continue;
        }

        // Auth-protected endpoint detection (401/403)
        if matches!(status, 401 | 403) {
            let auth_headers = ["www-authenticate", "x-api-key", "x-auth-token", "x-rate-limit"];
            if auth_headers.iter().any(|h| headers.iter().any(|(k, _)| k == h)) {
                votes.push(("Protected API".to_string(), status));
                continue;
            }
            // Check body for API-style auth errors
            let auth_regexes: Vec<Regex> = AUTH_ERROR_PATTERNS.iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect();
            if auth_regexes.iter().any(|rx| rx.is_match(&sample_lower)) {
                votes.push(("Protected API".to_string(), status));
                continue;
            }
        }

        // API structure pattern scoring
        let structure_regexes: Vec<Regex> = API_STRUCTURE_PATTERNS.iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();
        let structure_score: usize = structure_regexes.iter()
            .filter(|rx| rx.is_match(sample))
            .count();

        // API header scoring
        let api_header_score: usize = API_HEADERS.iter()
            .filter(|h| headers.iter().any(|(k, _)| k == **h))
            .count();

        // Framework detection via Server header
        let framework_score: usize = headers.iter()
            .filter(|(k, _)| k == "server")
            .map(|(_, v)| FRAMEWORK_SERVERS.iter().filter(|f| v.contains(*f)).count() * 2)
            .sum();

        let total_score = structure_score + api_header_score + framework_score;

        if total_score >= 4 {
            votes.push(("REST API".to_string(), status));
        } else if total_score >= 2 && status == 200 {
            votes.push(("REST API".to_string(), status));
        }
    }

    // Majority voting
    if votes.is_empty() {
        return None;
    }

    // Pick the best vote (prefer 2xx status)
    let best = votes.iter()
        .max_by_key(|(_, s)| if *s < 400 { 1000 - *s as i32 } else { -((*s) as i32) })
        .unwrap();

    Some(ApiEndpoint {
        url: url.to_string(),
        status_code: best.1,
        api_type: best.0.clone(),
    })
}

fn detect_api_from_headers(content_type: &str, headers: &[(String, String)], status: u16) -> Option<String> {
    if content_type.contains("application/json") {
        return Some("REST/JSON".to_string());
    }
    if content_type.contains("application/xml") || content_type.contains("text/xml") {
        return Some("REST/XML".to_string());
    }
    if content_type.contains("graphql") {
        return Some("GraphQL".to_string());
    }
    if matches!(status, 401 | 403) {
        let auth_headers = ["www-authenticate", "x-api-key", "x-rate-limit"];
        if auth_headers.iter().any(|h| headers.iter().any(|(k, _)| k == h)) {
            return Some("Protected API".to_string());
        }
    }
    None
}

// ── Endpoint Discovery Helpers ──────────────────────────────────────────────

async fn extract_js_endpoints(client: &Client, base_url: &str) -> Vec<String> {
    let mut endpoints = HashSet::new();
    let resp = match client.get(base_url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };
    let body = match resp.text().await { Ok(t) => t, Err(_) => return Vec::new() };

    // Collect inline JS
    let mut all_js = String::new();
    let doc = Html::parse_document(&body);
    let script_sel = Selector::parse("script").unwrap();
    for el in doc.select(&script_sel) {
        let inline = el.text().collect::<String>();
        if inline.len() > 10 {
            all_js.push('\n');
            all_js.push_str(&inline);
        }
        // Fetch up to 10 external JS files
        if let Some(src) = el.value().attr("src") {
            if endpoints.len() > 10 { continue; }
            let js_url = resolve_url(base_url, src);
            if let Some(ref js_url) = js_url {
                if let Ok(resp) = client.get(js_url).send().await {
                    if resp.status().is_success() {
                        if let Ok(js_body) = resp.text().await {
                            all_js.push('\n');
                            all_js.push_str(&js_body);
                        }
                    }
                }
            }
        }
    }

    // Extract API paths from JS content
    let regexes: Vec<Regex> = JS_API_PATTERNS.iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    for rx in &regexes {
        for cap in rx.captures_iter(&all_js) {
            if let Some(m) = cap.get(1) {
                let path = m.as_str().trim();
                if path.is_empty() { continue; }
                // Skip static assets
                if [".js", ".css", ".png", ".jpg", ".gif", ".ico", ".svg"]
                    .iter().any(|ext| path.to_lowercase().ends_with(ext))
                {
                    continue;
                }
                let full = format!("{}{}", base_url.trim_end_matches('/'), path);
                endpoints.insert(full);
            }
        }
    }

    endpoints.into_iter().collect()
}

async fn extract_robots_sitemap_endpoints(client: &Client, base_url: &str) -> Vec<String> {
    let mut endpoints = HashSet::new();

    // robots.txt
    let robots_url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&robots_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                for line in body.lines() {
                    let line = line.trim().to_lowercase();
                    if (line.starts_with("disallow:") || line.starts_with("allow:")) && line.contains(':') {
                        let path = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
                        if !path.is_empty() && path != "/"
                            && ["api", "graphql", "rest"].iter().any(|kw| path.contains(kw))
                        {
                            endpoints.insert(format!("{}{}", base_url.trim_end_matches('/'), path));
                        }
                    }
                }
            }
        }
    }

    // sitemap.xml
    let sitemap_url = format!("{}/sitemap.xml", base_url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&sitemap_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                if let Ok(rx) = Regex::new(r"<loc>([^<]+)</loc>") {
                    for cap in rx.captures_iter(&body) {
                        if let Some(m) = cap.get(1) {
                            let url = m.as_str();
                            if ["api", "graphql", "rest"].iter().any(|kw| url.to_lowercase().contains(kw)) {
                                endpoints.insert(url.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    endpoints.into_iter().collect()
}

async fn scrape_documentation_endpoints(client: &Client, base_url: &str) -> Vec<String> {
    let mut endpoints = HashSet::new();
    let doc_paths = [
        "/swagger.json", "/openapi.json", "/api-docs", "/docs",
        "/swagger", "/api/swagger.json", "/api/docs",
    ];

    for path in &doc_paths {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let resp = match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let body = match resp.text().await { Ok(t) => t, Err(_) => continue };

        // Try to parse as JSON and extract "paths" key
        if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(paths) = doc.get("paths").and_then(|p| p.as_object()) {
                for path_key in paths.keys() {
                    if path_key.starts_with('/') {
                        endpoints.insert(
                            format!("{}{}", base_url.trim_end_matches('/'), path_key)
                        );
                    }
                }
            }
            if let Some(base_path) = doc.get("basePath").and_then(|b| b.as_str()) {
                if !base_path.is_empty() {
                    endpoints.insert(
                        format!("{}{}", base_url.trim_end_matches('/'), base_path)
                    );
                }
            }
        }
    }

    endpoints.into_iter().collect()
}

async fn check_api_subdomains(client: &Client, domain: &str) -> Vec<String> {
    let mut endpoints = Vec::new();
    let bare_domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(domain);

    let parts: Vec<&str> = bare_domain.split('.').collect();
    if parts.len() < 2 { return endpoints; }

    let base = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

    let prefixes = [
        "api", "rest", "graphql", "gateway",
        "api-v1", "api-v2", "api-dev", "dev-api",
        "api-staging", "staging-api", "mobile-api", "app-api",
        "admin-api", "auth-api",
    ];

    for prefix in &prefixes[..8] { // limit to avoid excessive requests
        for proto in &["https", "http"] {
            let url = format!("{}://{}.{}", proto, prefix, base);
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().is_success() || matches!(resp.status().as_u16(), 401 | 403) {
                    endpoints.push(url);
                    break; // Found, skip other protocol
                }
            }
        }
    }

    endpoints
}

// ── Vulnerability Testing ───────────────────────────────────────────────────

async fn test_endpoint(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();

    findings.append(&mut test_sql_injection(client, endpoint).await);
    findings.append(&mut test_xss(client, endpoint).await);
    findings.append(&mut test_ssti(client, endpoint).await);
    findings.append(&mut test_ssrf(client, endpoint).await);
    findings.append(&mut test_auth_bypass(client, endpoint).await);
    findings.append(&mut test_command_injection(client, endpoint).await);
    findings.append(&mut test_nosql_injection(client, endpoint).await);
    findings.append(&mut test_xxe(client, endpoint).await);
    findings.append(&mut test_lfi(client, endpoint).await);

    findings
}

// ── SQLi ────────────────────────────────────────────────────────────────────

async fn test_sql_injection(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let sqli_payloads = payloads::lines(payloads::SQL_INJECTION);
    let params = ["id", "user", "search", "q", "filter"];

    let error_regexes: Vec<Regex> = SQL_ERROR_PATTERNS.iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    for param in &params[..3] {
        // Baseline
        let baseline_url = format!("{}?{}=1", endpoint, param);
        let baseline_body = match fetch_body(client, &baseline_url).await {
            Some(b) => b,
            None => continue,
        };
        if error_regexes.iter().any(|rx| rx.is_match(&baseline_body)) {
            continue; // Baseline already has SQL errors
        }

        for payload in sqli_payloads.iter().take(5) {
            let encoded = urlencoding::encode(payload);
            let test_url = format!("{}?{}={}", endpoint, param, encoded);

            // Time-based detection
            if payload.to_uppercase().contains("SLEEP") || payload.to_uppercase().contains("WAITFOR") {
                let start = Instant::now();
                if let Ok(resp) = client.get(&test_url).send().await {
                    let elapsed = start.elapsed().as_secs_f64();
                    let _ = resp.text().await;
                    if elapsed > 4.8 {
                        findings.push(VulnerabilityFinding {
                            vuln_type: "SQL_INJECTION".into(),
                            subtype: "Time-based Blind".into(),
                            endpoint: endpoint.into(),
                            parameter: param.to_string(),
                            payload: payload.to_string(),
                            severity: "CRITICAL".into(),
                            confidence: "MEDIUM".into(),
                            evidence: format!("Response delayed {:.1}s", elapsed),
                        });
                        return findings;
                    }
                }
                continue;
            }

            // Error-based detection
            if let Some(body) = fetch_body(client, &test_url).await {
                for rx in &error_regexes {
                    if let Some(m) = rx.find(&body) {
                        if !rx.is_match(&baseline_body) {
                            findings.push(VulnerabilityFinding {
                                vuln_type: "SQL_INJECTION".into(),
                                subtype: "Error-based".into(),
                                endpoint: endpoint.into(),
                                parameter: param.to_string(),
                                payload: payload.to_string(),
                                severity: "CRITICAL".into(),
                                confidence: "HIGH".into(),
                                evidence: format!("SQL error: {}", m.as_str()),
                            });
                            return findings;
                        }
                    }
                }
            }
        }
    }

    findings
}

// ── XSS ─────────────────────────────────────────────────────────────────────

async fn test_xss(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let xss_payloads = payloads::lines(payloads::XSS);
    let params = ["q", "search", "query", "keyword", "name"];

    for payload in xss_payloads.iter().take(5) {
        for param in &params[..3] {
            let encoded = urlencoding::encode(payload);
            let test_url = format!("{}?{}={}", endpoint, param, encoded);

            let resp = match client.get(&test_url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if !resp.status().is_success() { continue; }

            let ct = resp.headers().get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("").to_lowercase();

            if !ct.contains("text/html") { continue; }

            let body = match resp.text().await { Ok(t) => t, Err(_) => continue };

            // Payload reflected unencoded in HTML
            if body.contains(payload) && !is_payload_safe_context(&body, payload) {
                findings.push(VulnerabilityFinding {
                    vuln_type: "XSS".into(),
                    subtype: "Reflected".into(),
                    endpoint: endpoint.into(),
                    parameter: param.to_string(),
                    payload: payload.to_string(),
                    severity: "HIGH".into(),
                    confidence: "HIGH".into(),
                    evidence: "Payload reflected in HTML without encoding".into(),
                });
                return findings;
            }
        }
    }
    findings
}

fn is_payload_safe_context(content: &str, payload: &str) -> bool {
    let pos = match content.find(payload) {
        Some(p) => p,
        None => return true,
    };
    // Inside HTML comment?
    let before = &content[..pos];
    let after = &content[pos..];
    if before.rfind("<!--").is_some() && after.find("-->").is_some() {
        let comment_start = before.rfind("<!--").unwrap();
        if before[comment_start..].find("-->").is_none() {
            return true;
        }
    }
    // Properly encoded?
    let encoded = payload.replace('<', "&lt;").replace('>', "&gt;");
    if content.contains(&encoded) {
        return true;
    }
    false
}

// ── SSTI ────────────────────────────────────────────────────────────────────

async fn test_ssti(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let tests = [
        ("{{7*7*7}}", "343"),
        ("{{9*9*9}}", "729"),
        ("${8*8*8}", "512"),
        ("{{42*13}}", "546"),
    ];
    let params = ["template", "name", "msg", "content"];

    for &(payload, expected) in &tests {
        for param in &params[..3] {
            // Baseline
            let baseline_url = format!("{}?{}=normaltext", endpoint, param);
            let baseline = match fetch_body(client, &baseline_url).await {
                Some(b) => b,
                None => continue,
            };

            let encoded = urlencoding::encode(payload);
            let test_url = format!("{}?{}={}", endpoint, param, encoded);

            if let Some(body) = fetch_body(client, &test_url).await {
                if body.contains(expected) && !body.contains(payload) && !baseline.contains(expected) {
                    findings.push(VulnerabilityFinding {
                        vuln_type: "SSTI".into(),
                        subtype: "Template Injection".into(),
                        endpoint: endpoint.into(),
                        parameter: param.to_string(),
                        payload: payload.to_string(),
                        severity: "CRITICAL".into(),
                        confidence: "HIGH".into(),
                        evidence: format!("Template executed: {} = {}", payload, expected),
                    });
                    return findings;
                }
            }
        }
    }
    findings
}

// ── SSRF ────────────────────────────────────────────────────────────────────

async fn test_ssrf(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let ssrf_payloads = payloads::lines(payloads::SSRF);
    let params = ["url", "uri", "path", "dest", "redirect"];
    let indicators = ["root:", "daemon:", "localhost", "metadata", "ami-id", "instance-id"];

    for param in &params[..3] {
        for payload in ssrf_payloads.iter().take(3) {
            let encoded = urlencoding::encode(payload);
            let test_url = format!("{}?{}={}", endpoint, param, encoded);

            if let Some(body) = fetch_body(client, &test_url).await {
                for indicator in &indicators {
                    if body.contains(indicator) {
                        findings.push(VulnerabilityFinding {
                            vuln_type: "SSRF".into(),
                            subtype: "Server-Side Request Forgery".into(),
                            endpoint: endpoint.into(),
                            parameter: param.to_string(),
                            payload: payload.to_string(),
                            severity: "CRITICAL".into(),
                            confidence: "HIGH".into(),
                            evidence: format!("Internal data leaked: {}", indicator),
                        });
                        return findings;
                    }
                }
            }
        }
    }
    findings
}

// ── Auth Bypass ─────────────────────────────────────────────────────────────

async fn test_auth_bypass(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();

    // Check if endpoint is normally protected
    let normal_status = match client.get(endpoint).send().await {
        Ok(r) => r.status().as_u16(),
        Err(_) => return findings,
    };
    if !matches!(normal_status, 401 | 403) {
        return findings; // Not protected, skip
    }

    let bypass_headers = payloads::auth_headers(payloads::AUTH_BYPASS_HEADERS);

    for (name, value) in bypass_headers.iter().take(10) {
        let resp = match client.get(endpoint)
            .header(name.as_ref() as &str, value.as_ref() as &str)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        if resp.status().as_u16() == 200 {
            findings.push(VulnerabilityFinding {
                vuln_type: "AUTH_BYPASS".into(),
                subtype: "Header-based".into(),
                endpoint: endpoint.into(),
                parameter: String::new(),
                payload: format!("{}: {}", name, value),
                severity: "CRITICAL".into(),
                confidence: "HIGH".into(),
                evidence: format!("Bypass with header {}: {}", name, value),
            });
            return findings;
        }
    }
    findings
}

// ── Command Injection ───────────────────────────────────────────────────────

async fn test_command_injection(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let cmd_payloads = payloads::lines(payloads::COMMAND_INJECTION);
    let params = ["cmd", "exec", "command", "ping", "host"];

    for param in &params[..3] {
        for payload in cmd_payloads.iter().take(3) {
            if payload.to_lowercase().contains("sleep") {
                let encoded = urlencoding::encode(payload);
                let test_url = format!("{}?{}={}", endpoint, param, encoded);
                let start = Instant::now();
                if let Ok(resp) = client.get(&test_url).send().await {
                    let elapsed = start.elapsed().as_secs_f64();
                    let _ = resp.text().await;
                    if elapsed > 4.5 {
                        findings.push(VulnerabilityFinding {
                            vuln_type: "COMMAND_INJECTION".into(),
                            subtype: "Time-based".into(),
                            endpoint: endpoint.into(),
                            parameter: param.to_string(),
                            payload: payload.to_string(),
                            severity: "CRITICAL".into(),
                            confidence: "HIGH".into(),
                            evidence: format!("Command executed (delay: {:.1}s)", elapsed),
                        });
                        return findings;
                    }
                }
            }
        }
    }
    findings
}

// ── NoSQL Injection ─────────────────────────────────────────────────────────

async fn test_nosql_injection(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let nosql_payloads = payloads::lines(payloads::NOSQL_INJECTION);

    for payload in nosql_payloads.iter().take(3) {
        let resp = match client.post(endpoint)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        if matches!(resp.status().as_u16(), 200 | 201) {
            let body = match resp.text().await { Ok(t) => t, Err(_) => continue };
            if body.len() > 100 && !body.to_lowercase().contains("error") {
                findings.push(VulnerabilityFinding {
                    vuln_type: "NOSQL_INJECTION".into(),
                    subtype: "Operator Injection".into(),
                    endpoint: endpoint.into(),
                    parameter: String::new(),
                    payload: payload.to_string(),
                    severity: "HIGH".into(),
                    confidence: "MEDIUM".into(),
                    evidence: "NoSQL operator accepted, returned data".into(),
                });
                return findings;
            }
        }
    }
    findings
}

// ── XXE ─────────────────────────────────────────────────────────────────────

async fn test_xxe(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let xxe_payloads = payloads::lines(payloads::XXE);
    let indicators = ["root:", "daemon:", "Windows", "[fonts]"];

    for payload in xxe_payloads.iter().take(2) {
        let resp = match client.post(endpoint)
            .header("Content-Type", "application/xml")
            .body(payload.to_string())
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        if resp.status().is_success() {
            let body = match resp.text().await { Ok(t) => t, Err(_) => continue };
            for indicator in &indicators {
                if body.contains(indicator) {
                    findings.push(VulnerabilityFinding {
                        vuln_type: "XXE".into(),
                        subtype: "XML External Entity".into(),
                        endpoint: endpoint.into(),
                        parameter: String::new(),
                        payload: payload.to_string(),
                        severity: "CRITICAL".into(),
                        confidence: "HIGH".into(),
                        evidence: "File contents disclosed via XXE".into(),
                    });
                    return findings;
                }
            }
        }
    }
    findings
}

// ── LFI ─────────────────────────────────────────────────────────────────────

async fn test_lfi(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding> {
    let mut findings = Vec::new();
    let lfi_payloads = payloads::lines(payloads::LFI);
    let params = ["file", "path", "page", "include", "template"];
    let indicators = ["root:x:", "daemon:", "[fonts]", "[extensions]"];

    for param in &params[..3] {
        for payload in lfi_payloads.iter().take(3) {
            let encoded = urlencoding::encode(payload);
            let test_url = format!("{}?{}={}", endpoint, param, encoded);

            if let Some(body) = fetch_body(client, &test_url).await {
                for indicator in &indicators {
                    if body.contains(indicator) {
                        findings.push(VulnerabilityFinding {
                            vuln_type: "LFI".into(),
                            subtype: "Local File Inclusion".into(),
                            endpoint: endpoint.into(),
                            parameter: param.to_string(),
                            payload: payload.to_string(),
                            severity: "HIGH".into(),
                            confidence: "HIGH".into(),
                            evidence: "Local file contents exposed".into(),
                        });
                        return findings;
                    }
                }
            }
        }
    }
    findings
}

// ── Shared helpers ──────────────────────────────────────────────────────────

async fn fetch_body(client: &Client, url: &str) -> Option<String> {
    let resp = client.get(url).send().await.ok()?;
    if resp.status().as_u16() == 404 { return None; }
    resp.text().await.ok()
}

fn resolve_url(base: &str, href: &str) -> Option<String> {
    if href.starts_with("javascript:") || href.starts_with('#') || href.starts_with("mailto:") {
        return None;
    }
    if href.starts_with("//") {
        return Some(format!("https:{}", href));
    }
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    let base_trimmed = if let Some(idx) = base.rfind('/') {
        &base[..idx + 1]
    } else {
        base
    };
    Some(format!("{}{}", base_trimmed, href.trim_start_matches('/')))
}
