use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use crate::payloads;

// ── Result structs ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub secret_type: String,
    pub severity: String,
    pub masked_value: String,
    pub source_url: String,
    pub line: usize,
    pub entropy: f64,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsVulnerability {
    pub vuln_type: String,
    pub severity: String,
    pub source_url: String,
    pub matched_code: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfFinding {
    pub finding_type: String,
    pub severity: String,
    pub source_url: String,
    pub vulnerable_params: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_urls_crawled: usize,
    pub total_js_files: usize,
    pub total_api_endpoints: usize,
    pub secrets_count: usize,
    pub js_vulnerabilities_count: usize,
    pub ssrf_vulnerabilities_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerResult {
    pub domain: String,
    pub secrets: Vec<SecretFinding>,
    pub js_vulnerabilities: Vec<JsVulnerability>,
    pub ssrf_vulnerabilities: Vec<SsrfFinding>,
    pub api_endpoints_discovered: Vec<String>,
    pub summary: ScanSummary,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in data.bytes() {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn mask_secret(s: &str) -> String {
    if s.len() <= 8 {
        if s.len() > 2 {
            format!("****{}", &s[s.len() - 2..])
        } else {
            "****".into()
        }
    } else {
        format!("{}****{}", &s[..4], &s[s.len() - 4..])
    }
}

fn is_false_positive_context(context: &str) -> bool {
    let fp = [
        "example",
        "sample",
        "placeholder",
        "dummy",
        "test",
        "demo",
        "your_",
        "my_",
        "template",
        "undefined",
        "localhost",
        "127.0.0.1",
    ];
    let ctx_lower = context.to_lowercase();
    fp.iter().any(|p| ctx_lower.contains(p))
}

fn is_known_library(url: &str) -> bool {
    let libs = [
        "jquery",
        "bootstrap",
        "modernizr",
        "polyfill",
        "vendor",
        "bundle",
        "analytics",
        "tracking",
        "ga.js",
        "gtm.js",
        "react",
        "angular",
        "vue",
        "lodash",
        "moment",
        "cdn",
        "static",
        "dist",
        "chunk",
    ];
    let url_lower = url.to_lowercase();
    libs.iter().any(|lib| url_lower.contains(lib))
}

// ── Secret patterns ─────────────────────────────────────────────────────────

struct SecretPattern {
    name: &'static str,
    pattern: &'static str,
    severity: &'static str,
    recommendation: &'static str,
}

const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        name: "AWS Access Key",
        pattern: r"\bAKIA[0-9A-Z]{16}\b",
        severity: "Medium",
        recommendation: "Rotate the key immediately. Use AWS IAM roles instead of hard-coded keys.",
    },
    SecretPattern {
        name: "AWS Secret Key",
        pattern: r"\b[0-9a-zA-Z/+]{40}\b",
        severity: "High",
        recommendation: "Rotate the key immediately. Store secrets in AWS Secrets Manager.",
    },
    SecretPattern {
        name: "Google API Key",
        pattern: r"\bAIza[0-9A-Za-z\-_]{35}\b",
        severity: "Medium",
        recommendation: "Rotate the key and implement API key restrictions.",
    },
    SecretPattern {
        name: "Google OAuth",
        pattern: r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        severity: "Medium",
        recommendation: "Review and potentially regenerate the OAuth credentials.",
    },
    SecretPattern {
        name: "Stripe API Key",
        pattern: r"\b(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,34}\b",
        severity: "High",
        recommendation: "Rotate the key immediately. Only use server-side code for Stripe API.",
    },
    SecretPattern {
        name: "GitHub Token",
        pattern: r"\b(?:github|gh)(?:_pat)?_[0-9a-zA-Z]{36,40}\b",
        severity: "High",
        recommendation: "Revoke and regenerate the token. Use GitHub Actions secrets for CI/CD.",
    },
    SecretPattern {
        name: "GitHub OAuth",
        pattern: r"\bgho_[0-9a-zA-Z]{36,40}\b",
        severity: "High",
        recommendation: "Revoke and regenerate the OAuth token.",
    },
    SecretPattern {
        name: "Facebook Access Token",
        pattern: r"EAACEdEose0cBA[0-9A-Za-z]+",
        severity: "Medium",
        recommendation: "Revoke the token and regenerate. Store tokens securely.",
    },
    SecretPattern {
        name: "JWT Token",
        pattern: r"eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*",
        severity: "Medium",
        recommendation: "If valid, rotate the token. Implement proper expiration.",
    },
    SecretPattern {
        name: "SSH Private Key",
        pattern: r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY",
        severity: "High",
        recommendation: "Generate a new key pair. Never store private keys in code.",
    },
    SecretPattern {
        name: "Password in URL",
        pattern: r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}",
        severity: "High",
        recommendation: "Remove the password from the URL and use secure authentication.",
    },
    SecretPattern {
        name: "Firebase URL",
        pattern: r"https://[a-z0-9-]+\.firebaseio\.com",
        severity: "Low",
        recommendation: "Review Firebase security rules and regenerate any associated secrets.",
    },
    SecretPattern {
        name: "MongoDB Connection String",
        pattern: r"mongodb(?:\+srv)?://[^/\s]+:[^/\s]+@[^/\s]+",
        severity: "High",
        recommendation: "Rotate the password and use environment variables instead.",
    },
    SecretPattern {
        name: "Slack Token",
        pattern: r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
        severity: "Medium",
        recommendation: "Revoke and regenerate the token.",
    },
    SecretPattern {
        name: "Slack Webhook",
        pattern: r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        severity: "Medium",
        recommendation: "Regenerate the webhook URL and store it securely.",
    },
    SecretPattern {
        name: "API Key",
        pattern: r#"(?i)\b(?:api[_\-]?key|apikey)\b\s*[=:]\s*["'`]([a-zA-Z0-9_\-\.]{16,64})["'`]"#,
        severity: "Medium",
        recommendation: "Rotate the key. Store it in environment variables or a secrets manager.",
    },
    SecretPattern {
        name: "Secret Key",
        pattern: r#"(?i)\b(?:secret[_\-]?key|secretkey)\b\s*[=:]\s*["'`]([a-zA-Z0-9_\-\.]{16,64})["'`]"#,
        severity: "Medium",
        recommendation: "Rotate the key and ensure it's stored in a secure vault.",
    },
    SecretPattern {
        name: "Auth Token",
        pattern: r#"(?i)\b(?:auth[_\-]?token|authtoken)\b\s*[=:]\s*["'`]([a-zA-Z0-9_\-\.]{16,64})["'`]"#,
        severity: "Medium",
        recommendation: "Revoke the token and issue a new one.",
    },
    SecretPattern {
        name: "Access Token",
        pattern: r#"(?i)\b(?:access[_\-]?token|accesstoken)\b\s*[=:]\s*["'`]([a-zA-Z0-9_\-\.]{16,64})["'`]"#,
        severity: "Medium",
        recommendation: "Revoke and regenerate the token.",
    },
    SecretPattern {
        name: "Encryption Key",
        pattern: r#"(?i)(?:encryption|aes|des|blowfish)[\s_-]?key[\s=:]+["'`][A-Za-z0-9+/]{16,}={0,2}["'`]"#,
        severity: "High",
        recommendation: "Rotate the key and store it securely using a key management system.",
    },
    SecretPattern {
        name: "Stripe Publishable Key",
        pattern: r"\bpk_(live|test)_[0-9a-zA-Z]{24,34}\b",
        severity: "Low",
        recommendation:
            "Publishable keys are public, but verify no secret keys are exposed nearby.",
    },
    SecretPattern {
        name: "Twitter Bearer",
        pattern: r"AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+",
        severity: "Medium",
        recommendation: "Rotate the bearer token. Use environment variables for storage.",
    },
    SecretPattern {
        name: "Password",
        pattern: r#"(?i)(?:password|passwd|pwd)[\s=:]+["'`]([^"'`\s]{8,64})["'`]"#,
        severity: "High",
        recommendation:
            "Remove hardcoded passwords. Use a secrets manager or environment variables.",
    },
    SecretPattern {
        name: "Database Credentials",
        pattern: r#"(?i)(?:db_pass|db_password|database_password)[\s=:]+["'`]([^"'`\s]+)["'`]"#,
        severity: "High",
        recommendation: "Change DB credentials immediately. Store in env vars or a vault.",
    },
];

// ── JS vulnerability patterns ───────────────────────────────────────────────

struct JsVulnCategory {
    name: &'static str,
    severity: &'static str,
    patterns: &'static [&'static str],
    description: &'static str,
    recommendation: &'static str,
}

const JS_VULN_CATEGORIES: &[JsVulnCategory] = &[
    JsVulnCategory {
        name: "DOM XSS",
        severity: "High",
        patterns: &[
            r"document\.write\s*\(\s*.*?(?:location|URL|documentURI|referrer|href|search|hash)",
            r"\.innerHTML\s*=\s*.*?(?:location|URL|documentURI|referrer|href|search|hash)",
            r"\.outerHTML\s*=\s*.*?(?:location|URL|documentURI|referrer|href|search|hash)",
            r"eval\s*\(\s*.*?(?:location|URL|documentURI|referrer|href|search|hash)",
        ],
        description:
            "DOM-based XSS: user-controllable data passed to a dynamic code execution sink.",
        recommendation:
            "Sanitize all user inputs before DOM operations. Use DOMPurify or a strict CSP.",
    },
    JsVulnCategory {
        name: "Open Redirect",
        severity: "High",
        patterns: &[
            r"(?:window\.)?location(?:\.href)?\s*=\s*.*?(?:user|input|param|arg)",
            r"(?:window\.)?location\.replace\s*\(\s*.*?(?:user|input|param|arg)",
            r"(?:window\.)?location\.assign\s*\(\s*.*?(?:user|input|param|arg)",
        ],
        description: "User input determines redirect destination, enabling phishing attacks.",
        recommendation: "Implement a whitelist of allowed redirect URLs.",
    },
    JsVulnCategory {
        name: "CORS Misconfiguration",
        severity: "Medium",
        patterns: &[
            r"Access-Control-Allow-Origin\s*:\s*\*",
            r"Access-Control-Allow-Origin\s*:\s*null",
            r"Access-Control-Allow-Credentials\s*:\s*true",
        ],
        description: "CORS misconfiguration can allow unauthorized cross-origin access.",
        recommendation: "Be specific with CORS policies. Avoid wildcard origins.",
    },
    JsVulnCategory {
        name: "Insecure Cookie",
        severity: "Medium",
        patterns: &[r"document\.cookie\s*="],
        description: "Cookies set without secure flags can be vulnerable to theft.",
        recommendation: "Set 'Secure' and 'HttpOnly' flags on sensitive cookies.",
    },
    JsVulnCategory {
        name: "Insecure Data Transmission",
        severity: "Medium",
        patterns: &[r#"\.postMessage\([^,]+,\s*["']\*["']\)"#],
        description: "Data transmitted insecurely via postMessage with wildcard origin.",
        recommendation: "Use specific origin URLs with postMessage() and validate senders.",
    },
    JsVulnCategory {
        name: "Prototype Pollution",
        severity: "Medium",
        patterns: &[r"__proto__\s*[=\[]", r"prototype\["],
        description: "Prototype pollution can lead to property injection attacks.",
        recommendation:
            "Avoid user-controlled data with Object.assign()/prototype. Use Object.create(null).",
    },
    JsVulnCategory {
        name: "Command Injection",
        severity: "High",
        patterns: &[
            r"exec\s*\(\s*.*?(?:user|input|param|arg)",
            r"spawn\s*\(\s*.*?(?:user|input|param|arg)",
        ],
        description: "Command injection allows attackers to execute arbitrary commands.",
        recommendation: "Avoid executing commands with user input. Implement strict validation.",
    },
    JsVulnCategory {
        name: "Insecure Data Storage",
        severity: "Low",
        patterns: &[
            r"localStorage\.setItem\(\s*[^,]+,\s*.*?(?:password|token|key|secret|credentials)",
            r"sessionStorage\.setItem\(\s*[^,]+,\s*.*?(?:password|token|key|secret|credentials)",
        ],
        description: "Sensitive data stored insecurely in client-side storage.",
        recommendation: "Don't store sensitive info in localStorage/sessionStorage.",
    },
    JsVulnCategory {
        name: "Event Handler XSS",
        severity: "Medium",
        patterns: &[r#"\.setAttribute\(["']on\w+["']\s*,"#],
        description: "Event handlers assigned dynamically can lead to XSS.",
        recommendation: "Validate and sanitize data before assigning to event handlers.",
    },
    JsVulnCategory {
        name: "CSP Bypass",
        severity: "Medium",
        patterns: &[r#"document\.createElement\(["']script["']\)"#],
        description: "Dynamic script creation may bypass Content Security Policy.",
        recommendation: "Implement a strict CSP and avoid dynamic script creation with user input.",
    },
    JsVulnCategory {
        name: "WebSocket Insecurity",
        severity: "High",
        patterns: &[r#"new\s+WebSocket\(\s*["']ws://"#],
        description: "Insecure WebSocket connections (ws://) can be intercepted.",
        recommendation: "Use secure WebSocket connections (wss://) and validate data.",
    },
    JsVulnCategory {
        name: "Insecure Crypto",
        severity: "High",
        patterns: &[
            r#"(?:createHash|crypto\.subtle).*?["'](?:md5|sha1)["']"#,
            r"Math\.random\(\)",
        ],
        description: "Weak cryptographic methods (MD5/SHA1/Math.random) in use.",
        recommendation:
            "Use modern crypto algorithms. Use crypto.getRandomValues() instead of Math.random().",
    },
    JsVulnCategory {
        name: "Path Traversal",
        severity: "Medium",
        patterns: &[r"\.\./|\.\.\\"],
        description: "Path traversal allows access to files outside the intended directory.",
        recommendation: "Validate and sanitize file paths. Use allowlists.",
    },
];

// ── SSRF parameters ─────────────────────────────────────────────────────────

const SSRF_PARAMS: &[&str] = &[
    "url",
    "uri",
    "link",
    "src",
    "href",
    "target",
    "destination",
    "redirect",
    "redirect_to",
    "redirecturl",
    "redirect_uri",
    "return",
    "return_to",
    "returnurl",
    "return_path",
    "path",
    "load",
    "file",
    "filename",
    "folder",
    "folder_url",
    "image",
    "img",
    "image_url",
    "image_path",
    "avatar",
    "document",
    "doc",
    "document_url",
    "fetch",
    "get",
    "view",
    "content",
    "domain",
    "callback",
    "reference",
    "site",
    "page",
    "data",
    "data_url",
    "resource",
    "template",
    "api_endpoint",
    "endpoint",
    "proxy",
    "feed",
    "host",
    "webhook",
    "address",
    "media",
    "video",
    "audio",
    "download",
    "upload",
    "preview",
    "source",
    "location",
    "goto",
    "callback_url",
    "forward",
    "next",
    "origin",
    "continue",
];

// ── Main scanner ────────────────────────────────────────────────────────────

pub async fn scan_content(
    domain: &str,
) -> Result<ScannerResult, Box<dyn std::error::Error + Send + Sync>> {
    let base_url = if domain.starts_with("http") {
        domain.to_string()
    } else {
        format!("https://{}", domain)
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()?;

    let mut secrets = Vec::new();
    let mut js_vulns = Vec::new();
    let mut ssrf_findings = Vec::new();
    let mut visited = HashSet::new();
    let mut js_file_urls = HashSet::new();
    let mut api_endpoints: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, u8)> = VecDeque::new();
    queue.push_back((base_url.clone(), 0));

    let max_depth: u8 = 2;
    let max_pages: usize = 50;

    // Compile regex patterns once
    let secret_regexes: Vec<(&SecretPattern, Regex)> = SECRET_PATTERNS
        .iter()
        .filter_map(|sp| Regex::new(sp.pattern).ok().map(|r| (sp, r)))
        .collect();

    let js_vuln_regexes: Vec<(&JsVulnCategory, Vec<Regex>)> = JS_VULN_CATEGORIES
        .iter()
        .map(|cat| {
            let rxs: Vec<Regex> = cat
                .patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect();
            (cat, rxs)
        })
        .collect();

    // API endpoint extraction patterns
    let api_regexes: Vec<Regex> = [
        r"/api/v\d+/",
        r"/api/",
        r"/graphql",
        r"/rest/",
        r"/v\d+/\w+",
        r"/service/",
        r"/json/",
        r"/rpc/",
        r"/gateway/",
        r"/ajax/",
        r"/data/",
        r"/query/",
        r"/feeds/",
        r"/svc/",
        r"/soap/",
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect();

    // ── Parse robots.txt ─────────────────────────────────────────────
    let mut disallowed: Vec<String> = Vec::new();
    let robots_url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&robots_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                let mut agent_match = false;
                for line in body.lines() {
                    let line = line.trim().to_lowercase();
                    if let Some(agent) = line.strip_prefix("user-agent:") {
                        let agent = agent.trim();
                        agent_match = agent == "*";
                    }
                    if agent_match {
                        if let Some(path) = line.strip_prefix("disallow:") {
                            let path = path.trim();
                            if !path.is_empty() {
                                disallowed.push(path.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Process sitemap.xml for seed URLs ─────────────────────────────
    let sitemap_url = format!("{}/sitemap.xml", base_url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&sitemap_url).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                let loc_rx = Regex::new(r"<loc>([^<]+)</loc>").unwrap();
                for cap in loc_rx.captures_iter(&body) {
                    if let Some(url) = cap.get(1) {
                        let u = url.as_str().to_string();
                        if is_same_domain(&base_url, &u) && !visited.contains(&u) {
                            queue.push_back((u, 1));
                        }
                    }
                }
            }
        }
    }

    // ── BFS Crawl ───────────────────────────────────────────────────────
    while let Some((url, depth)) = queue.pop_front() {
        if visited.len() >= max_pages || depth > max_depth || visited.contains(&url) {
            continue;
        }

        // Respect robots.txt disallow rules
        let url_path = url.trim_start_matches(&base_url);
        if disallowed.iter().any(|d| url_path.starts_with(d.as_str())) {
            continue;
        }

        visited.insert(url.clone());

        // Check URL parameters for SSRF-vulnerable names
        check_url_params_ssrf(&url, &mut ssrf_findings);

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !resp.status().is_success() {
            continue;
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let body = match resp.text().await {
            Ok(t) => t,
            Err(_) => continue,
        };

        // Scan this page's content for secrets
        scan_for_secrets(&body, &url, &secret_regexes, &mut secrets);

        // Extract API endpoints from the body
        extract_api_endpoints(&body, &base_url, &api_regexes, &mut api_endpoints);

        if content_type.contains("text/html") {
            let doc = Html::parse_document(&body);

            // ── Extract & queue links ───────────────────────────────────
            if depth < max_depth {
                let a_sel = Selector::parse("a[href]").unwrap();
                for el in doc.select(&a_sel) {
                    if let Some(href) = el.value().attr("href") {
                        let abs = resolve_url(&base_url, href);
                        if let Some(abs_url) = abs {
                            if is_same_domain(&base_url, &abs_url) && !visited.contains(&abs_url) {
                                queue.push_back((abs_url, depth + 1));
                            }
                        }
                    }
                }
            }

            // ── Extract inline JS & external JS URLs ────────────────────
            let script_sel = Selector::parse("script").unwrap();
            for el in doc.select(&script_sel) {
                // Inline JS
                let inline = el.text().collect::<String>();
                if inline.len() > 10 {
                    scan_js_security(&inline, &url, &js_vuln_regexes, &mut js_vulns);
                    scan_for_secrets(&inline, &url, &secret_regexes, &mut secrets);
                }
                // External JS src
                if let Some(src) = el.value().attr("src") {
                    if let Some(js_url) = resolve_url(&base_url, src) {
                        if !is_known_library(&js_url) {
                            js_file_urls.insert(js_url);
                        }
                    }
                }
            }

            // ── Check forms for SSRF-vulnerable params ──────────────────
            let form_sel = Selector::parse("form").unwrap();
            let input_sel = Selector::parse("input[name], textarea[name]").unwrap();
            for form in doc.select(&form_sel) {
                let mut vuln_params = Vec::new();
                for input in form.select(&input_sel) {
                    if let Some(name) = input.value().attr("name") {
                        let name_lower = name.to_lowercase();
                        if SSRF_PARAMS.iter().any(|p| name_lower.contains(p)) {
                            vuln_params.push(name.to_string());
                        }
                    }
                }
                if !vuln_params.is_empty() {
                    ssrf_findings.push(SsrfFinding {
                        finding_type: "Potential SSRF in Form".into(),
                        severity: "Medium".into(),
                        source_url: url.clone(),
                        vulnerable_params: vuln_params,
                        description: "Form contains fields that could be used for Server-Side Request Forgery.".into(),
                    });
                }
            }

            // ── Check meta CSP for weak policies ────────────────────────
            let meta_sel =
                Selector::parse(r#"meta[http-equiv="Content-Security-Policy"]"#).unwrap();
            for meta in doc.select(&meta_sel) {
                if let Some(content) = meta.value().attr("content") {
                    let c_lower = content.to_lowercase();
                    if c_lower.contains("unsafe-inline") || c_lower.contains("unsafe-eval") {
                        js_vulns.push(JsVulnerability {
                            vuln_type: "Weak CSP".into(),
                            severity: "Medium".into(),
                            source_url: url.clone(),
                            matched_code: content.to_string(),
                            description: "CSP allows unsafe-inline or unsafe-eval.".into(),
                            recommendation: "Remove unsafe-inline and unsafe-eval from your CSP."
                                .into(),
                        });
                    }
                }
            }

            // ── Check forms for missing CSRF tokens ─────────────────────
            let csrf_sel = Selector::parse(
                r#"input[name*="csrf" i], input[name*="xsrf" i], input[name*="token" i]"#,
            )
            .unwrap();
            for form in doc.select(&form_sel) {
                if form.select(&csrf_sel).next().is_none() {
                    js_vulns.push(JsVulnerability {
                        vuln_type: "Missing CSRF Protection".into(),
                        severity: "Medium".into(),
                        source_url: url.clone(),
                        matched_code: String::new(),
                        description: "Form found without CSRF token.".into(),
                        recommendation: "Add CSRF tokens to all state-changing forms.".into(),
                    });
                }
            }
        } else if (content_type.contains("javascript") || url.ends_with(".js"))
            && !is_known_library(&url) {
                js_file_urls.insert(url.clone());
                scan_js_security(&body, &url, &js_vuln_regexes, &mut js_vulns);
                scan_for_secrets(&body, &url, &secret_regexes, &mut secrets);
            }
    }

    // ── Fetch & analyze external JS files ────────────────────────────────
    for js_url in &js_file_urls {
        if visited.contains(js_url) {
            continue;
        }
        if let Ok(resp) = client.get(js_url).send().await {
            if resp.status().is_success() {
                if let Ok(js_body) = resp.text().await {
                    if js_body.len() > 10 {
                        scan_js_security(&js_body, js_url, &js_vuln_regexes, &mut js_vulns);
                        scan_for_secrets(&js_body, js_url, &secret_regexes, &mut secrets);
                        extract_api_endpoints(
                            &js_body,
                            &base_url,
                            &api_regexes,
                            &mut api_endpoints,
                        );
                    }
                }
            }
        }
    }

    // ── Probe discovered API endpoints for SSRF ─────────────────────────
    let ssrf_probes = payloads::lines(payloads::SSRF);
    for endpoint in api_endpoints.iter().take(20) {
        // limit to 20 to avoid flooding
        for probe in ssrf_probes.iter().take(5) {
            // top 5 probes per endpoint
            let test_url = format!("{}?url={}", endpoint, probe);
            if let Ok(resp) = client.get(&test_url).header("Accept", "*/*").send().await {
                // Check if response indicates SSRF (redirect to our probe)
                if resp.status().is_redirection() {
                    if let Some(loc) = resp.headers().get("location") {
                        if let Ok(loc_str) = loc.to_str() {
                            if loc_str.contains(probe) {
                                ssrf_findings.push(SsrfFinding {
                                    finding_type: "Confirmed SSRF in API Endpoint".into(),
                                    severity: "High".into(),
                                    source_url: endpoint.clone(),
                                    vulnerable_params: vec!["url".into()],
                                    description: format!(
                                        "API endpoint redirects to SSRF probe: {}",
                                        loc_str
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Deduplicate ─────────────────────────────────────────────────────
    dedup_secrets(&mut secrets);
    dedup_js_vulns(&mut js_vulns);

    let api_list: Vec<String> = api_endpoints.into_iter().collect();

    let summary = ScanSummary {
        total_urls_crawled: visited.len(),
        total_js_files: js_file_urls.len(),
        total_api_endpoints: api_list.len(),
        secrets_count: secrets.len(),
        js_vulnerabilities_count: js_vulns.len(),
        ssrf_vulnerabilities_count: ssrf_findings.len(),
    };

    Ok(ScannerResult {
        domain: domain.to_string(),
        secrets,
        js_vulnerabilities: js_vulns,
        ssrf_vulnerabilities: ssrf_findings,
        api_endpoints_discovered: api_list,
        summary,
    })
}

// ── Scanner sub-functions ───────────────────────────────────────────────────

fn scan_for_secrets(
    content: &str,
    source_url: &str,
    patterns: &[(&SecretPattern, Regex)],
    results: &mut Vec<SecretFinding>,
) {
    for (sp, rx) in patterns {
        for m in rx.find_iter(content) {
            let value = m.as_str();
            let line = content[..m.start()].matches('\n').count() + 1;
            let entropy = shannon_entropy(value);

            // Skip low-entropy matches for key-type secrets
            if matches!(
                sp.name,
                "AWS Secret Key" | "Google API Key" | "API Key" | "Secret Key"
            ) && entropy < 3.5
            {
                continue;
            }

            // Context-based false positive check
            let ctx_start = m.start().saturating_sub(80);
            let ctx_end = (m.end() + 80).min(content.len());
            let context = &content[ctx_start..ctx_end];
            if is_false_positive_context(context) {
                continue;
            }

            results.push(SecretFinding {
                secret_type: sp.name.to_string(),
                severity: sp.severity.to_string(),
                masked_value: mask_secret(value),
                source_url: source_url.to_string(),
                line,
                entropy: (entropy * 100.0).round() / 100.0,
                recommendation: sp.recommendation.to_string(),
            });
        }
    }
}

fn scan_js_security(
    content: &str,
    source_url: &str,
    categories: &[(&JsVulnCategory, Vec<Regex>)],
    results: &mut Vec<JsVulnerability>,
) {
    // Skip analysis on very large minified files for non-critical checks
    let is_minified = content.len() > 5000 && content.matches('\n').count() < 50;

    for (cat, rxs) in categories {
        // For minified files, only check high-severity issues
        if is_minified && cat.severity != "High" {
            continue;
        }

        for rx in rxs {
            for m in rx.find_iter(content) {
                let matched = m.as_str();
                // Limit matched_code length
                let display = if matched.len() > 200 {
                    &matched[..200]
                } else {
                    matched
                };

                results.push(JsVulnerability {
                    vuln_type: cat.name.to_string(),
                    severity: cat.severity.to_string(),
                    source_url: source_url.to_string(),
                    matched_code: display.to_string(),
                    description: cat.description.to_string(),
                    recommendation: cat.recommendation.to_string(),
                });
            }
        }
    }
}

fn dedup_secrets(v: &mut Vec<SecretFinding>) {
    let mut seen = HashSet::new();
    v.retain(|s| {
        seen.insert(format!(
            "{}:{}:{}",
            s.secret_type, s.source_url, s.masked_value
        ))
    });
}

fn dedup_js_vulns(v: &mut Vec<JsVulnerability>) {
    let mut seen = HashSet::new();
    v.retain(|j| {
        seen.insert(format!(
            "{}:{}:{}",
            j.vuln_type, j.source_url, j.matched_code
        ))
    });
}

fn check_url_params_ssrf(url: &str, findings: &mut Vec<SsrfFinding>) {
    if let Some(query_start) = url.find('?') {
        let query = &url[query_start + 1..];
        let mut vuln_params = Vec::new();
        for pair in query.split('&') {
            if let Some(eq) = pair.find('=') {
                let param = pair[..eq].to_lowercase();
                if SSRF_PARAMS.iter().any(|p| param.contains(p)) {
                    vuln_params.push(pair[..eq].to_string());
                }
            }
        }
        if !vuln_params.is_empty() {
            findings.push(SsrfFinding {
                finding_type: "Potential SSRF in URL Parameter".into(),
                severity: "Medium".into(),
                source_url: url.to_string(),
                vulnerable_params: vuln_params,
                description: "URL contains parameters that could be used for SSRF.".into(),
            });
        }
    }
}

fn extract_api_endpoints(
    content: &str,
    base_url: &str,
    patterns: &[Regex],
    endpoints: &mut HashSet<String>,
) {
    for rx in patterns {
        for m in rx.find_iter(content) {
            let path = m.as_str();
            let full_url = format!("{}{}", base_url.trim_end_matches('/'), path);
            endpoints.insert(full_url);
        }
    }
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

fn is_same_domain(base: &str, url: &str) -> bool {
    let extract_host = |u: &str| -> String {
        u.trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .to_lowercase()
    };
    extract_host(base) == extract_host(url)
}
