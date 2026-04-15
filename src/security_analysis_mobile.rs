use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

pub async fn analyze_security(
    _domain: &str,
    _progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<SecurityAnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
    Err(crate::error::WebAnalyzerError::UnsupportedPlatform("Mobile integration via native networking is pending implementation.".into()).into())
}
