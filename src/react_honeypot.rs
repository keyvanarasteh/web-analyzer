//! # React2Shell Honeypot — Attack Vector Detection & Attacker Intelligence
//!
//! A realistic React Server Components (RSC) honeypot that detects **45+ attack
//! vectors** while silently collecting comprehensive attacker intelligence.
//!
//! ## Capabilities
//!
//! - **Attack Detection** — SQLi, XSS, SSRF, SSTI, LFI/RFI, command injection,
//!   NoSQLi, XXE, deserialization, JWT attacks, GraphQL injection, CRLF, path
//!   traversal, prototype pollution, and 30+ more categories
//! - **Attacker Profiling** — IP, GeoIP, User-Agent, OS/browser fingerprint,
//!   request cadence, technique enumeration, session correlation
//! - **Realistic RSC Simulation** — Fake Server Action endpoints, plausible error
//!   messages, timing jitter, progressive response sizes
//! - **Structured Intelligence** — JSON-serializable event logs, severity
//!   scoring, risk classification, MITRE ATT&CK mapping

use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ═════════════════════════════════════════════════════════════════════════════
// Core Types
// ═════════════════════════════════════════════════════════════════════════════

/// Severity level for a detected attack.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

/// An individual detected attack event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEvent {
    /// Unique event ID (UUIDv4-style timestamp-based).
    pub event_id: String,
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// Attack category (e.g. "sqli", "xss", "ssrf").
    pub category: String,
    /// Sub-category or specific technique.
    pub subcategory: String,
    /// The matched payload/pattern excerpt.
    pub matched_payload: String,
    /// Full incoming payload (truncated for storage).
    pub full_payload: String,
    /// HTTP method used.
    pub method: String,
    /// Request path/endpoint targeted.
    pub path: String,
    /// Severity assessment.
    pub severity: Severity,
    /// MITRE ATT&CK technique ID.
    pub mitre_id: Option<String>,
    /// The honeypot's simulated response code.
    pub simulated_response: u16,
    /// IP address of the attacker.
    pub attacker_ip: String,
    /// Raw User-Agent header.
    pub user_agent: String,
    /// All captured headers (sanitized).
    pub headers: HashMap<String, String>,
    /// Session tracking ID (cookie or fingerprint).
    pub session_id: Option<String>,
    /// Confidence score (0.0–1.0) that this is an actual attack.
    pub confidence: f64,
}

/// Accumulated profile of an attacker across multiple requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerProfile {
    /// Unique profile ID (derived from IP + fingerprint).
    pub profile_id: String,
    /// IP address.
    pub ip: String,
    /// GeoIP country code (if resolved).
    pub country: Option<String>,
    /// GeoIP ASN/organization.
    pub asn: Option<String>,
    /// Whether the IP is a known Tor exit node.
    pub is_tor: bool,
    /// Whether the IP belongs to a known cloud provider.
    pub is_cloud: bool,
    /// Whether the connection came through a proxy.
    pub is_proxy: bool,
    /// User-Agent string from the first request.
    pub user_agent: String,
    /// Parsed browser/OS fingerprint.
    pub browser_fingerprint: Option<BrowserFingerprint>,
    /// First-seen timestamp.
    pub first_seen: String,
    /// Last-seen timestamp.
    pub last_seen: String,
    /// Total requests sent.
    pub total_requests: u64,
    /// Count per attack category.
    pub attack_categories: HashMap<String, u64>,
    /// Techniques observed.
    pub techniques_used: Vec<String>,
    /// Average request interval (seconds).
    pub avg_request_interval: f64,
    /// Whether the attacker appears automated (bot/script).
    pub is_automated: bool,
    /// Cumulative risk score (0–100).
    pub risk_score: f64,
    /// List of targeted endpoints.
    pub targets: Vec<String>,
    /// Timeline of detected events.
    pub event_timeline: Vec<String>,
}

/// Parsed browser and OS information from User-Agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFingerprint {
    pub browser: String,
    pub browser_version: String,
    pub os: String,
    pub os_version: String,
    pub engine: String,
    pub device_type: String,
    pub is_headless: bool,
}

/// Configuration for the honeypot engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotConfig {
    /// Maximum payload size to store (bytes).
    pub max_payload_store: usize,
    /// Whether to simulate realistic RSC timing delays.
    pub realistic_timing: bool,
    /// Minimum simulated delay (ms).
    pub min_delay_ms: u64,
    /// Maximum simulated delay (ms).
    pub max_delay_ms: u64,
    /// Whether to respond with fake RSC content.
    pub fake_rsc_responses: bool,
    /// Whether to track sessions via cookie/fingerprint.
    pub session_tracking: bool,
    /// Session cookie name to set.
    pub session_cookie: String,
    /// Whether to log all requests (not just attacks).
    pub log_all_requests: bool,
    /// Confidence threshold for considering a detection as an attack.
    pub detection_threshold: f64,
    /// Whether to simulate progressive response sizes (keep attackers engaged).
    pub progressive_sizing: bool,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            max_payload_store: 8192,
            realistic_timing: true,
            min_delay_ms: 20,
            max_delay_ms: 180,
            fake_rsc_responses: true,
            session_tracking: true,
            session_cookie: "__Host-RSC-ID".to_string(),
            log_all_requests: false,
            detection_threshold: 0.5,
            progressive_sizing: true,
        }
    }
}

/// The complete honeypot state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotState {
    pub config: HoneypotConfig,
    pub total_requests: u64,
    pub total_attacks_detected: u64,
    pub unique_attackers: usize,
    pub attack_events: Vec<AttackEvent>,
    pub attacker_profiles: HashMap<String, AttackerProfile>,
    pub uptime_seconds: f64,
    pub requests_per_minute: f64,
}

/// Result of analyzing a single request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// All attack vectors detected in the request.
    pub detections: Vec<AttackEvent>,
    /// The simulated HTTP response status code.
    pub simulated_status: u16,
    /// The simulated response body.
    pub simulated_body: String,
    /// Recommended content-type for the response.
    pub content_type: String,
    /// Whether the request should be blocked.
    pub should_block: bool,
    /// Suggested delay before responding (ms).
    pub suggested_delay_ms: u64,
}

/// Raw request input for analysis.
#[derive(Debug, Clone)]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub body: String,
    pub headers: HashMap<String, String>,
    pub ip: String,
    pub timestamp: chrono::DateTime<Utc>,
}

// ═════════════════════════════════════════════════════════════════════════════
// Attack Vector Definitions (45+ Categories)
// ═════════════════════════════════════════════════════════════════════════════

/// Definition of a single attack vector detector.
struct AttackVector {
    category: &'static str,
    subcategory: &'static str,
    patterns: &'static [&'static str],
    severity: Severity,
    mitre_id: &'static str,
    /// Where to search: "body", "query", "path", "headers", "all"
    search_location: &'static str,
    /// Additional context keywords that must also be present (AND logic).
    context_keywords: &'static [&'static str],
}

/// All 45+ attack vector definitions.
fn attack_vectors() -> &'static [AttackVector] {
    use Severity::*;
    static VECTORS: std::sync::OnceLock<Vec<AttackVector>> = std::sync::OnceLock::new();
    VECTORS.get_or_init(|| vec![
            // ── SQL Injection (Classic, Union, Blind, Error, Stacked, Time) ──
            AttackVector {
                category: "sqli", subcategory: "classic_tautology", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)('|\%27)\s*(OR|AND)\s*('|\%27)?\s*\d+\s*=\s*\d+",
                    r"(?i)('|\%27)\s*(OR|AND)\s*('|\%27)?\s*'\d+'\s*=\s*'\d+'",
                    r"(?i)(OR|AND)\s+\d+\s*=\s*\d+\s*--",
                    r"(?i)admin'\s*(--|#|/\*)",
                    r#"(?i)['"]\s*OR\s+1\s*=\s*1\s*--"#,
                    r"(?i)'\s*OR\s+'1'\s*=\s*'1",
                ],
            },
            AttackVector {
                category: "sqli", subcategory: "union_select", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)UNION\s+(ALL\s+)?SELECT\s+(NULL|@@|\d+|user\b|database\b)",
                    r"(?i)UNION\s+(ALL\s+)?SELECT\s+(NULL|@@|\d+|user\b|database\b).*--",
                    r"(?i)'\s*UNION\s+SELECT\s+.*FROM\s+",
                ],
            },
            AttackVector {
                category: "sqli", subcategory: "blind_time", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(SLEEP|pg_sleep|WAITFOR\s+DELAY|dbms_lock\.sleep|benchmark)\s*\(.*\d+",
                    r"(?i)AND\s+(SLEEP|pg_sleep|WAITFOR)\s*\(\s*\d+\s*\)",
                    r"(?i)'\s*AND\s+(SELECT\s+.*FROM\s+.*SLEEP)",
                ],
            },
            AttackVector {
                category: "sqli", subcategory: "error_based", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)extractvalue\s*\(\s*\d+\s*,\s*concat\s*\(",
                    r"(?i)updatexml\s*\(\s*\d+\s*,\s*concat\s*\(",
                    r"(?i)convert\s*\(.*using\s+",
                    r"(?i)AND\s+1\s*=\s*CONVERT\s*\(int",
                ],
            },
            AttackVector {
                category: "sqli", subcategory: "stacked", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i);\s*(DROP|INSERT|UPDATE|DELETE|ALTER|CREATE|EXEC|TRUNCATE|SHUTDOWN)\s+",
                    r"(?i)';\s*(DROP|INSERT|UPDATE|DELETE)\s+",
                    r"(?i);\s*EXEC\s+(sp_|xp_)",
                ],
            },
            // ── NoSQL Injection ──
            AttackVector {
                category: "nosqli", subcategory: "mongodb", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)\{\s*"\$ne"\s*:\s*""#,
                    r#"(?i)\{\s*"\$gt"\s*:\s*""#,
                    r#"(?i)\{\s*"\$regex"\s*:\s*".*"\s*\}"#,
                    r#"(?i)\{\s*"\$where"\s*:\s*""#,
                    r#"(?i)"\$(eq|ne|gt|gte|lt|lte|in|nin|regex|exists|type|mod|text|search|where)"\s*:"#,
                    r"(?i)\{\s*'\$ne'\s*:\s*",
                ],
            },
            AttackVector {
                category: "nosqli", subcategory: "redis_injection", severity: High,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(\r\n|\n)\s*(CONFIG|SET|GET|FLUSHALL|KEYS|SAVE|SHUTDOWN|SLAVEOF)\s",
                    r"(?i)%0[dD]%0[aA]\s*(CONFIG|SET|FLUSHALL)",
                ],
            },
            // ── Cross-Site Scripting (XSS) ──
            AttackVector {
                category: "xss", subcategory: "reflected", severity: High,
                mitre_id: "T1059.007",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)<script[^>]*>.*</script>",
                    r"(?i)<script[^>]*>.*",
                    r#"(?i)javascript\s*:\s*(alert|prompt|confirm)\s*\("#,
                    r#"(?i)"><script[^>]*>alert\("#,
                    r#"(?i)<img[^>]+onerror\s*=\s*[`'\"]?\w+"#,
                    r#"(?i)<svg[^>]+onload\s*=\s*[`'\"]?\w+"#,
                ],
            },
            AttackVector {
                category: "xss", subcategory: "polyglot", severity: High,
                mitre_id: "T1059.007",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)jaVasCript:/*-/*`/*\`/*'/*"/**/(\s*/\*\s*/.*\)\s*;)"#,
                    r#"(?i)"\s*;\s*alert\s*\(.*\)\s*//"#,
                ],
            },
            AttackVector {
                category: "xss", subcategory: "stored_payload", severity: High,
                mitre_id: "T1059.007",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)<iframe[^>]*srcdoc\s*=\s*[`'\"]?\s*<script"#,
                    r#"(?i)<object[^>]*data\s*=\s*[`'\"]?data:text/html"#,
                    r#"(?i)<embed[^>]*src\s*=\s*[`'\"]?data:text/html"#,
                ],
            },
            // ── Command Injection ──
            AttackVector {
                category: "cmdi", subcategory: "unix_pipe", severity: Critical,
                mitre_id: "T1059.004",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?m)[\|\;`]\s*(id|whoami|ls|cat|pwd|uname|hostname)\s*$",
                    r"(?m)\$\(\s*(id|whoami|ls|cat|wget|curl)\s*",
                    r"(?m)`\s*(id|whoami|ls|cat)\s*`",
                    r"(?m)\|\|\s*(id|whoami|ls|cat|ping)\s",
                    r"(?m)&&\s*(id|whoami|ls|cat|ping)\s",
                    r"(?m);\s*(id|whoami|ls|cat|ping|sleep)\s",
                ],
            },
            AttackVector {
                category: "cmdi", subcategory: "unix_advanced", severity: Critical,
                mitre_id: "T1059.004",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?m)(/usr/bin/|/bin/|/sbin/)(id|whoami|ls|cat|bash|sh|nc|wget|curl)",
                    r"(?m)\|\s*(nc|ncat|netcat)\s",
                    r"(?m)\|\s*(wget|curl)\s+http",
                    r"(?m);\s*/bin/(bash|sh|dash)\s+-[ci]",
                    r"(?m);\s*(chmod|chown)\s",
                ],
            },
            AttackVector {
                category: "cmdi", subcategory: "windows", severity: Critical,
                mitre_id: "T1059.003",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)[\|\;`]\s*(whoami|systeminfo|ipconfig|net\s+user|tasklist)\b",
                    r"(?i)cmd\.exe\s+/[cCkK]\s+",
                    r"(?i)powershell\.exe\s+-[eE][xX]",
                    r"(?i)%(COMSPEC|SystemRoot|WINDIR)%",
                    r"(?i)certutil\s+-urlcache\s+-split\s+-f\s+http",
                ],
            },
            AttackVector {
                category: "cmdi", subcategory: "blind_oob", severity: Critical,
                mitre_id: "T1059.004",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?m)\|\s*(nslookup|dig|host)\s+[a-zA-Z0-9]",
                    r"(?m)ping\s+-[cnt]\s+\d+\s+[a-zA-Z0-9]",
                    r"(?m);\s*(nslookup|dig|host|ping)\s+\$\{",
                ],
            },
            // ── Path Traversal / Directory Traversal ──
            AttackVector {
                category: "path_traversal", subcategory: "dot_dot_slash", severity: High,
                mitre_id: "T1083",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(\.\./){2,}(etc|var|proc|sys|home|root|tmp|windows|winnt)",
                    r"(\.\.\\){2,}(windows|winnt|system32|boot\.ini)",
                    r"\.\./\.\./\.\./.*(passwd|shadow|hosts|\.ini|\.conf)",
                    r"\.%2e/\.%2e/",
                    r"\.%252e/\.%252e/",
                    r"\.\.%2f\.\.%2f",
                    r"\.\.%5c\.\.%5c",
                    r"file:///(etc|proc|sys|var|home)/",
                ],
            },
            AttackVector {
                category: "path_traversal", subcategory: "absolute_path", severity: High,
                mitre_id: "T1083",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"^/(etc|proc|sys|var|root|home)/.*(passwd|shadow|hosts|\.conf)",
                    r"^(C:|D:)\\(windows|winnt|system32)\\.*",
                ],
            },
            // ── LFI / RFI (Local/Remote File Inclusion) ──
            AttackVector {
                category: "lfi", subcategory: "local_include", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(file|page|path|include|require|document|folder|dir|template|module|load)\s*=\s*(\.\./|/etc/|/proc/)",
                    r"(?i)/etc/(passwd|shadow|hosts|group|sudoers|resolv\.conf)",
                    r"(?i)/proc/(self|version|cpuinfo|meminfo|cmdline)/?",
                    r"(?i)/var/log/(apache|nginx|syslog|messages|auth\.log)",
                    r"(?i)C:\\windows\\(system32|win\.ini|boot\.ini|repair\\sam)",
                    r"(?i)php://filter/convert\.base64-encode/resource=",
                    r"(?i)php://filter/read=convert\.base64-encode/resource=",
                    r"(?i)php://input",
                    r"(?i)expect://(id|whoami|ls)",
                    r"(?i)data://text/plain;base64,",
                ],
            },
            AttackVector {
                category: "rfi", subcategory: "remote_include", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(https?|ftp)://[^/\s]+/[^?\s]+\.(php|txt|jpg|png|gif)\?",
                    r"(?i)(https?|ftp)://.*(shell|backdoor|r57|c99|web-shell)",
                    r"(?i)(https?|ftp)://.*/.*\.(txt|php|asp|jsp)\?",
                ],
            },
            // ── SSRF (Server-Side Request Forgery) ──
            AttackVector {
                category: "ssrf", subcategory: "cloud_metadata", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(169\.254\.\d+\.\d+|metadata\.google\.internal|100\.100\.\d+\.\d+)",
                    r"(?i)(/latest/meta-data|/metadata/v1|/openstack)",
                    r"(?i)instance-data\.ec2\.internal",
                    r"(?i)/latest/(meta-data|dynamic|user-data)",
                    r"(?i)kubernetes\.default\.svc",
                    r"(?i)\.compute\.internal",
                ],
            },
            AttackVector {
                category: "ssrf", subcategory: "internal_ports", severity: High,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(http://|https://)(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])\s*[/:]",
                    r"(?i)(http://|https://)(10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2\d\.\d+\.\d+|172\.3[01]\.\d+\.\d+|192\.168\.\d+\.\d+)",
                ],
            },
            AttackVector {
                category: "ssrf", subcategory: "dns_rebinding", severity: Medium,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)([a-z0-9]+\.){2,}(1zero|rbndr|nip\.io|xip\.io|sslip\.io)",
                    r"(?i)(nslookup|dig|host)\s+[a-z0-9]+\.[a-z]+\.[a-z]+",
                ],
            },
            // ── XXE (XML External Entity) ──
            AttackVector {
                category: "xxe", subcategory: "external_entity", severity: Critical,
                mitre_id: "T1190",
                search_location: "body",
                context_keywords: &[],
                patterns: &[
                    r#"<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+['\"]"#,
                    r#"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+['\"]"#,
                    r"<!DOCTYPE\s+\w+\s+\[\s*<!ENTITY",
                    r"<xml[^>]*>\s*<!DOCTYPE",
                    r#"<\?xml[^?]*\?>\s*<!DOCTYPE\s+\w+\s+\["#,
                ],
            },
            AttackVector {
                category: "xxe", subcategory: "billion_laughs", severity: Critical,
                mitre_id: "T1499.002",
                search_location: "body",
                context_keywords: &[],
                patterns: &[
                    r#"<!ENTITY\s+\w+\s+['\"]<!ENTITY"#,
                    r"&(lol|lolz|lol1|lol2|laugh|boom|ha|haha);",
                ],
            },
            // ── SSTI (Server-Side Template Injection) ──
            AttackVector {
                category: "ssti", subcategory: "jinja2", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"\{\{\s*(\d+\s*[\*\+\-]\s*\d+|\w+\.\w+)",
                    r"\{\{\s*config\s*\}\}",
                    r"\{\{\s*self\s*\}\}",
                    r"\{\{\s*''\.__class__\.__mro__",
                    r"\{\{\s*lipsum\.__globals__",
                    r"\{\{\s*request\.application\.__globals__",
                    r"\{\%\s*(import|extends|include|set|for|if)\s+",
                    r"\{\{\s*cycler\.__init__\.__globals__",
                ],
            },
            AttackVector {
                category: "ssti", subcategory: "twig", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"\{\{\s*_self\.env\.registerUndefinedFilterCallback",
                    r#"\{\{\s*['\"].*['\"]\s*\|\s*map\("#,
                    r#"\{\{\s*['\"].*['\"]\s*\|\s*filter\("#,
                ],
            },
            AttackVector {
                category: "ssti", subcategory: "freemarker", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"\$\{.*\.class\.forName\(",
                    r#"<\#assign\s+ex\s*=\s*['\"]freemarker"#,
                    r"\$\{(.*\?)?new\s+java\.\w+\(",
                ],
            },
            // ── Deserialization Attacks ──
            AttackVector {
                category: "deserialization", subcategory: "java", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(ac ed 00 05|rO0AB|aced0005)",
                    r"(?i)(com\.sun\.org\.apache\.xalan|org\.apache\.commons\.collections)",
                    r"(?i)(java\.lang\.Runtime|java\.lang\.ProcessBuilder)",
                    r"(?i)(org\.springframework\.beans\.factory)",
                ],
            },
            AttackVector {
                category: "deserialization", subcategory: "php", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)(O:\d+:['\"][A-Za-z0-9_\\]+['\"]:\d+:)"#,
                    r"(?i)(a:\d+:\{.*s:\d+:)",
                    r#"(?i)(C:\d+:['\"][A-Za-z0-9_\\]+['\"]:\d+:)"#,
                ],
            },
            AttackVector {
                category: "deserialization", subcategory: "python_pickle", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(cos\\nsystem|c__builtin__\\neval|csubprocess\\nPopen)",
                    r"(?i)(__reduce__|__reduce_ex__)",
                    r"(?i)(S'((import|exec|eval)\b|__import__)",
                ],
            },
            AttackVector {
                category: "deserialization", subcategory: "nodejs", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)\{"_bsontype":"Code","code":"[^"]*require\(['"]child_process"#,
                    r#"(?i)\{"type":"Function","body":"[^"]*require\("#,
                ],
            },
            // ── JWT Attacks ──
            AttackVector {
                category: "jwt", subcategory: "none_algorithm", severity: Critical,
                mitre_id: "T1557",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)"alg"\s*:\s*"none""#,
                    r"(?i)ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.(?:$|\s|&)",
                ],
            },
            AttackVector {
                category: "jwt", subcategory: "key_confusion", severity: High,
                mitre_id: "T1557",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)"alg"\s*:\s*"HS256"[^}]*"k"\s*:"#,
                    r#"(?i)"jwk"\s*:\s*\{[^}]*"kty"\s*:"#,
                ],
            },
            // ── GraphQL Attacks ──
            AttackVector {
                category: "graphql", subcategory: "introspection", severity: Medium,
                mitre_id: "T1190",
                search_location: "body",
                context_keywords: &[],
                patterns: &[
                    r"__schema\s*\{\s*types\s*\{",
                    r#"__type\s*\(\s*name\s*:\s*\"\""#,
                    r"query\s*\{\s*__schema\{",
                    r"fragment\s+FullType\s+on\s+__Type\s*\{",
                ],
            },
            AttackVector {
                category: "graphql", subcategory: "batch_attack", severity: High,
                mitre_id: "T1190",
                search_location: "body",
                context_keywords: &[],
                patterns: &[
                    r#"\[\s*\{\s*\"query\""#,
                    r#"\"batch\"\s*:\s*\["#,
                ],
            },
            // ── Prototype Pollution ──
            AttackVector {
                category: "prototype_pollution", subcategory: "javascript", severity: High,
                mitre_id: "T1059.007",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)(__proto__|constructor|prototype)\s*=\s*["']"#,
                    r#"(?i)"__proto__"\s*:\s*\{[^}]*\}"#,
                    r#"(?i)"constructor"\s*:\s*\{[^}]*"prototype"\s*:"#,
                    r#"(?i)\[\[__proto__\]\]\s*=\s*"#,
                ],
            },
            // ── CRLF Injection ──
            AttackVector {
                category: "crlf", subcategory: "response_splitting", severity: High,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(\r\n|\%0[dD]\%0[aA])\s*Content-(Type|Length|Disposition):",
                    r"(\r\n|\%0[dD]\%0[aA])\s*Set-Cookie\s*:",
                    r"(\r\n|\%0[dD]\%0[aA])\s*(HTTP/|Location\s*:)",
                    r"(\r\n|\%0[dD]\%0[aA])\s*X-XSS-Protection\s*:",
                ],
            },
            AttackVector {
                category: "crlf", subcategory: "header_injection", severity: Medium,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(\r\n|\%0[dD]\%0[aA])\s*[A-Za-z0-9\-]+\s*:\s*[^\n]+\r?\n",
                ],
            },
            // ── HTTP Host Header / Request Smuggling ──
            AttackVector {
                category: "http_smuggling", subcategory: "cl_te", severity: High,
                mitre_id: "T1190",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)^\s*Transfer-Encoding\s*:\s*[\x0b]",
                    r"(?i)^\s*Transfer-Encoding\s*:.*\x0b",
                    r"(?i)^\s*Content-Length\s*:\s*\d+\s*\n\s*Content-Length",
                ],
            },
            AttackVector {
                category: "host_attack", subcategory: "host_injection", severity: High,
                mitre_id: "T1190",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)^\s*Host\s*:\s*(evil|attacker|malware|hack|bugbounty|pwned)\.(com|net|org|io)",
                    r"(?i)^\s*Host\s*:\s*(127\.0\.0\.1|localhost|0\.0\.0\.0)",
                    r"(?i)^\s*X-Forwarded-Host\s*:\s*(evil|attacker|127\.0\.0\.1)",
                ],
            },
            // ── File Upload Attacks ──
            AttackVector {
                category: "file_upload", subcategory: "malicious_extension", severity: Critical,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)filename\s*=\s*["'][^"']+\.(php|jsp|asp|aspx|phtml|php5|php7|shtml|cgi|pl|war|jspx)['"]#"#,
                    r#"(?i)Content-Disposition:.*filename=\\*['"][^'"]+\.(php|jsp|asp)['"]#"#,
                    r"(?i)\.php\d*\.(jpg|png|gif|pdf)",
                    r"(?i)\.(php|jsp|asp)\s*%00",
                ],
            },
            // ── Open Redirect ──
            AttackVector {
                category: "open_redirect", subcategory: "url_param", severity: Medium,
                mitre_id: "T1204.001",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(redirect|url|next|return|goto|target|dest|continue|back)\s*=\s*(https?://|//)[^&\s]+",
                    r"(?i)(redirect|url|next|return|goto)\s*=\s*(evil|attacker|phish|malw)",
                    r#"(?i)"(redirect|url|next)"\s*:\s*"(https?://|//)"#,
                ],
            },
            // ── Cookie Manipulation ──
            AttackVector {
                category: "cookie_attack", subcategory: "injection", severity: Medium,
                mitre_id: "T1539",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)Cookie\s*:\s*.*(<script|alert|onerror|javascript:)",
                    r"(?i)Cookie\s*:\s*.*(../|\.\.\\\\)",
                    r"(?i)Cookie\s*:\s*.*(SELECT|UNION)",
                ],
            },
            // ── Cache Poisoning ──
            AttackVector {
                category: "cache_poisoning", subcategory: "header_probe", severity: High,
                mitre_id: "T1499",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)^\s*X-Forwarded-(Scheme|Proto|Host|Port|Prefix)\s*:\s*(https?://)?[a-z]+",
                    r"(?i)^\s*X-Original-URL\s*:\s*",
                    r"(?i)^\s*X-Rewrite-URL\s*:\s*",
                    r"(?i)^\s*X-HTTP-Method-Override\s*:\s*",
                    r"(?i)^\s*X-Method-Override\s*:\s*",
                ],
            },
            // ── Authentication Bypass ──
            AttackVector {
                category: "auth_bypass", subcategory: "header_forgery", severity: Critical,
                mitre_id: "T1548",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)^\s*X-Forwarded-For\s*:\s*(127\.0\.0\.1|localhost|::1)",
                    r"(?i)^\s*X-Remote-IP\s*:\s*(127\.0\.0\.1|10\.\d+\.\d+\.\d+)",
                    r"(?i)^\s*X-Originating-IP\s*:\s*(127\.0\.0\.1)",
                    r"(?i)^\s*X-Real-IP\s*:\s*(127\.0\.0\.1|10\.\d+\.\d+\.\d+)",
                    r"(?i)^\s*Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]+={0,2}",
                ],
            },
            // ── HTTP Parameter Pollution ──
            AttackVector {
                category: "hpp", subcategory: "duplicate_params", severity: Medium,
                mitre_id: "T1190",
                search_location: "query",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)([?&])[^?&=]+=[^?&=]+&[^?&=]+=&"#,
                    r"(?i)([?&])[^?&=]+=[^?&=]+&(same_param)=[^?&=]+",
                ],
            },
            // ── HTTP Method Tampering ──
            AttackVector {
                category: "method_tamper", subcategory: "method_override", severity: Medium,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)_method\s*=\s*(PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT)",
                    r"(?i)X-HTTP-Method\s*:\s*(PUT|DELETE)",
                ],
            },
            // ── Null Byte Injection ──
            AttackVector {
                category: "null_byte", subcategory: "termination", severity: High,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)%00\.(php|jsp|asp|html|txt|conf)",
                    r"(?i)\.php%00",
                    r"\x00[^\x00]*\.(php|jsp|asp)",
                ],
            },
            // ── CORS Misconfiguration Probe ──
            AttackVector {
                category: "cors", subcategory: "origin_spoof", severity: Medium,
                mitre_id: "T1190",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)^\s*Origin\s*:\s*https?://(evil|attacker|null|127\.0\.0\.1)",
                    r"(?i)^\s*Origin\s*:\s*null",
                ],
            },
            // ── Brute Force / Credential Stuffing ──
            AttackVector {
                category: "brute_force", subcategory: "multi_attempt", severity: High,
                mitre_id: "T1110",
                search_location: "body",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)(password|passwd|pwd|pin|secret|token)\s*=\s*['\"][^'\"]{1,20}['\"]"#,
                    r#"(?i)\{"(email|username|user|login)"\s*:\s*"[^"]+"\s*,\s*"(password|passwd|pwd)"\s*:\s*""#,
                ],
            },
            // ── Format String ──
            AttackVector {
                category: "format_string", subcategory: "printf_injection", severity: High,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(%[0-9]*\$)?%([xXndsSph]|p[rd]){1,2}",
                    r"%[0-9]{1,2}\$[xdspnXDSPN]",
                ],
            },
            // ── Race Condition Probing ──
            AttackVector {
                category: "race_condition", subcategory: "concurrent", severity: Medium,
                mitre_id: "T1499",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(race|parallel|concurrent|thread)\s*=\s*(true|1|yes)",
                ],
            },
            // ── Clickjacking Frame Attempts ──
            AttackVector {
                category: "clickjacking", subcategory: "frame_probe", severity: Low,
                mitre_id: "T1499",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)<iframe[^>]*style\s*=\s*['\"]opacity\s*:\s*0"#,
                    r#"(?i)<iframe[^>]*width\s*=\s*['\"]\d+['\"][^>]*height\s*=\s*['\"]\d+"#,
                ],
            },
            // ── Source Map Extraction ──
            AttackVector {
                category: "source_leak", subcategory: "sourcemap_probe", severity: Low,
                mitre_id: "T1213",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(\.js\.map|\.css\.map|//#\s*sourceMappingURL)",
                    r"(?i)/_next/static/.*\.map$",
                ],
            },
            // ── React/Next.js Specific Attacks ──
            AttackVector {
                category: "rsc_attack", subcategory: "flight_injection", severity: Critical,
                mitre_id: "T1190",
                search_location: "body",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)\[\["\$","@\w+",null,\{"#,
                    r#"(?i)"type"\s*:\s*"blob_handler""#,
                    r#"(?i)"dispatch"\s*:\s*"dynamic""#,
                    r#"(?i)"method"\s*:\s*"child_process\.exec""#,
                ],
            },
            AttackVector {
                category: "rsc_attack", subcategory: "server_action_probe", severity: High,
                mitre_id: "T1190",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)^\s*Next-Action\s*:",
                    r"(?i)^\s*RSC\s*:\s*1",
                    r"(?i)^\s*Content-Type\s*:\s*text/x-component",
                    r"(?i)^\s*Next-Router-State-Tree\s*:",
                ],
            },
            AttackVector {
                category: "nextjs_probe", subcategory: "internal_route", severity: Medium,
                mitre_id: "T1190",
                search_location: "path",
                context_keywords: &[],
                patterns: &[
                    r"^/_next/.*(webpack-hmr|__nextjs_|middleware)",
                    r"^/_next/data/",
                    r"^/_next/image\?url=",
                ],
            },
            // ── WebSocket Attack Probing ──
            AttackVector {
                category: "websocket", subcategory: "injection", severity: High,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)ws://(evil|attacker|localhost|127\.0\.0\.1)",
                    r"(?i)Sec-WebSocket-Key\s*:\s*[A-Za-z0-9+/=]+",
                ],
            },
            // ── DNS Exfiltration Probing ──
            AttackVector {
                category: "dns_exfil", subcategory: "tunnel_probe", severity: High,
                mitre_id: "T1048.001",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(nslookup|dig|host)\s+\w{20,}\.[a-z]+\.[a-z]+",
                    r"(?i)\.(burpcollaborator|interact\.sh|canarytokens|oastify)\.(com|net|io|pro|live|site|online|fun)",
                ],
            },
            // ── Content-Type Confusion ──
            AttackVector {
                category: "content_type", subcategory: "mismatch_attack", severity: Medium,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)Content-Type\s*:\s*text/html.*\{.*\}.*Content-Type\s*:\s*application/json",
                ],
            },
            // ── Charset / Encoding Attacks ──
            AttackVector {
                category: "encoding_attack", subcategory: "charset_confusion", severity: Medium,
                mitre_id: "T1190",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)%u[0-9a-fA-F]{4}",
                    r"(?i)&#x[0-9a-fA-F]+;",
                    r"(?i)&#\d{2,};",
                    r"(?i)[\\]x[0-9a-fA-F]{2}",
                ],
            },
            // ── User-Agent Probing / Fake Crawlers ──
            AttackVector {
                category: "user_agent", subcategory: "fake_crawler", severity: Low,
                mitre_id: "T1592",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)User-Agent\s*:\s*.*(sqlmap|nikto|nmap|burp|nessus|wpscan|dirbuster|gobuster|hydra)",
                    r"(?i)User-Agent\s*:\s*.*(curl|wget|python|go-http|libwww|axios|node-fetch)",
                ],
            },
            // ── API Key / Token Brute Force ──
            AttackVector {
                category: "credential_probe", subcategory: "token_brute", severity: High,
                mitre_id: "T1110.001",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r"(?i)(Authorization|X-API-Key|X-Auth-Token|Bearer)\s*:\s*[A-Za-z0-9\-_\.]{20,}",
                ],
            },
            // ── Session Fixation ──
            AttackVector {
                category: "session_fixation", subcategory: "cookie_set", severity: Medium,
                mitre_id: "T1539",
                search_location: "headers",
                context_keywords: &[],
                patterns: &[
                    r"(?i)Cookie\s*:\s*(SESSID|JSESSIONID|PHPSESSID|session_id|sid|connect\.sid)\s*=\s*[A-Za-z0-9]+",
                ],
            },
            // ── CSS Injection (data exfil) ──
            AttackVector {
                category: "css_injection", subcategory: "data_exfil", severity: Medium,
                mitre_id: "T1213",
                search_location: "all",
                context_keywords: &[],
                patterns: &[
                    r#"(?i)@import\s+url\s*\(\s*['\"]?https?://"#,
                    r#"(?i)background(-image)?\s*:\s*url\s*\(\s*['\"]?https?://"#,
                    r#"input\[type\s*=\s*["']password["']\][^{]*\{[^}]*background"#,
                ],
            },
    ])
}

// ═════════════════════════════════════════════════════════════════════════════
// Honeypot Engine
// ═════════════════════════════════════════════════════════════════════════════

/// The core honeypot detection and intelligence engine.
pub struct HoneypotEngine {
    config: HoneypotConfig,
    state: HoneypotState,
    /// Per-profile request timestamps for cadence analysis.
    request_times: HashMap<String, Vec<Instant>>,
    /// Fake RSC endpoint list for realistic simulation.
    rsc_endpoints: Vec<String>,
}

impl HoneypotEngine {
    /// Create a new honeypot engine with default configuration.
    pub fn new() -> Self {
        Self::with_config(HoneypotConfig::default())
    }

    /// Create a new honeypot engine with custom configuration.
    pub fn with_config(config: HoneypotConfig) -> Self {
        Self {
            config,
            state: HoneypotState {
                config: HoneypotConfig::default(),
                total_requests: 0,
                total_attacks_detected: 0,
                unique_attackers: 0,
                attack_events: Vec::new(),
                attacker_profiles: HashMap::new(),
                uptime_seconds: 0.0,
                requests_per_minute: 0.0,
            },
            request_times: HashMap::new(),
            rsc_endpoints: vec![
                "/".to_string(),
                "/api/graphql".to_string(),
                "/api/auth/callback".to_string(),
                "/api/chat".to_string(),
                "/api/upload".to_string(),
                "/api/search".to_string(),
                "/api/admin/settings".to_string(),
                "/_rsc/__PAGE__".to_string(),
                "/dashboard".to_string(),
            ],
        }
    }

    /// Process a raw HTTP request and return detection results.
    pub fn process_request(&mut self, req: &RawRequest) -> DetectionResult {
        let _start = Instant::now();
        self.state.total_requests += 1;

        // Update request rate
        self.state.uptime_seconds = (Utc::now().timestamp_millis() as f64) / 1000.0;
        if self.state.uptime_seconds > 0.0 {
            self.state.requests_per_minute =
                (self.state.total_requests as f64 / self.state.uptime_seconds) * 60.0;
        }

        let profile_id = self.get_or_create_profile_id(req);
        self.update_request_times(&profile_id);

        // Detect attacks
        let detections = self.detect_attacks(req, &profile_id);

        let attack_count = detections.len() as u64;
        if attack_count > 0 {
            self.state.total_attacks_detected += attack_count;
            for det in &detections {
                self.state.attack_events.push(det.clone());
                // Limit stored events
                if self.state.attack_events.len() > 10000 {
                    self.state.attack_events.drain(0..1000);
                }
            }
        }

        // Update or create attacker profile
        self.update_attacker_profile(req, &profile_id, &detections);

        // Generate simulated response
        let simulated_status = self.simulate_status(&detections);
        let simulated_body = self.simulate_body(req, &detections);
        let content_type = self.simulate_content_type(req);
        let should_block = self.should_block_request(&detections);
        let suggested_delay = self.calculate_delay(&detections);

        DetectionResult {
            detections,
            simulated_status,
            simulated_body,
            content_type,
            should_block,
            suggested_delay_ms: suggested_delay.as_millis() as u64,
        }
    }

    /// Analyze all 45+ attack vectors against a request.
    fn detect_attacks(&mut self, req: &RawRequest, profile_id: &str) -> Vec<AttackEvent> {
        let mut events = Vec::new();

        for vector in attack_vectors().iter() {
            let search_text = match vector.search_location {
                "body" => &req.body,
                "query" => &req.query_string,
                "path" => &req.path,
                "headers" => &self.headers_as_string(&req.headers),
                "all" => &self.all_request_text(req),
                _ => &self.all_request_text(req),
            };

            if search_text.is_empty() {
                continue;
            }

            // Check context keywords (AND logic)
            if !vector.context_keywords.is_empty() {
                let has_context = vector.context_keywords.iter().any(|kw| {
                    search_text.to_lowercase().contains(&kw.to_lowercase())
                });
                if !has_context {
                    continue;
                }
            }

            for pattern in vector.patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if let Some(m) = re.find(search_text) {
                        let matched = m.as_str().to_string();
                        let confidence = self.calculate_confidence(vector, &matched, search_text);

                        if confidence >= self.config.detection_threshold {
                            events.push(AttackEvent {
                                event_id: Self::generate_event_id(),
                                timestamp: Utc::now().to_rfc3339(),
                                category: vector.category.to_string(),
                                subcategory: vector.subcategory.to_string(),
                                matched_payload: Self::truncate_str(&matched, 500),
                                full_payload: Self::truncate_str(
                                    search_text,
                                    self.config.max_payload_store,
                                ),
                                method: req.method.clone(),
                                path: req.path.clone(),
                                severity: vector.severity.clone(),
                                mitre_id: Some(vector.mitre_id.to_string()),
                                simulated_response: 0, // Filled later
                                attacker_ip: req.ip.clone(),
                                user_agent: req
                                    .headers
                                    .get("user-agent")
                                    .cloned()
                                    .unwrap_or_default(),
                                headers: req.headers.clone(),
                                session_id: Some(profile_id.to_string()),
                                confidence,
                            });
                            break; // One match per vector category is enough
                        }
                    }
                }
            }
        }

        // Fill simulated_response after detection
        for event in &mut events {
            event.simulated_response = self.simulate_status_for_event(event);
        }

        events
    }

    /// Calculate detection confidence based on pattern specificity and context.
    fn calculate_confidence(
        &self,
        _vector: &AttackVector,
        matched: &str,
        full_text: &str,
    ) -> f64 {
        let mut confidence = 0.5; // Base confidence

        // Longer patterns are more specific
        let specificity_bonus = (matched.len() as f64 / 30.0).min(0.3);
        confidence += specificity_bonus;

        // Multiple patterns from same category (already checked via context_keywords)
        // Count additional keyword signals
        let keyword_signals = [
            ("eval", 0.05),
            ("exec", 0.05),
            ("system", 0.05),
            ("import", 0.03),
            ("require", 0.03),
            ("base64", 0.04),
            ("fromCharCode", 0.05),
            ("String.fromCharCode", 0.06),
            ("atob", 0.03),
            ("charCodeAt", 0.03),
            ("document.cookie", 0.06),
            ("window.location", 0.04),
            ("XMLHttpRequest", 0.03),
            ("fetch(", 0.02),
            ("curl", 0.04),
            ("wget", 0.04),
            ("nc ", 0.05),
            ("/bin/bash", 0.06),
            ("/bin/sh", 0.06),
            ("cmd.exe", 0.06),
            ("powershell", 0.06),
            ("reverse", 0.04),
            ("shell", 0.05),
            ("backdoor", 0.06),
            ("trojan", 0.06),
            ("exploit", 0.05),
        ];

        let lower = full_text.to_lowercase();
        for (signal, bonus) in keyword_signals {
            if lower.contains(signal) {
                confidence += bonus;
            }
        }

        confidence.min(1.0)
    }

    /// Determine the simulated HTTP status for a detection set.
    fn simulate_status(&self, detections: &[AttackEvent]) -> u16 {
        if detections.is_empty() {
            return 200;
        }
        let has_critical = detections
            .iter()
            .any(|d| d.severity == Severity::Critical);
        let has_high = detections.iter().any(|d| d.severity == Severity::High);

        if has_critical {
            500 // Internal error — don't tip off the attacker
        } else if has_high {
            400 // Bad request
        } else {
            200 // Appear normal for low/medium severity
        }
    }

    fn simulate_status_for_event(&self, event: &AttackEvent) -> u16 {
        match event.severity {
            Severity::Critical => 500,
            Severity::High => 400,
            Severity::Medium | Severity::Low | Severity::Info => 200,
        }
    }

    /// Generate a realistic fake response body.
    fn simulate_body(&self, req: &RawRequest, _detections: &[AttackEvent]) -> String {
        if !self.config.fake_rsc_responses {
            return String::new();
        }

        // RSC endpoints get realistic Flight-protocol responses
        let is_rsc = self.rsc_endpoints.iter().any(|ep| req.path.starts_with(ep))
            || req
                .headers
                .get("content-type")
                .map(|ct| ct.contains("text/x-component"))
                .unwrap_or(false)
            || req.headers.contains_key("next-action");

        if is_rsc {
            self.generate_fake_rsc_response(req)
        } else if req.path.contains("/api/") {
            self.generate_fake_api_response(req)
        } else {
            self.generate_fake_html_response(req)
        }
    }

    /// Generate a fake React Server Components Flight-protocol response.
    fn generate_fake_rsc_response(&self, _req: &RawRequest) -> String {
        let responses = [
            r#"0:["$","@2",null,{"id":"__PAGE__","children":[["$","@3",null,{"name":"Page","props":{}}]]}]
1:{"status":"resolved","data":{"pageProps":{"title":"Dashboard","user":{"name":"Admin User","role":"administrator","email":"admin@internal.local"}}}}
2:["$","div",null,{"className":"page-wrapper","children":[["$","header",null,{"children":"Dashboard"}],["$","main",null,{"children":["$","p",null,{"children":"Welcome back, Admin User"},"$","@4",null,{}]}]]
3:{"status":"pending","chunks":["@5","@6"]}"#,
            r#"0:["$","@2",null,{"id":"__PAGE__"}]
1:{"status":"resolved","data":{"pageProps":{"items":[{"id":1,"name":"Project Alpha","status":"active","owner":"admin"},{"id":2,"name":"Project Beta","status":"inactive","owner":"user2"},{"id":3,"name":"API Gateway","status":"active","owner":"admin"}]}}}
2:"$6eb96e9c8e4a3f1b2d5c7a8e9f0a1b2c""#,
            r#"0:["$","@2",null,{"id":"__PAGE__","children":[["$","@3",null,{"name":"ErrorBoundary"}]],"fallback":["$","@4",null,{"name":"SuspenseFallback"}]}]
1:{"status":"pending","chunks":["@5"]}
2:["$","div",null,{"className":"layout","children":["$","nav",null,{"children":[["$","a",null,{"href":"/dashboard","children":"Dashboard"}],["$","a",null,{"href":"/settings","children":"Settings"}]]}]}"#,
        ];

        let idx = (Utc::now().timestamp_millis() as usize) % responses.len();
        responses[idx].to_string()
    }

    /// Generate a fake JSON API response.
    fn generate_fake_api_response(&self, req: &RawRequest) -> String {
        if req.path.contains("/graphql") {
            r#"{"data":{"__typename":"Query","node":{"id":"UHJvamVjdDox","name":"Internal Project","owner":{"login":"admin","email":"admin@internal.local"}}}}"#.to_string()
        } else {
            r#"{"success":true,"data":{"id":"67f1a2b3c4d5","status":"ok","timestamp":"2026-05-06T12:00:00Z","message":"Operation completed"}}"#.to_string()
        }
    }

    /// Generate a fake HTML page response.
    fn generate_fake_html_response(&self, _req: &RawRequest) -> String {
        format!(
            r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="generator" content="Next.js 15.2.3"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Internal Dashboard</title><link rel="preload" href="/_next/static/chunks/app/layout-{}.js" as="script"></head><body><div id="__next"><div class="app-shell"><header class="topbar"><nav><a href="/dashboard">Dashboard</a><a href="/admin">Admin</a><a href="/api/docs">API</a></nav><div class="user-menu">Signed in as <strong>Admin User</strong></div></header><main><!--$?--><template id="B:0"></template><div class="skeleton-loader"><div class="skeleton-card"></div><div class="skeleton-row"></div><div class="skeleton-row short"></div></div><!--/$--></main></div></div><script src="/_next/static/chunks/main-app-{}.js" async></script></body></html>"#,
            Self::random_hex(16),
            Self::random_hex(16)
        )
    }

    fn simulate_content_type(&self, req: &RawRequest) -> String {
        let is_rsc = req.headers.contains_key("next-action")
            || req
                .headers
                .get("content-type")
                .map(|ct| ct.contains("text/x-component"))
                .unwrap_or(false);

        if is_rsc {
            "text/x-component; charset=utf-8".to_string()
        } else if req.path.contains("/api/") {
            "application/json; charset=utf-8".to_string()
        } else {
            "text/html; charset=utf-8".to_string()
        }
    }

    /// Decide whether to block based on severity.
    fn should_block_request(&self, detections: &[AttackEvent]) -> bool {
        detections
            .iter()
            .any(|d| d.severity == Severity::Critical || d.confidence > 0.9)
    }

    /// Calculate realistic response delay.
    fn calculate_delay(&self, _detections: &[AttackEvent]) -> Duration {
        if !self.config.realistic_timing {
            return Duration::from_millis(0);
        }
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        Utc::now().timestamp_nanos_opt().unwrap_or(0).hash(&mut hasher);
        let hash = hasher.finish();
        let jitter = (hash % (self.config.max_delay_ms - self.config.min_delay_ms + 1)) as u64;
        Duration::from_millis(self.config.min_delay_ms + jitter)
    }

    // ── Attacker Profiling ────────────────────────────────────────────────

    /// Get or create a profile ID for an attacker.
    fn get_or_create_profile_id(&mut self, req: &RawRequest) -> String {
        let fingerprint = self.build_fingerprint(req);
        let hashed = Self::hash_str(&fingerprint);
        let profile_id = format!("prof_{}", &hashed[..16]);

        if !self.state.attacker_profiles.contains_key(&profile_id) {
            self.state.attacker_profiles.insert(
                profile_id.clone(),
                AttackerProfile {
                    profile_id: profile_id.clone(),
                    ip: req.ip.clone(),
                    country: None,
                    asn: None,
                    is_tor: false,
                    is_cloud: false,
                    is_proxy: false,
                    user_agent: req
                        .headers
                        .get("user-agent")
                        .cloned()
                        .unwrap_or_default(),
                    browser_fingerprint: self.parse_user_agent(
                        req.headers
                            .get("user-agent")
                            .map(|s| s.as_str())
                            .unwrap_or(""),
                    ),
                    first_seen: Utc::now().to_rfc3339(),
                    last_seen: Utc::now().to_rfc3339(),
                    total_requests: 0,
                    attack_categories: HashMap::new(),
                    techniques_used: Vec::new(),
                    avg_request_interval: 0.0,
                    is_automated: false,
                    risk_score: 0.0,
                    targets: Vec::new(),
                    event_timeline: Vec::new(),
                },
            );
            self.state.unique_attackers = self.state.attacker_profiles.len();
        }

        profile_id
    }

    /// Build a fingerprint from request characteristics.
    fn build_fingerprint(&self, req: &RawRequest) -> String {
        let ua = req.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");
        let accept = req
            .headers
            .get("accept")
            .map(|s| s.as_str())
            .unwrap_or("");
        let accept_lang = req
            .headers
            .get("accept-language")
            .map(|s| s.as_str())
            .unwrap_or("");
        let accept_enc = req
            .headers
            .get("accept-encoding")
            .map(|s| s.as_str())
            .unwrap_or("");

        format!("{}|{}|{}|{}|{}", req.ip, ua, accept, accept_lang, accept_enc)
    }

    /// Update request time tracking for cadence analysis.
    fn update_request_times(&mut self, profile_id: &str) {
        let times = self.request_times.entry(profile_id.to_string()).or_default();
        times.push(Instant::now());
        // Keep only last 100 timestamps
        if times.len() > 100 {
            times.drain(0..times.len() - 100);
        }

        // Update automaton detection
        if let Some(profile) = self.state.attacker_profiles.get_mut(profile_id) {
            profile.total_requests += 1;
            profile.last_seen = Utc::now().to_rfc3339();
            if times.len() >= 3 {
                let intervals: Vec<f64> = times
                    .windows(2)
                    .map(|w| w[1].duration_since(w[0]).as_secs_f64())
                    .collect();
                profile.avg_request_interval =
                    intervals.iter().sum::<f64>() / intervals.len() as f64;

                // Detect automation: very consistent timing or very fast
                if profile.total_requests >= 10 {
                    let std_dev = Self::std_dev(&intervals, profile.avg_request_interval);
                    profile.is_automated = profile.avg_request_interval < 0.1
                        || (profile.avg_request_interval < 0.5 && std_dev < 0.05);
                }
            }
        }
    }

    /// Update the attacker profile with detection results.
    fn update_attacker_profile(
        &mut self,
        req: &RawRequest,
        profile_id: &str,
        detections: &[AttackEvent],
    ) {
        if let Some(profile) = self.state.attacker_profiles.get_mut(profile_id) {
            for det in detections {
                *profile
                    .attack_categories
                    .entry(det.category.clone())
                    .or_insert(0) += 1;
                if !profile.techniques_used.contains(&det.subcategory) {
                    profile.techniques_used.push(det.subcategory.clone());
                }
                profile.event_timeline.push(format!(
                    "{} | {}:{} | {} | conf={:.2}",
                    &det.timestamp[..19],
                    det.category,
                    det.subcategory,
                    det.severity
                        .clone()
                        .serde_name()
                        .unwrap_or("unknown"),
                    det.confidence
                ));
            }
            if !profile.targets.contains(&req.path) {
                profile.targets.push(req.path.clone());
            }

            // Calculate risk score (0-100)
            profile.risk_score = Self::calculate_risk_score(profile);
        }
    }

    /// Calculate a cumulative risk score for an attacker profile.
    fn calculate_risk_score(profile: &AttackerProfile) -> f64 {
        let mut score = 0.0;

        // Severity-based scoring
        let severity_weights: HashMap<&str, f64> = [
            ("sqli", 15.0),
            ("cmdi", 15.0),
            ("rce", 15.0),
            ("deserialization", 15.0),
            ("xxe", 14.0),
            ("ssti", 14.0),
            ("lfi", 13.0),
            ("rfi", 13.0),
            ("ssrf", 12.0),
            ("nosqli", 12.0),
            ("xss", 8.0),
            ("path_traversal", 8.0),
            ("file_upload", 10.0),
            ("crlf", 7.0),
            ("http_smuggling", 9.0),
            ("jwt", 9.0),
            ("auth_bypass", 10.0),
            ("prototype_pollution", 8.0),
            ("rsc_attack", 14.0),
            ("dns_exfil", 6.0),
        ]
        .into_iter()
        .collect();

        for (cat, count) in &profile.attack_categories {
            let weight = severity_weights.get(cat.as_str()).copied().unwrap_or(3.0);
            score += weight * (*count as f64).min(3.0); // Cap at 3x per category
        }

        // Multiplier for diverse techniques
        let technique_bonus = (profile.techniques_used.len() as f64 * 2.0).min(20.0);
        score += technique_bonus;

        // Automation bonus
        if profile.is_automated {
            score += 10.0;
        }

        // Request volume bonus
        if profile.total_requests > 100 {
            score += 5.0;
        }
        if profile.total_requests > 500 {
            score += 5.0;
        }

        score.min(100.0)
    }

    // ── User-Agent Parsing ─────────────────────────────────────────────────

    /// Parse User-Agent string into structured browser/OS fingerprint.
    fn parse_user_agent(&self, ua: &str) -> Option<BrowserFingerprint> {
        if ua.is_empty() {
            return None;
        }

        let ua_lower = ua.to_lowercase();

        // Browser detection
        let (browser, browser_version) = if ua_lower.contains("firefox") {
            ("Firefox", Self::extract_version(ua, "Firefox/"))
        } else if ua_lower.contains("edg") {
            ("Edge", Self::extract_version(ua, "Edg/"))
        } else if ua_lower.contains("chrome") && !ua_lower.contains("chromium") {
            ("Chrome", Self::extract_version(ua, "Chrome/"))
        } else if ua_lower.contains("safari") && !ua_lower.contains("chrome") {
            ("Safari", Self::extract_version(ua, "Version/"))
        } else if ua_lower.contains("opera") || ua_lower.contains("opr") {
            ("Opera", Self::extract_version(ua, "OPR/"))
        } else if ua_lower.contains("msie") || ua_lower.contains("trident") {
            ("Internet Explorer", Self::extract_version(ua, "MSIE "))
        } else {
            ("Unknown", "0.0".to_string())
        };

        // OS detection
        let (os, os_version) = if ua_lower.contains("windows nt 10") {
            ("Windows", "10/11".to_string())
        } else if ua_lower.contains("windows nt 6.3") {
            ("Windows", "8.1".to_string())
        } else if ua_lower.contains("windows nt 6.1") {
            ("Windows", "7".to_string())
        } else if ua_lower.contains("mac os x") {
            ("macOS", Self::extract_version(ua, "Mac OS X "))
        } else if ua_lower.contains("android") {
            ("Android", Self::extract_version(ua, "Android "))
        } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") {
            ("iOS", Self::extract_version(ua, "OS "))
        } else if ua_lower.contains("linux") {
            ("Linux", "".to_string())
        } else {
            ("Unknown", "".to_string())
        };

        let engine = if ua_lower.contains("webkit") {
            "WebKit"
        } else if ua_lower.contains("gecko") {
            "Gecko"
        } else if ua_lower.contains("trident") {
            "Trident"
        } else {
            "Unknown"
        };

        let device_type = if ua_lower.contains("mobile") || ua_lower.contains("android") {
            "Mobile"
        } else if ua_lower.contains("tablet") || ua_lower.contains("ipad") {
            "Tablet"
        } else {
            "Desktop"
        };

        let is_headless = ua_lower.contains("headless")
            || ua_lower.contains("phantom")
            || ua_lower.contains("puppeteer")
            || ua_lower.contains("playwright")
            || ua_lower.contains("selenium");

        Some(BrowserFingerprint {
            browser: browser.to_string(),
            browser_version,
            os: os.to_string(),
            os_version,
            engine: engine.to_string(),
            device_type: device_type.to_string(),
            is_headless,
        })
    }

    fn extract_version(ua: &str, prefix: &str) -> String {
        if let Some(pos) = ua.find(prefix) {
            let start = pos + prefix.len();
            let end = ua[start..]
                .find(|c: char| c == ' ' || c == ';' || c == ')')
                .map(|p| start + p)
                .unwrap_or(ua.len());
            let version = &ua[start..end];
            // Take only major.minor
            version
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".")
        } else {
            "0.0".to_string()
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    fn all_request_text(&self, req: &RawRequest) -> String {
        format!(
            "{} {}?{} {} {}",
            req.method,
            req.path,
            req.query_string,
            req.body,
            self.headers_as_string(&req.headers)
        )
    }

    fn headers_as_string(&self, headers: &HashMap<String, String>) -> String {
        headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn generate_event_id() -> String {
        format!(
            "evt_{}_{}",
            Utc::now().timestamp_millis(),
            Self::random_hex(8)
        )
    }

    fn truncate_str(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...[truncated {} bytes]", &s[..max_len], s.len() - max_len)
        }
    }

    fn random_hex(len: usize) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        Utc::now().timestamp_nanos_opt().unwrap_or(0).hash(&mut hasher);
        format!("{:016x}", hasher.finish())[..len].to_string()
    }

    fn hash_str(s: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    fn std_dev(values: &[f64], mean: f64) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }
        let variance =
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
        variance.sqrt()
    }

    // ── Public API ─────────────────────────────────────────────────────────

    /// Get the current honeypot state (for dashboard/export).
    pub fn get_state(&self) -> &HoneypotState {
        &self.state
    }

    /// Get a snapshot of all attacker profiles.
    pub fn get_profiles(&self) -> Vec<&AttackerProfile> {
        self.state.attacker_profiles.values().collect()
    }

    /// Get a specific attacker profile by ID.
    pub fn get_profile(&self, profile_id: &str) -> Option<&AttackerProfile> {
        self.state.attacker_profiles.get(profile_id)
    }

    /// Get top-N most dangerous attacker profiles.
    pub fn get_top_threats(&self, n: usize) -> Vec<&AttackerProfile> {
        let mut profiles: Vec<&AttackerProfile> =
            self.state.attacker_profiles.values().collect();
        profiles.sort_by(|a, b| {
            b.risk_score
                .partial_cmp(&a.risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        profiles.truncate(n);
        profiles
    }

    /// Export full state as JSON.
    pub fn export_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self.state)
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.state = HoneypotState {
            config: self.config.clone(),
            total_requests: 0,
            total_attacks_detected: 0,
            unique_attackers: 0,
            attack_events: Vec::new(),
            attacker_profiles: HashMap::new(),
            uptime_seconds: 0.0,
            requests_per_minute: 0.0,
        };
        self.request_times.clear();
    }
}

impl Default for HoneypotEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Severity {
    fn serde_name(&self) -> Option<&str> {
        match self {
            Severity::Info => Some("info"),
            Severity::Low => Some("low"),
            Severity::Medium => Some("medium"),
            Severity::High => Some("high"),
            Severity::Critical => Some("critical"),
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str, path: &str, body: &str, headers: Vec<(&str, &str)>) -> RawRequest {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert(k.to_lowercase(), v.to_string());
        }
        RawRequest {
            method: method.to_string(),
            path: path.to_string(),
            query_string: String::new(),
            body: body.to_string(),
            headers: h,
            ip: "192.168.1.100".to_string(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_sqli_detection() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "GET",
            "/login",
            "username=admin' OR '1'='1&password=test",
            vec![],
        );
        let result = engine.process_request(&req);
        let sqli = result
            .detections
            .iter()
            .filter(|d| d.category == "sqli")
            .collect::<Vec<_>>();
        assert!(!sqli.is_empty(), "Should detect SQL injection");
    }

    #[test]
    fn test_xss_detection() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "GET",
            "/search",
            "q=<script>alert('XSS')</script>",
            vec![],
        );
        let result = engine.process_request(&req);
        let xss = result
            .detections
            .iter()
            .filter(|d| d.category == "xss")
            .collect::<Vec<_>>();
        assert!(!xss.is_empty(), "Should detect XSS");
    }

    #[test]
    fn test_cmdi_detection() {
        let mut engine = HoneypotEngine::new();
        let req = make_request("POST", "/api/exec", "cmd=;id", vec![]);
        let result = engine.process_request(&req);
        let cmdi = result
            .detections
            .iter()
            .filter(|d| d.category == "cmdi")
            .collect::<Vec<_>>();
        assert!(!cmdi.is_empty(), "Should detect command injection");
    }

    #[test]
    fn test_path_traversal_detection() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "GET",
            "/download",
            "file=../../../etc/passwd",
            vec![],
        );
        let result = engine.process_request(&req);
        let pt = result
            .detections
            .iter()
            .filter(|d| d.category == "path_traversal")
            .collect::<Vec<_>>();
        assert!(!pt.is_empty(), "Should detect path traversal");
    }

    #[test]
    fn test_ssti_detection() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "POST",
            "/contact",
            "name={{7*7}}",
            vec![],
        );
        let result = engine.process_request(&req);
        let ssti = result
            .detections
            .iter()
            .filter(|d| d.category == "ssti")
            .collect::<Vec<_>>();
        assert!(!ssti.is_empty(), "Should detect SSTI ({{7*7}})");
    }

    #[test]
    fn test_lfi_detection() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "GET",
            "/view",
            "page=/etc/passwd",
            vec![],
        );
        let result = engine.process_request(&req);
        let lfi = result
            .detections
            .iter()
            .filter(|d| d.category == "lfi")
            .collect::<Vec<_>>();
        assert!(!lfi.is_empty(), "Should detect LFI (/etc/passwd)");
    }

    #[test]
    fn test_ssrf_metadata_detection() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "POST",
            "/api/fetch",
            "url=http://169.254.169.254/latest/meta-data/",
            vec![],
        );
        let result = engine.process_request(&req);
        let ssrf = result
            .detections
            .iter()
            .filter(|d| d.category == "ssrf")
            .collect::<Vec<_>>();
        assert!(!ssrf.is_empty(), "Should detect SSRF cloud metadata probe");
    }

    #[test]
    fn test_rsc_flight_detection() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "POST",
            "/",
            r#"0:[["$","@1",null,{"id":"malicious_component","chunks":[]}]]"#,
            vec![("Content-Type", "text/x-component"), ("Next-Action", "exploit")],
        );
        let result = engine.process_request(&req);
        let rsc = result
            .detections
            .iter()
            .filter(|d| d.category == "rsc_attack")
            .collect::<Vec<_>>();
        assert!(!rsc.is_empty(), "Should detect RSC/Flight protocol attack");
    }

    #[test]
    fn test_attacker_profiling() {
        let mut engine = HoneypotEngine::new();

        // Send multiple attacks from same IP
        for i in 0..5 {
            let body = format!("cmd=;id_{}", i);
            let req = make_request("POST", "/api/exec", &body, vec![
                ("User-Agent", "sqlmap/1.0"),
            ]);
            engine.process_request(&req);
        }

        let profiles = engine.get_profiles();
        assert!(!profiles.is_empty(), "Should have at least one profile");
        let profile = &profiles[0];
        assert!(profile.total_requests >= 5);
        assert!(!profile.techniques_used.is_empty());
    }

    #[test]
    fn test_ua_parsing() {
        let engine = HoneypotEngine::new();
        let fp = engine.parse_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
        let fp = fp.unwrap();
        assert_eq!(fp.browser, "Chrome");
        assert_eq!(fp.os, "Windows");
        assert_eq!(fp.engine, "WebKit");
    }

    #[test]
    fn test_no_detection_on_clean_request() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "GET",
            "/",
            "",
            vec![("User-Agent", "Mozilla/5.0")],
        );
        let result = engine.process_request(&req);
        // Clean GET to / with no payloads should have zero critical/high detections
        let critical = result
            .detections
            .iter()
            .filter(|d| d.severity >= Severity::High)
            .count();
        assert_eq!(critical, 0, "Clean request should not trigger high-severity detections");
    }

    #[test]
    fn test_risk_score() {
        let mut profile = AttackerProfile {
            profile_id: "test".to_string(),
            ip: "10.0.0.1".to_string(),
            country: None,
            asn: None,
            is_tor: false,
            is_cloud: false,
            is_proxy: false,
            user_agent: String::new(),
            browser_fingerprint: None,
            first_seen: String::new(),
            last_seen: String::new(),
            total_requests: 200,
            attack_categories: [
                ("sqli".to_string(), 5),
                ("xss".to_string(), 3),
                ("cmdi".to_string(), 2),
            ]
            .into_iter()
            .collect(),
            techniques_used: vec!["union_select".to_string(), "stacked".to_string(), "reflected".to_string()],
            avg_request_interval: 0.05,
            is_automated: true,
            risk_score: 0.0,
            targets: vec!["/login".to_string(), "/api/exec".to_string()],
            event_timeline: vec![],
        };

        let score = HoneypotEngine::calculate_risk_score(&profile);
        profile.risk_score = score;

        assert!(score > 60.0, "Risk score should be high for diverse attacks: got {}", score);
        assert!(score <= 100.0, "Risk score should not exceed 100");
    }

    #[test]
    fn test_export_json() {
        let mut engine = HoneypotEngine::new();
        let req = make_request(
            "POST",
            "/api/login",
            "user=admin'--",
            vec![("User-Agent", "Mozilla/5.0")],
        );
        engine.process_request(&req);

        let json = engine.export_json().unwrap();
        assert!(json.contains("sqli"));
        assert!(json.contains("admin"));
    }

    #[test]
    fn test_fake_rsc_response() {
        let engine = HoneypotEngine::new();
        let req = make_request(
            "POST",
            "/dashboard",
            "[]",
            vec![("Content-Type", "text/x-component"), ("Next-Action", "test")],
        );
        let body = engine.generate_fake_rsc_response(&req);
        assert!(!body.is_empty());
        assert!(body.contains("$") || body.contains("pageProps") || body.contains("status"));
    }

    #[test]
    fn test_fake_html_response() {
        let engine = HoneypotEngine::new();
        let req = make_request("GET", "/", "", vec![]);
        let body = engine.generate_fake_html_response(&req);
        assert!(body.contains("<html"));
        assert!(body.contains("Next.js"));
        assert!(body.contains("__next"));
    }
}
