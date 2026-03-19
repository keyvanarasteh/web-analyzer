use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashMap;
use std::time::Duration;

// ── Detection pattern constants ─────────────────────────────────────────────

const WEB_SERVERS: &[(&str, &str)] = &[
    ("nginx", "Nginx"), ("apache", "Apache HTTP Server"),
    ("iis", "Microsoft IIS"), ("cloudflare", "Cloudflare"),
    ("litespeed", "LiteSpeed"), ("caddy", "Caddy"),
    ("traefik", "Traefik Proxy"), ("envoy", "Envoy Proxy"),
    ("gunicorn", "Gunicorn WSGI"), ("uwsgi", "uWSGI"),
];

const JS_LIBRARIES: &[(&str, &[&str])] = &[
    ("jQuery", &["jquery", "jquery.min.js"]),
    ("Lodash", &["lodash", "underscore"]),
    ("Moment.js", &["moment.js", "moment.min.js"]),
    ("D3.js", &["d3.js", "d3.min.js"]),
    ("Chart.js", &["chart.js", "chart.min.js"]),
    ("Three.js", &["three.js", "three.min.js"]),
    ("GSAP", &["gsap", "tweenmax"]),
    ("Axios", &["axios"]),
    ("Swiper", &["swiper"]),
    ("Bootstrap JS", &["bootstrap.js", "bootstrap.min.js"]),
    ("Popper.js", &["popper.js"]),
    ("Font Awesome", &["fontawesome", "font-awesome"]),
];

const CSS_FRAMEWORKS: &[(&str, &[&str])] = &[
    ("Bootstrap", &["bootstrap"]),
    ("Tailwind CSS", &["tailwind"]),
    ("Bulma", &["bulma"]),
    ("Foundation", &["foundation"]),
    ("Semantic UI", &["semantic-ui"]),
    ("Materialize", &["materialize"]),
    ("UIKit", &["uikit"]),
    ("Pure CSS", &["pure-css", "pure-"]),
];

const CMS_PATTERNS: &[(&str, &[&str])] = &[
    ("WordPress", &["wp-content", "wp-includes", "wp-admin", "wordpress"]),
    ("Drupal", &["drupal", "sites/all", "sites/default"]),
    ("Joomla", &["joomla", "option=com_"]),
    ("Magento", &["magento", "mage/cookies.js", "skin/frontend"]),
    ("Shopify", &["shopify", "shopifycdn"]),
    ("Wix", &["wix.com", "wixstatic"]),
    ("Squarespace", &["squarespace", "sqsp"]),
    ("Ghost", &["ghost.io", "casper"]),
    ("Webflow", &["webflow"]),
    ("TYPO3", &["typo3", "typo3conf"]),
    ("Concrete5", &["concrete5"]),
];

const ECOMMERCE: &[(&str, &[&str])] = &[
    ("Shopify", &["shopify", "shopifycdn"]),
    ("WooCommerce", &["woocommerce", "wc-"]),
    ("Magento", &["magento", "mage"]),
    ("PrestaShop", &["prestashop"]),
    ("BigCommerce", &["bigcommerce"]),
    ("OpenCart", &["opencart"]),
    ("Stripe", &["stripe"]),
    ("PayPal", &["paypal"]),
    ("Square", &["squareup"]),
];

const ANALYTICS: &[(&str, &[&str])] = &[
    ("Google Analytics", &["google-analytics", "googletagmanager", "gtag"]),
    ("Google Tag Manager", &["googletagmanager"]),
    ("Facebook Pixel", &["facebook.net/tr", "fbevents.js"]),
    ("Hotjar", &["hotjar"]),
    ("Mixpanel", &["mixpanel"]),
    ("Segment", &["segment.com", "analytics.js"]),
    ("Adobe Analytics", &["adobe", "omniture"]),
    ("Yandex Metrica", &["yandex", "metrica"]),
];

const WAF_INDICATORS: &[(&str, &[&str])] = &[
    ("Cloudflare", &["cf-ray", "cloudflare"]),
    ("AWS WAF", &["x-amzn-requestid", "awselb"]),
    ("Incapsula", &["incap_ses", "incapsula"]),
    ("Akamai", &["akamai"]),
    ("Sucuri", &["sucuri"]),
    ("ModSecurity", &["mod_security"]),
    ("F5 BIG-IP", &["bigip", "f5"]),
    ("Barracuda", &["barracuda"]),
];

const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("Content-Security-Policy", "High"),
    ("Strict-Transport-Security", "High"),
    ("X-Frame-Options", "Medium"),
    ("X-Content-Type-Options", "Medium"),
    ("X-XSS-Protection", "Medium"),
    ("Referrer-Policy", "Medium"),
];

const WP_KNOWN_PLUGINS: &[(&str, &str)] = &[
    ("yoast", "Yoast SEO"), ("akismet", "Akismet Anti-Spam"),
    ("jetpack", "Jetpack"), ("woocommerce", "WooCommerce"),
    ("contact-form-7", "Contact Form 7"), ("elementor", "Elementor"),
    ("wordfence", "Wordfence Security"), ("wp-super-cache", "WP Super Cache"),
    ("all-in-one-seo", "All in One SEO"), ("google-analytics", "Google Analytics"),
];

// ── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebTechResult {
    pub domain: String,
    // Basic technology
    pub web_server: String,
    pub backend: Vec<String>,
    pub frontend: Vec<String>,
    pub js_libraries: Vec<String>,
    pub css_frameworks: Vec<String>,
    pub cms: Vec<String>,
    pub ecommerce: Vec<String>,
    pub cdn: Vec<String>,
    pub analytics: Vec<String>,
    // Security
    pub security_headers: HashMap<String, SecurityHeaderInfo>,
    pub security_vulnerabilities: VulnerabilityInfo,
    pub information_disclosure: DisclosureInfo,
    pub security_services: SecurityServicesInfo,
    pub cookie_security: CookieSecurityInfo,
    // WordPress
    pub is_wordpress: bool,
    pub wordpress_analysis: Option<WordPressAnalysis>,
    // Score
    pub security_score: SecurityScoreResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderInfo {
    pub present: bool,
    pub value: String,
    pub security_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub missing_security_headers: Vec<String>,
    pub insecure_practices: Vec<String>,
    pub exposed_information: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureInfo {
    pub server_info: Vec<String>,
    pub technology_disclosure: Vec<String>,
    pub file_exposure: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityServicesInfo {
    pub waf: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieSecurityInfo {
    pub secure_flag: bool,
    pub httponly_flag: bool,
    pub samesite_attribute: bool,
    pub security_score: u32,
    pub security_level: String,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordPressAnalysis {
    pub confidence: String,
    pub version: String,
    pub theme: String,
    pub plugins: Vec<String>,
    pub users_found: Vec<WpUser>,
    pub rest_api_enabled: bool,
    pub xmlrpc_enabled: bool,
    pub admin_accessible: bool,
    pub login_accessible: bool,
    pub debug_enabled: bool,
    pub security_issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpUser {
    pub id: u64,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScoreResult {
    pub overall_score: u32,
    pub security_grade: String,
    pub risk_level: String,
    pub critical_issues: Vec<String>,
    pub recommendations: Vec<String>,
}

// ── Main Function ───────────────────────────────────────────────────────────

pub async fn detect_web_technologies(domain: &str) -> Result<WebTechResult, Box<dyn std::error::Error + Send + Sync>> {
    let url = if domain.starts_with("http") { domain.to_string() }
        else { format!("https://{}", domain) };

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;

    let res = client.get(&url).send().await?;
    let headers = res.headers().clone();
    let html_raw = res.text().await?;
    let html_lower = html_raw.to_lowercase();
    let document = Html::parse_document(&html_raw);

    let base_domain = domain.replace("https://", "").replace("http://", "");

    // Cache header strings
    let server_hdr = get_header(&headers, "server");
    let powered_by = get_header(&headers, "x-powered-by").to_lowercase();
    let headers_str = format!("{:?}", headers).to_lowercase();

    // 1. Web Server
    let web_server = detect_server(&server_hdr, &powered_by);

    // 2. Backend Technologies
    let backend = detect_backend(&html_lower, &powered_by, &server_hdr);

    // 3. Frontend Technologies
    let frontend = detect_frontend(&html_lower, &document);

    // 4. JS Libraries
    let js_libraries = detect_pattern_list(&html_lower, &document, JS_LIBRARIES);

    // 5. CSS Frameworks
    let css_frameworks = detect_css(&html_lower, &document);

    // 6. CMS
    let cms = detect_by_content(&html_lower, CMS_PATTERNS);

    // 7. E-commerce
    let ecommerce = detect_by_content(&html_lower, ECOMMERCE);

    // 8. CDN
    let cdn = detect_cdn(&server_hdr, &headers, &html_lower);

    // 9. Analytics
    let analytics = detect_pattern_list(&html_lower, &document, ANALYTICS);

    // 10. Security Headers
    let security_headers = analyze_security_headers(&headers);

    // 11. Security Vulnerabilities
    let security_vulnerabilities = detect_vulnerabilities(&html_lower, &headers);

    // 12. Information Disclosure
    let information_disclosure = detect_disclosure(&html_lower, &server_hdr, &powered_by);

    // 13. Security Services (WAF)
    let security_services = detect_waf(&headers_str, &html_lower);

    // 14. Cookie Security
    let cookie_security = analyze_cookies(&headers);

    // 15. WordPress Analysis
    let is_wordpress = is_wp(&html_lower);
    let wordpress_analysis = if is_wordpress {
        Some(analyze_wordpress(&client, &base_domain, &html_lower, &document).await)
    } else { None };

    // 16. Security Score
    let security_score = calculate_score(
        &security_headers, &security_vulnerabilities,
        &information_disclosure, &security_services, &cookie_security,
        &wordpress_analysis,
    );

    Ok(WebTechResult {
        domain: domain.to_string(),
        web_server, backend, frontend, js_libraries, css_frameworks,
        cms, ecommerce, cdn, analytics, security_headers,
        security_vulnerabilities, information_disclosure,
        security_services, cookie_security,
        is_wordpress, wordpress_analysis, security_score,
    })
}

// ── 1. Web Server ───────────────────────────────────────────────────────────

fn detect_server(server: &str, powered_by: &str) -> String {
    let s_lower = server.to_lowercase();
    let p_lower = powered_by.to_lowercase();
    for &(key, name) in WEB_SERVERS {
        if s_lower.contains(key) || p_lower.contains(key) {
            let version = Regex::new(r"[\d\.]+").ok()
                .and_then(|r| r.find(&s_lower).map(|m| format!(" {}", m.as_str())))
                .unwrap_or_default();
            return format!("{}{}", name, version);
        }
    }
    if server.is_empty() { "Not Detected".into() } else { server.to_string() }
}

// ── 2. Backend Technologies ─────────────────────────────────────────────────

fn detect_backend(html: &str, powered_by: &str, server: &str) -> Vec<String> {
    let mut techs = vec![];
    let srv = server.to_lowercase();

    if powered_by.contains("php") || html.contains(".php") || html.contains("phpsessid") { techs.push("PHP".into()); }
    if powered_by.contains("asp.net") || html.contains("__viewstate") || html.contains("aspxauth") { techs.push("ASP.NET".into()); }
    if powered_by.contains("express") || srv.contains("node") || powered_by.contains("koa") { techs.push("Node.js".into()); }
    if html.contains("django") || html.contains("csrfmiddlewaretoken") { techs.push("Python Django".into()); }
    if html.contains("flask") || srv.contains("werkzeug") { techs.push("Python Flask".into()); }
    if powered_by.contains("ruby") || html.contains("rails") || html.contains("authenticity_token") { techs.push("Ruby on Rails".into()); }
    if html.contains("jsessionid") || html.contains("servlet") || html.contains(".jsp") || html.contains("spring") { techs.push("Java".into()); }
    if html.contains("golang") || html.contains("gin-gonic") { techs.push("Go".into()); }

    if techs.is_empty() { vec!["Not Detected".into()] } else { techs }
}

// ── 3. Frontend Technologies ────────────────────────────────────────────────

fn detect_frontend(html: &str, doc: &Html) -> Vec<String> {
    let mut techs = vec![];
    let scripts = collect_script_srcs(doc);

    if scripts.contains("react") || html.contains("data-reactroot") || html.contains("__react") { techs.push("React".into()); }
    if scripts.contains("vue") || html.contains("v-app") || html.contains("v-cloak") { techs.push("Vue.js".into()); }
    if scripts.contains("angular") || html.contains("ng-app") || html.contains("ng-version") { techs.push("Angular".into()); }
    if scripts.contains("svelte") || html.contains("_svelte") { techs.push("Svelte".into()); }
    if scripts.contains("ember") || html.contains("ember-application") { techs.push("Ember.js".into()); }
    if scripts.contains("alpine") || html.contains("x-data") { techs.push("Alpine.js".into()); }
    if scripts.contains("jquery") { techs.push("jQuery".into()); }

    if techs.is_empty() { vec!["Not Detected".into()] } else { techs }
}

// ── 4/9. Pattern-based detection (JS libs, Analytics) ───────────────────────

fn detect_pattern_list(html: &str, doc: &Html, patterns: &[(&str, &[&str])]) -> Vec<String> {
    let mut found = vec![];
    let scripts = collect_script_srcs(doc);
    for &(name, pats) in patterns {
        if pats.iter().any(|p| scripts.contains(p) || html.contains(p)) {
            found.push(name.to_string());
        }
    }
    if found.is_empty() { vec!["Not Detected".into()] } else { found }
}

// ── 5. CSS Frameworks ───────────────────────────────────────────────────────

fn detect_css(html: &str, doc: &Html) -> Vec<String> {
    let mut found = vec![];
    let stylesheets = collect_stylesheet_hrefs(doc);
    let combined = format!("{} {}", stylesheets, html);
    for &(name, pats) in CSS_FRAMEWORKS {
        if pats.iter().any(|p| combined.contains(p)) {
            found.push(name.to_string());
        }
    }
    if found.is_empty() { vec!["Not Detected".into()] } else { found }
}

// ── 6/7. Content-based detection (CMS, E-commerce) ─────────────────────────

fn detect_by_content(html: &str, patterns: &[(&str, &[&str])]) -> Vec<String> {
    let mut found = vec![];
    for &(name, pats) in patterns {
        if pats.iter().any(|p| html.contains(p)) {
            found.push(name.to_string());
        }
    }
    if found.is_empty() { vec!["Not Detected".into()] } else { found }
}

// ── 8. CDN ──────────────────────────────────────────────────────────────────

fn detect_cdn(server: &str, headers: &reqwest::header::HeaderMap, html: &str) -> Vec<String> {
    let mut found = vec![];
    let s = server.to_lowercase();
    let via = get_header(headers, "via").to_lowercase();

    if s.contains("cloudflare") || headers.contains_key("cf-ray") { found.push("Cloudflare".into()); }
    if s.contains("cloudfront") || via.contains("cloudfront") || headers.contains_key("x-amz-cf-id") { found.push("AWS CloudFront".into()); }
    if s.contains("fastly") || via.contains("fastly") { found.push("Fastly".into()); }
    if s.contains("keycdn") { found.push("KeyCDN".into()); }
    if html.contains("maxcdn") { found.push("MaxCDN".into()); }
    if s.contains("akamai") || headers.contains_key("x-akamai-transformed") { found.push("Akamai".into()); }

    if found.is_empty() { vec!["Not Detected".into()] } else { found }
}

// ── 10. Security Headers ────────────────────────────────────────────────────

fn analyze_security_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, SecurityHeaderInfo> {
    let mut result = HashMap::new();
    for &(name, importance) in SECURITY_HEADERS {
        let present = headers.contains_key(name);
        let value = headers.get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("Not Set").to_string();
        result.insert(name.to_string(), SecurityHeaderInfo {
            present,
            value,
            security_level: if present { importance.to_string() } else { "Low".into() },
        });
    }
    result
}

// ── 11. Security Vulnerabilities ────────────────────────────────────────────

fn detect_vulnerabilities(html: &str, headers: &reqwest::header::HeaderMap) -> VulnerabilityInfo {
    let mut missing = vec![];
    let required = [
        ("Content-Security-Policy", "CSP Header Missing - XSS Risk"),
        ("X-Frame-Options", "Clickjacking Protection Missing"),
        ("X-Content-Type-Options", "MIME Sniffing Protection Missing"),
        ("Strict-Transport-Security", "HSTS Missing - MITM Risk"),
        ("X-XSS-Protection", "XSS Protection Header Missing"),
    ];
    for &(header, risk) in &required {
        if !headers.contains_key(header) { missing.push(risk.to_string()); }
    }

    let mut insecure = vec![];
    if html.contains("http://") && html.contains("https://") {
        insecure.push("Mixed Content - HTTP resources on HTTPS page".into());
    }

    let mut exposed = vec![];
    let debug_patterns = [
        (r"debug.*true", "Debug mode enabled"),
        (r"error.*trace", "Error traces exposed"),
        (r"stack.*trace", "Stack traces visible"),
        (r"sql.*error", "SQL errors exposed"),
    ];
    for &(pattern, desc) in &debug_patterns {
        if Regex::new(pattern).ok().map(|r| r.is_match(html)).unwrap_or(false) {
            exposed.push(desc.to_string());
        }
    }

    VulnerabilityInfo { missing_security_headers: missing, insecure_practices: insecure, exposed_information: exposed }
}

// ── 12. Information Disclosure ───────────────────────────────────────────────

fn detect_disclosure(html: &str, server: &str, powered_by: &str) -> DisclosureInfo {
    let mut server_info = vec![];
    if Regex::new(r"/[\d\.]+").ok().map(|r| r.is_match(server)).unwrap_or(false) {
        server_info.push(format!("Server version exposed: {}", server));
    }

    let mut tech = vec![];
    if !powered_by.is_empty() {
        tech.push(format!("Technology stack exposed: {}", powered_by));
    }

    let mut files = vec![];
    if html.contains("c:\\") || html.contains("c:/") { files.push("Windows file paths exposed".into()); }
    if html.contains("/var/www/") { files.push("Linux file paths exposed".into()); }
    if html.contains("/home/") { files.push("User directories exposed".into()); }
    if html.contains(".env") { files.push("Environment files referenced".into()); }

    DisclosureInfo { server_info, technology_disclosure: tech, file_exposure: files }
}

// ── 13. Security Services (WAF) ─────────────────────────────────────────────

fn detect_waf(headers_str: &str, html: &str) -> SecurityServicesInfo {
    let mut waf = vec![];
    for &(name, indicators) in WAF_INDICATORS {
        if indicators.iter().any(|i| headers_str.contains(i) || html.contains(i)) {
            waf.push(name.to_string());
        }
    }
    SecurityServicesInfo { waf }
}

// ── 14. Cookie Security ─────────────────────────────────────────────────────

fn analyze_cookies(headers: &reqwest::header::HeaderMap) -> CookieSecurityInfo {
    let cookie_str = headers.get("set-cookie")
        .and_then(|v| v.to_str().ok()).unwrap_or("");

    if cookie_str.is_empty() {
        return CookieSecurityInfo {
            secure_flag: false, httponly_flag: false, samesite_attribute: false,
            security_score: 0, security_level: "N/A".into(),
            recommendations: vec!["No cookies detected".into()],
        };
    }

    let secure = cookie_str.to_lowercase().contains("secure");
    let httponly = cookie_str.to_lowercase().contains("httponly");
    let samesite = cookie_str.to_lowercase().contains("samesite");

    let mut score = 0u32;
    let mut recs = vec![];
    if secure { score += 40; } else { recs.push("Add Secure flag to cookies".into()); }
    if httponly { score += 30; } else { recs.push("Add HttpOnly flag to prevent XSS".into()); }
    if samesite { score += 30; } else { recs.push("Add SameSite attribute for CSRF protection".into()); }

    let level = if score >= 90 { "Excellent" } else if score >= 70 { "Good" }
        else if score >= 50 { "Fair" } else { "Poor" };

    CookieSecurityInfo { secure_flag: secure, httponly_flag: httponly, samesite_attribute: samesite,
        security_score: score, security_level: level.into(), recommendations: recs }
}

// ── 15. WordPress Analysis ──────────────────────────────────────────────────

fn is_wp(html: &str) -> bool {
    let indicators = [
        html.contains("wp-content/"), html.contains("wp-includes/"),
        html.contains("wp-admin/"), html.contains("wp-json/"),
        html.contains("xmlrpc.php"),
    ];
    indicators.iter().filter(|&&x| x).count() >= 2
}

async fn analyze_wordpress(client: &Client, domain: &str, html: &str, doc: &Html) -> WordPressAnalysis {
    let base_url = format!("https://{}", domain);

    // Version from generator meta
    let version = extract_wp_version(html, doc);

    // Confidence
    let confidence = if html.contains("wp-content/") && html.contains("wp-includes/") { "High" }
        else { "Medium" };

    // Theme
    let theme = extract_wp_theme(doc);

    // Plugins
    let plugins = extract_wp_plugins(html, doc);

    // Users via REST API
    let users_found = enumerate_wp_users(client, &base_url).await;

    // REST API
    let rest_api = check_wp_endpoint(client, &format!("{}/wp-json/", base_url)).await;

    // XMLRPC
    let xmlrpc = check_wp_xmlrpc(client, &base_url).await;

    // Admin / Login
    let admin = check_wp_endpoint(client, &format!("{}/wp-admin/", base_url)).await;
    let login = check_wp_endpoint(client, &format!("{}/wp-login.php", base_url)).await;

    // Debug
    let debug = html.contains("wp_debug") ||
        Regex::new(r"fatal error.*wp-").ok().map(|r| r.is_match(html)).unwrap_or(false);

    // Security issues
    let mut issues = vec![];
    if rest_api { issues.push("REST API enabled - user enumeration possible".into()); }
    if xmlrpc { issues.push("XML-RPC enabled - brute force risk".into()); }
    if debug { issues.push("Debug information potentially exposed".into()); }
    if !users_found.is_empty() { issues.push(format!("{} users enumerated via REST API", users_found.len())); }

    WordPressAnalysis {
        confidence: confidence.into(), version, theme, plugins,
        users_found, rest_api_enabled: rest_api, xmlrpc_enabled: xmlrpc,
        admin_accessible: admin, login_accessible: login,
        debug_enabled: debug, security_issues: issues,
    }
}

fn extract_wp_version(html: &str, doc: &Html) -> String {
    // Check generator meta
    if let Ok(sel) = Selector::parse("meta[name=\"generator\"]") {
        if let Some(el) = doc.select(&sel).next() {
            if let Some(content) = el.value().attr("content") {
                if content.to_lowercase().contains("wordpress") {
                    if let Some(m) = Regex::new(r"(?i)wordpress\s+([\d\.]+)").ok().and_then(|r| r.captures(content)) {
                        return m.get(1).unwrap().as_str().to_string();
                    }
                }
            }
        }
    }
    // Regex on HTML
    if let Some(m) = Regex::new(r#"ver=([\d\.]+)"#).ok().and_then(|r| r.captures(html)) {
        return m.get(1).unwrap().as_str().to_string();
    }
    "Unknown".into()
}

fn extract_wp_theme(doc: &Html) -> String {
    if let Ok(sel) = Selector::parse("link[rel=\"stylesheet\"]") {
        for el in doc.select(&sel) {
            if let Some(href) = el.value().attr("href") {
                if href.contains("wp-content/themes/") {
                    if let Some(m) = Regex::new(r"/wp-content/themes/([^/]+)").ok().and_then(|r| r.captures(href)) {
                        return m.get(1).unwrap().as_str().to_string();
                    }
                }
            }
        }
    }
    "Unknown".into()
}

fn extract_wp_plugins(html: &str, doc: &Html) -> Vec<String> {
    let mut plugins = std::collections::HashSet::new();

    // From script/link srcs
    let selectors = ["script[src]", "link[rel=\"stylesheet\"]"];
    for sel_str in &selectors {
        if let Ok(sel) = Selector::parse(sel_str) {
            for el in doc.select(&sel) {
                let attr = el.value().attr("src").or_else(|| el.value().attr("href")).unwrap_or("");
                if attr.contains("wp-content/plugins/") {
                    if let Some(m) = Regex::new(r"/wp-content/plugins/([^/]+)").ok().and_then(|r| r.captures(attr)) {
                        plugins.insert(m.get(1).unwrap().as_str().to_string());
                    }
                }
            }
        }
    }

    // Known plugin signatures in HTML
    for &(slug, _name) in WP_KNOWN_PLUGINS {
        if html.contains(slug) {
            plugins.insert(slug.to_string());
        }
    }

    // Map slugs to names
    plugins.into_iter().map(|slug| {
        WP_KNOWN_PLUGINS.iter()
            .find(|&&(s, _)| s == slug.as_str())
            .map(|&(_, name)| name.to_string())
            .unwrap_or_else(|| slug.replace('-', " "))
    }).collect()
}

async fn enumerate_wp_users(client: &Client, base_url: &str) -> Vec<WpUser> {
    let url = format!("{}/wp-json/wp/v2/users", base_url);
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(users) = resp.json::<Vec<serde_json::Value>>().await {
                return users.iter().filter_map(|u| {
                    Some(WpUser {
                        id: u.get("id")?.as_u64()?,
                        username: u.get("slug")?.as_str()?.to_string(),
                        display_name: u.get("name")?.as_str()?.to_string(),
                    })
                }).collect();
            }
        }
        _ => {}
    }
    vec![]
}

async fn check_wp_endpoint(client: &Client, url: &str) -> bool {
    match client.get(url).send().await {
        Ok(r) => [200, 301, 302].contains(&r.status().as_u16()),
        Err(_) => false,
    }
}

async fn check_wp_xmlrpc(client: &Client, base_url: &str) -> bool {
    let url = format!("{}/xmlrpc.php", base_url);
    match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => {
            r.text().await.unwrap_or_default().contains("XML-RPC server accepts POST requests only")
        }
        _ => false,
    }
}

// ── 16. Security Score ──────────────────────────────────────────────────────

fn calculate_score(
    headers: &HashMap<String, SecurityHeaderInfo>,
    vulns: &VulnerabilityInfo,
    disclosure: &DisclosureInfo,
    services: &SecurityServicesInfo,
    cookies: &CookieSecurityInfo,
    wp: &Option<WordPressAnalysis>,
) -> SecurityScoreResult {
    let mut score: i32 = 100;
    let mut issues = vec![];
    let mut recs = vec![];

    // Security headers (−8 per missing)
    let missing = headers.values().filter(|h| !h.present).count() as i32;
    score -= missing * 8;
    if missing > 0 {
        issues.push(format!("{} critical security headers missing", missing));
        recs.push("Implement missing security headers".into());
    }

    // Missing headers from vuln check (−5 each)
    score -= vulns.missing_security_headers.len() as i32 * 5;

    // Insecure practices (−10 each)
    for p in &vulns.insecure_practices {
        score -= 10;
        issues.push(p.clone());
    }

    // Info disclosure (−5 each)
    let disc_count = disclosure.server_info.len() + disclosure.technology_disclosure.len() + disclosure.file_exposure.len();
    score -= disc_count as i32 * 5;

    // WAF bonus (+5)
    if !services.waf.is_empty() {
        score += 5;
        recs.push("WAF detected - Good security practice".into());
    }

    // Cookie security
    if cookies.security_score < 70 && cookies.security_level != "N/A" {
        score -= 10;
        issues.push("Insecure cookie configuration".into());
        recs.push("Implement secure cookie flags".into());
    }

    // WordPress
    if let Some(wp_info) = wp {
        for issue in &wp_info.security_issues {
            score -= 5;
            issues.push(issue.clone());
        }
    }

    let final_score = score.clamp(0, 100) as u32;

    let grade = match final_score {
        90..=100 => "A+", 85..=89 => "A", 80..=84 => "A-",
        75..=79 => "B+", 70..=74 => "B", 65..=69 => "B-",
        60..=64 => "C+", 55..=59 => "C", 50..=54 => "C-",
        40..=49 => "D", _ => "F",
    };

    let risk = match final_score {
        80..=100 => "Low Risk", 60..=79 => "Medium Risk",
        40..=59 => "High Risk", _ => "Critical Risk",
    };

    SecurityScoreResult {
        overall_score: final_score,
        security_grade: grade.into(),
        risk_level: risk.into(),
        critical_issues: issues.into_iter().take(5).collect(),
        recommendations: recs.into_iter().take(5).collect(),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn get_header(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn collect_script_srcs(doc: &Html) -> String {
    let sel = Selector::parse("script[src]").unwrap();
    doc.select(&sel)
        .filter_map(|el| el.value().attr("src"))
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn collect_stylesheet_hrefs(doc: &Html) -> String {
    let sel = Selector::parse("link[rel=\"stylesheet\"]").unwrap();
    doc.select(&sel)
        .filter_map(|el| el.value().attr("href"))
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}
