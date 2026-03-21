use qicro_data_core::endpoint_registry::{EndpointMeta, ParamMeta};
use qicro_data_core::graphql_registry::{GraphqlFieldMeta, GraphqlOperationMeta, GraphqlTypeMeta};
use qicro_data_core::mcp::McpToolDef;
use qicro_data_core::proto::{MethodDescriptor, ServiceDescriptor};
use qicro_data_core::registry::{ModelMeta, FieldMeta};
use qicro_data_core::ws_registry::{ChannelMeta, WsEventMeta};

// ═══════════════════════════════════════════════════════════════════
//  PROTOBUF
// ═══════════════════════════════════════════════════════════════════

pub fn web_analyzer_proto_services() -> Vec<ServiceDescriptor> {
    vec![
        ServiceDescriptor::new("WebAnalyzerService", "qicro.web_analyzer")
            .description("Web security & intelligence platform — domain info, DNS, SEO, subdomain discovery, security analysis, API scanner, tech detect, contact spy, content scan, Cloudflare bypass, Nmap, geo analysis")
            // Intelligence Gathering
            .method(MethodDescriptor::unary("DomainInfo", "DomainRequest", "DomainInfoResult")
                .description("Domain WHOIS and registration info"))
            .method(MethodDescriptor::unary("DomainDns", "DnsRequest", "DnsResult")
                .description("DNS record analysis"))
            .method(MethodDescriptor::unary("SeoAnalysis", "SeoRequest", "SeoReport")
                .description("SEO analysis of a URL"))
            .method(MethodDescriptor::unary("WebTechDetect", "WebTechRequest", "WebTechResult")
                .description("Detect web technologies, frameworks, and CMS"))
            .method(MethodDescriptor::unary("DomainValidate", "DomainValidateRequest", "ValidationResult")
                .description("Validate domain availability and DNS configuration"))
            .method(MethodDescriptor::unary("DomainValidateBulk", "BulkValidateRequest", "BulkValidateResult")
                .description("Bulk validate multiple domains"))
            // Reconnaissance
            .method(MethodDescriptor::unary("SubdomainDiscovery", "SubdomainRequest", "SubdomainList")
                .description("Discover subdomains via Subfinder integration"))
            .method(MethodDescriptor::unary("ContactSpy", "ContactSpyRequest", "ContactSpyResult")
                .description("Crawl a website to find emails, phones, and social media profiles"))
            .method(MethodDescriptor::unary("ContentScan", "ContentScanRequest", "ScannerResult")
                .description("Advanced content analysis — sitemap, robots, comments, meta extraction"))
            // Security Assessment
            .method(MethodDescriptor::unary("SecurityAnalysis", "SecurityRequest", "SecurityReport")
                .description("Comprehensive security assessment — WAF, SSL, CORS, cookies"))
            .method(MethodDescriptor::unary("SubdomainTakeover", "TakeoverRequest", "TakeoverResult")
                .description("Check subdomains for takeover vulnerabilities across 36+ cloud services"))
            .method(MethodDescriptor::unary("CloudflareBypass", "BypassRequest", "BypassResult")
                .description("Attempt to find real IP behind Cloudflare"))
            .method(MethodDescriptor::unary("NmapScan", "NmapRequest", "NmapScanResult")
                .description("Port scan and service enumeration via Nmap"))
            .method(MethodDescriptor::unary("ApiSecurityScan", "ApiScanRequest", "ApiSecurityReport")
                .description("API endpoint security scanning — SQLi, XSS, SSRF, etc."))
            .method(MethodDescriptor::unary("GeoAnalysis", "GeoRequest", "GeoAnalysisResult")
                .description("IP geolocation and hosting infrastructure analysis")),
    ]
}

// ═══════════════════════════════════════════════════════════════════
//  MCP TOOLS
// ═══════════════════════════════════════════════════════════════════

pub fn web_analyzer_mcp_tools() -> Vec<McpToolDef> {
    vec![
        // Intelligence Gathering
        McpToolDef::new("web_domain_info", "Get domain WHOIS and registration info")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Target domain (e.g. example.com)" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_domain_dns", "Resolve DNS records — A, AAAA, MX, NS, SOA, TXT, CNAME")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Target domain" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_seo_analysis", "SEO analysis for a URL — scores, meta, heading structure")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "url": { "type": "string", "description": "Target URL or domain" } },
                "required": ["url"]
            })),
        McpToolDef::new("web_technology_detect", "Detect web technologies, frameworks, CMS, CDNs, analytics")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Target domain" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_domain_validate", "Validate if a domain is active and properly configured")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Domain to validate" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_domain_validate_bulk", "Bulk validate multiple domains")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domains": { "type": "array", "items": { "type": "string" }, "description": "List of domains" } },
                "required": ["domains"]
            })),
        // Reconnaissance
        McpToolDef::new("web_subdomain_discovery", "Discover subdomains using Subfinder")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Root domain" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_contact_spy", "Crawl website to extract emails, phones, social media profiles")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Target domain" },
                    "max_pages": { "type": "integer", "description": "Max pages to crawl (default 20)", "default": 20 }
                },
                "required": ["domain"]
            })),
        McpToolDef::new("web_content_scan", "Advanced content scanner — sitemap, robots.txt, comments, meta tags")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Target domain" } },
                "required": ["domain"]
            })),
        // Security Assessment
        McpToolDef::new("web_security_scan", "Comprehensive security assessment — WAF, SSL, CORS, cookies")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Target domain" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_subdomain_takeover", "Check subdomains for takeover vulnerabilities (36+ cloud services)")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Root domain" },
                    "subdomains": { "type": "array", "items": { "type": "string" }, "description": "Subdomains to check" }
                },
                "required": ["domain", "subdomains"]
            })),
        McpToolDef::new("web_cloudflare_bypass", "Attempt to find the real IP behind Cloudflare")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Cloudflare-protected domain" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_nmap_scan", "Port scan and service enumeration via Nmap")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Target domain or IP" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_api_security_scan", "API endpoint security scanning — SQLi, XSS, SSRF probes")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "API base URL or domain" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_geo_analysis", "IP geolocation and hosting infrastructure analysis")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string", "description": "Target domain" } },
                "required": ["domain"]
            })),
    ]
}

// ═══════════════════════════════════════════════════════════════════
//  WEBSOCKET CHANNEL
// ═══════════════════════════════════════════════════════════════════

pub fn web_analyzer_websockets() -> Vec<ChannelMeta> {
    vec![ChannelMeta::new("web-analyzer", "/ws/web-analyzer")
        .description("Web Security & Intelligence Analysis Platform")
        .module("web-analyzer")
        // ── Intelligence Gathering ──────────────────────────────
        .event(
            WsEventMeta::new("domain_info", "client_to_server")
                .summary("Get domain WHOIS and registration info")
                .payload_type("DomainInfoRequest"),
        )
        .event(
            WsEventMeta::new("domain_info_result", "server_to_client")
                .summary("Result of domain info gather")
                .payload_type("DomainInfoResult"),
        )
        .event(
            WsEventMeta::new("domain_dns", "client_to_server")
                .summary("Get DNS records for a domain")
                .payload_type("DnsRequest"),
        )
        .event(
            WsEventMeta::new("domain_dns_result", "server_to_client")
                .summary("Result of DNS analysis")
                .payload_type("DnsResult"),
        )
        .event(
            WsEventMeta::new("seo_analysis", "client_to_server")
                .summary("SEO analysis of a URL/domain")
                .payload_type("SeoRequest"),
        )
        .event(
            WsEventMeta::new("seo_analysis_result", "server_to_client")
                .summary("Result of SEO analysis")
                .payload_type("SeoReport"),
        )
        .event(
            WsEventMeta::new("web_technologies", "client_to_server")
                .summary("Detect web technologies and frameworks")
                .payload_type("WebTechRequest"),
        )
        .event(
            WsEventMeta::new("web_technologies_result", "server_to_client")
                .summary("Result of web technology detection")
                .payload_type("WebTechResult"),
        )
        .event(
            WsEventMeta::new("domain_validate", "client_to_server")
                .summary("Validate domain status and DNS config")
                .payload_type("DomainValidateRequest"),
        )
        .event(
            WsEventMeta::new("domain_validate_result", "server_to_client")
                .summary("Result of domain validation")
                .payload_type("ValidationResult"),
        )
        .event(
            WsEventMeta::new("domain_validate_bulk", "client_to_server")
                .summary("Bulk validate multiple domains")
                .payload_type("BulkValidateRequest"),
        )
        .event(
            WsEventMeta::new("domain_validate_bulk_result", "server_to_client")
                .summary("Result of bulk domain validation")
                .payload_type("BulkValidateResult"),
        )
        // ── Reconnaissance ──────────────────────────────────────
        .event(
            WsEventMeta::new("subdomain_discovery", "client_to_server")
                .summary("Discover subdomains via Subfinder")
                .payload_type("SubdomainRequest"),
        )
        .event(
            WsEventMeta::new("subdomain_discovery_result", "server_to_client")
                .summary("Result of subdomain discovery")
                .payload_type("SubdomainList"),
        )
        .event(
            WsEventMeta::new("contact_spy", "client_to_server")
                .summary("Crawl website for emails/phones/social")
                .payload_type("ContactSpyRequest"),
        )
        .event(
            WsEventMeta::new("contact_spy_result", "server_to_client")
                .summary("Result of contact crawl")
                .payload_type("ContactSpyResult"),
        )
        .event(
            WsEventMeta::new("content_scan", "client_to_server")
                .summary("Advanced content analysis")
                .payload_type("ContentScanRequest"),
        )
        .event(
            WsEventMeta::new("content_scan_result", "server_to_client")
                .summary("Result of content analysis")
                .payload_type("ScannerResult"),
        )
        // ── Security Assessment ─────────────────────────────────
        .event(
            WsEventMeta::new("security_analysis", "client_to_server")
                .summary("Determine security posture of a domain")
                .payload_type("SecurityRequest"),
        )
        .event(
            WsEventMeta::new("security_analysis_result", "server_to_client")
                .summary("Result of security analysis")
                .payload_type("SecurityReport"),
        )
        .event(
            WsEventMeta::new("subdomain_takeover", "client_to_server")
                .summary("Check subdomains for takeover vulnerabilities")
                .payload_type("TakeoverRequest"),
        )
        .event(
            WsEventMeta::new("subdomain_takeover_result", "server_to_client")
                .summary("Result of subdomain takeover check")
                .payload_type("TakeoverResult"),
        )
        .event(
            WsEventMeta::new("cloudflare_bypass", "client_to_server")
                .summary("Find real IP behind Cloudflare")
                .payload_type("BypassRequest"),
        )
        .event(
            WsEventMeta::new("cloudflare_bypass_result", "server_to_client")
                .summary("Result of Cloudflare bypass attempt")
                .payload_type("BypassResult"),
        )
        .event(
            WsEventMeta::new("nmap_scan", "client_to_server")
                .summary("Port scan and service enumeration")
                .payload_type("NmapRequest"),
        )
        .event(
            WsEventMeta::new("nmap_scan_result", "server_to_client")
                .summary("Result of Nmap scan")
                .payload_type("NmapScanResult"),
        )
        .event(
            WsEventMeta::new("api_security_scan", "client_to_server")
                .summary("Scan API for security vulnerabilities")
                .payload_type("ApiScanRequest"),
        )
        .event(
            WsEventMeta::new("api_security_scan_result", "server_to_client")
                .summary("Result of API security scan")
                .payload_type("ApiSecurityReport"),
        )
        .event(
            WsEventMeta::new("geo_analysis", "client_to_server")
                .summary("IP geolocation and hosting analysis")
                .payload_type("GeoRequest"),
        )
        .event(
            WsEventMeta::new("geo_analysis_result", "server_to_client")
                .summary("Result of geo analysis")
                .payload_type("GeoAnalysisResult"),
        )]
}

// ═══════════════════════════════════════════════════════════════════
//  GRAPHQL OPERATIONS
// ═══════════════════════════════════════════════════════════════════

pub fn web_analyzer_graphql_operations() -> Vec<GraphqlOperationMeta> {
    vec![
        // Intelligence Gathering
        GraphqlOperationMeta::new("webDomainInfo", "query")
            .summary("Domain WHOIS info")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webDomainDns", "query")
            .summary("DNS record resolution")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webSeoAnalysis", "query")
            .summary("SEO analysis")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webTechnologyDetect", "query")
            .summary("Detect web technologies and frameworks")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webDomainValidate", "query")
            .summary("Validate domain config")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webDomainValidateBulk", "query")
            .summary("Bulk validate domains")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        // Reconnaissance
        GraphqlOperationMeta::new("webSubdomainDiscovery", "query")
            .summary("Subdomain enumeration")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webContactSpy", "query")
            .summary("Crawl for emails/phones/social")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webContentScan", "query")
            .summary("Advanced content analysis")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        // Security Assessment
        GraphqlOperationMeta::new("webSecurityScan", "query")
            .summary("Security assessment")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webSubdomainTakeover", "query")
            .summary("Subdomain takeover analysis")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webCloudflareBypass", "query")
            .summary("Find real IP behind Cloudflare")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webNmapScan", "query")
            .summary("Port scan and services")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webApiSecurityScan", "query")
            .summary("API security scanning")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
        GraphqlOperationMeta::new("webGeoAnalysis", "query")
            .summary("IP geolocation and hosting analysis")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .return_type("JSON!"),
    ]
}

// ═══════════════════════════════════════════════════════════════════
//  GRAPHQL TYPES
// ═══════════════════════════════════════════════════════════════════

pub fn web_analyzer_graphql_types() -> Vec<GraphqlTypeMeta> {
    vec![
        GraphqlTypeMeta::new("DomainInfoResult", "object")
            .description("Domain WHOIS and registration data")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("registrar", "String"))
            .field(GraphqlFieldMeta::new("creation_date", "String"))
            .field(GraphqlFieldMeta::new("expiration_date", "String"))
            .field(GraphqlFieldMeta::new("name_servers", "[String!]!")),
        GraphqlTypeMeta::new("DomainDnsResult", "object")
            .description("DNS records for a domain")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("a_records", "[String!]!"))
            .field(GraphqlFieldMeta::new("aaaa_records", "[String!]!"))
            .field(GraphqlFieldMeta::new("mx_records", "[String!]!"))
            .field(GraphqlFieldMeta::new("ns_records", "[String!]!"))
            .field(GraphqlFieldMeta::new("txt_records", "[String!]!")),
        GraphqlTypeMeta::new("SecurityAnalysisResult", "object")
            .description("Security assessment report")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("grade", "String!"))
            .field(GraphqlFieldMeta::new("score", "Int!"))
            .field(GraphqlFieldMeta::new("waf_detected", "Boolean!"))
            .field(GraphqlFieldMeta::new("ssl_grade", "String")),
        GraphqlTypeMeta::new("SeoAnalysisResult", "object")
            .description("SEO analysis report")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("overall_score", "Int!"))
            .field(GraphqlFieldMeta::new("issues_count", "Int!"))
            .field(GraphqlFieldMeta::new("categories", "JSON!")),
        GraphqlTypeMeta::new("WebTechResult", "object")
            .description("Detected web technologies")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("technologies", "JSON!")),
        GraphqlTypeMeta::new("ContactSpyResult", "object")
            .description("Contact information extracted from website")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("emails", "[String!]!"))
            .field(GraphqlFieldMeta::new("phones", "[String!]!"))
            .field(GraphqlFieldMeta::new("social_media", "JSON!"))
            .field(GraphqlFieldMeta::new("pages_scanned", "Int!")),
        GraphqlTypeMeta::new("TakeoverResult", "object")
            .description("Subdomain takeover vulnerability report")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("statistics", "JSON!"))
            .field(GraphqlFieldMeta::new("vulnerable", "JSON!")),
        GraphqlTypeMeta::new("GeoAnalysisResult", "object")
            .description("IP geolocation and hosting data")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("ip", "String"))
            .field(GraphqlFieldMeta::new("country", "String"))
            .field(GraphqlFieldMeta::new("hosting_provider", "String")),
    ]
}

// ═══════════════════════════════════════════════════════════════════
//  REST ENDPOINTS
// ═══════════════════════════════════════════════════════════════════

pub fn web_analyzer_endpoint_metas() -> Vec<EndpointMeta> {
    vec![
        // Intelligence Gathering
        EndpointMeta::new(
            "web_analyzer.domain_info",
            "POST",
            "/web-analyzer/domain-info",
        )
        .summary("Get domain WHOIS and registration info")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Target domain"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.domain_dns",
            "POST",
            "/web-analyzer/domain-dns",
        )
        .summary("Resolve DNS records")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Target domain"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.seo_analysis",
            "POST",
            "/web-analyzer/seo-analysis",
        )
        .summary("SEO analysis")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Target URL/domain"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.web_technologies",
            "POST",
            "/web-analyzer/web-technologies",
        )
        .summary("Detect web technologies")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Target domain"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.domain_validate",
            "POST",
            "/web-analyzer/domain-validate",
        )
        .summary("Validate domain status")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Domain to validate"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.domain_validate_bulk",
            "POST",
            "/web-analyzer/domain-validate-bulk",
        )
        .summary("Bulk validate domains")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domains", "body", "[String]").description("List of domains"))
        .tag("web-analyzer"),
        // Reconnaissance
        EndpointMeta::new(
            "web_analyzer.subdomain_discovery",
            "POST",
            "/web-analyzer/subdomain-discovery",
        )
        .summary("Discover subdomains")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Root domain"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.contact_spy",
            "POST",
            "/web-analyzer/contact-spy",
        )
        .summary("Crawl for contact information")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Target domain"))
        .param(ParamMeta::new("max_pages", "body", "Integer").description("Max pages to crawl"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.content_scan",
            "POST",
            "/web-analyzer/content-scan",
        )
        .summary("Advanced content analysis")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Target domain"))
        .tag("web-analyzer"),
        // Security Assessment
        EndpointMeta::new(
            "web_analyzer.security_analysis",
            "POST",
            "/web-analyzer/security-analysis",
        )
        .summary("Security assessment")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Target domain"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.subdomain_takeover",
            "POST",
            "/web-analyzer/subdomain-takeover",
        )
        .summary("Subdomain takeover check")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Root domain"))
        .param(ParamMeta::new("subdomains", "body", "[String]").description("Subdomains to check"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.cloudflare_bypass",
            "POST",
            "/web-analyzer/cloudflare-bypass",
        )
        .summary("Find real IP behind Cloudflare")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(
            ParamMeta::new("domain", "body", "String").description("Cloudflare-protected domain"),
        )
        .tag("web-analyzer"),
        EndpointMeta::new("web_analyzer.nmap_scan", "POST", "/web-analyzer/nmap-scan")
            .summary("Port scan and service enumeration")
            .module("web-analyzer")
            .source_crate("qicro-web-analyzer")
            .param(ParamMeta::new("domain", "body", "String").description("Target domain or IP"))
            .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.api_security_scan",
            "POST",
            "/web-analyzer/api-security-scan",
        )
        .summary("API security scanning")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("API base URL"))
        .tag("web-analyzer"),
        EndpointMeta::new(
            "web_analyzer.geo_analysis",
            "POST",
            "/web-analyzer/geo-analysis",
        )
        .summary("IP geolocation analysis")
        .module("web-analyzer")
        .source_crate("qicro-web-analyzer")
        .param(ParamMeta::new("domain", "body", "String").description("Target domain"))
        .tag("web-analyzer"),
    ]
}

// ═══════════════════════════════════════════════════════════════════
//  MODEL TYPES
// ═══════════════════════════════════════════════════════════════════

pub fn web_analyzer_model_metas() -> Vec<ModelMeta> {
    vec![
        // ── domain_info ─────────────────────────────────────────
        ModelMeta::new("DomainInfoResult", "domain_info_results")
            .description("Domain WHOIS and registration data")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("whois", "WhoisInfo").nullable())
            .field(FieldMeta::new("ssl", "SslInfo").nullable())
            .field(FieldMeta::new("dns", "DnsInfo").nullable())
            .field(FieldMeta::new("security", "SecurityInfo").nullable())
            .field(FieldMeta::new("server", "String").nullable())
            .field(FieldMeta::new("ip_address", "String").nullable()),
        ModelMeta::new("WhoisInfo", "whois_info")
            .description("WHOIS registration details")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("registrar", "String").nullable())
            .field(FieldMeta::new("creation_date", "String").nullable())
            .field(FieldMeta::new("expiration_date", "String").nullable())
            .field(FieldMeta::new("updated_date", "String").nullable())
            .field(FieldMeta::new("name_servers", "Vec<String>"))
            .field(FieldMeta::new("status", "Vec<String>"))
            .field(FieldMeta::new("registrant_org", "String").nullable()),
        ModelMeta::new("SslInfo", "ssl_info")
            .description("SSL/TLS certificate details")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("issuer", "String"))
            .field(FieldMeta::new("subject", "String"))
            .field(FieldMeta::new("valid_from", "String"))
            .field(FieldMeta::new("valid_to", "String"))
            .field(FieldMeta::new("protocol", "String"))
            .field(FieldMeta::new("cipher", "String"))
            .field(FieldMeta::new("key_size", "u32"))
            .field(FieldMeta::new("san", "Vec<String>"))
            .field(FieldMeta::new("is_valid", "bool")),
        ModelMeta::new("SecurityInfo", "security_info")
            .description("Basic domain security indicators")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("has_https", "bool"))
            .field(FieldMeta::new("has_hsts", "bool"))
            .field(FieldMeta::new("security_headers", "Vec<String>")),

        // ── domain_dns ──────────────────────────────────────────
        ModelMeta::new("DomainDnsResult", "domain_dns_results")
            .description("DNS record resolution results")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("records", "DnsRecords")),
        ModelMeta::new("DnsRecords", "dns_records")
            .description("Collection of DNS records by type")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("a", "Vec<String>"))
            .field(FieldMeta::new("aaaa", "Vec<String>"))
            .field(FieldMeta::new("mx", "Vec<String>"))
            .field(FieldMeta::new("ns", "Vec<String>"))
            .field(FieldMeta::new("txt", "Vec<String>"))
            .field(FieldMeta::new("cname", "Vec<String>"))
            .field(FieldMeta::new("soa", "Vec<String>")),

        // ── web_technologies ────────────────────────────────────
        ModelMeta::new("WebTechResult", "web_tech_results")
            .description("Detected web technologies, frameworks, and security posture")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("web_server", "Vec<String>"))
            .field(FieldMeta::new("backend", "Vec<String>"))
            .field(FieldMeta::new("frontend", "Vec<String>"))
            .field(FieldMeta::new("js_libraries", "Vec<String>"))
            .field(FieldMeta::new("css_frameworks", "Vec<String>"))
            .field(FieldMeta::new("cms", "Vec<String>"))
            .field(FieldMeta::new("ecommerce", "Vec<String>"))
            .field(FieldMeta::new("cdn", "Vec<String>"))
            .field(FieldMeta::new("analytics", "Vec<String>"))
            .field(FieldMeta::new("security_headers", "Vec<SecurityHeaderInfo>"))
            .field(FieldMeta::new("security_vulnerabilities", "Vec<VulnerabilityInfo>"))
            .field(FieldMeta::new("information_disclosure", "Vec<DisclosureInfo>"))
            .field(FieldMeta::new("security_services", "Vec<SecurityServicesInfo>"))
            .field(FieldMeta::new("cookie_security", "Vec<CookieSecurityInfo>"))
            .field(FieldMeta::new("is_wordpress", "bool"))
            .field(FieldMeta::new("wordpress_analysis", "Option<WordPressAnalysis>").nullable())
            .field(FieldMeta::new("security_score", "SecurityScoreResult")),
        ModelMeta::new("SecurityHeaderInfo", "security_header_info")
            .description("Status of a specific security header")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("name", "String"))
            .field(FieldMeta::new("present", "bool"))
            .field(FieldMeta::new("value", "String").nullable())
            .field(FieldMeta::new("severity", "String")),
        ModelMeta::new("VulnerabilityInfo", "vulnerability_info")
            .description("Detected vulnerability detail")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("name", "String"))
            .field(FieldMeta::new("description", "String"))
            .field(FieldMeta::new("severity", "String")),
        ModelMeta::new("DisclosureInfo", "disclosure_info")
            .description("Information disclosure finding")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("type_name", "String"))
            .field(FieldMeta::new("detail", "String"))
            .field(FieldMeta::new("severity", "String")),
        ModelMeta::new("SecurityServicesInfo", "security_services_info")
            .description("Detected security service (WAF, CDN protection)")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("name", "String"))
            .field(FieldMeta::new("detected", "bool")),
        ModelMeta::new("CookieSecurityInfo", "cookie_security_info")
            .description("Cookie security analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("name", "String"))
            .field(FieldMeta::new("secure", "bool"))
            .field(FieldMeta::new("http_only", "bool"))
            .field(FieldMeta::new("same_site", "String").nullable()),
        ModelMeta::new("WordPressAnalysis", "wordpress_analysis")
            .description("WordPress-specific security analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("confidence", "String"))
            .field(FieldMeta::new("version", "String"))
            .field(FieldMeta::new("theme", "String"))
            .field(FieldMeta::new("plugins", "Vec<String>"))
            .field(FieldMeta::new("users_found", "Vec<WpUser>"))
            .field(FieldMeta::new("rest_api_enabled", "bool"))
            .field(FieldMeta::new("xmlrpc_enabled", "bool"))
            .field(FieldMeta::new("admin_accessible", "bool"))
            .field(FieldMeta::new("login_accessible", "bool"))
            .field(FieldMeta::new("debug_enabled", "bool"))
            .field(FieldMeta::new("security_issues", "Vec<String>")),
        ModelMeta::new("WpUser", "wp_users")
            .description("WordPress user enumerated via REST API")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("id", "u64"))
            .field(FieldMeta::new("name", "String"))
            .field(FieldMeta::new("slug", "String")),
        ModelMeta::new("WebTechSecurityScoreResult", "web_tech_security_scores")
            .description("Computed security score from technology detection")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("score", "u32"))
            .field(FieldMeta::new("grade", "String"))
            .field(FieldMeta::new("details", "Vec<String>")),

        // ── security_analysis ───────────────────────────────────
        ModelMeta::new("SecurityAnalysisResult", "security_analysis_results")
            .description("Comprehensive security assessment report")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("waf", "WafDetectionResult"))
            .field(FieldMeta::new("headers", "SecurityHeadersResult"))
            .field(FieldMeta::new("ssl", "SslAnalysisResult"))
            .field(FieldMeta::new("cors", "CorsPolicyResult"))
            .field(FieldMeta::new("cookies", "CookieSecurityResult"))
            .field(FieldMeta::new("http_methods", "HttpMethodsResult"))
            .field(FieldMeta::new("server_info", "ServerInfoResult"))
            .field(FieldMeta::new("vuln_scan", "VulnScanResult"))
            .field(FieldMeta::new("security_score", "SecurityScoreResult")),
        ModelMeta::new("WafMatch", "waf_matches")
            .description("WAF pattern match result")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("name", "String"))
            .field(FieldMeta::new("category", "String"))
            .field(FieldMeta::new("confidence", "String"))
            .field(FieldMeta::new("evidence", "Vec<String>")),
        ModelMeta::new("WafDetectionResult", "waf_detection_results")
            .description("Web Application Firewall detection")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("detected", "bool"))
            .field(FieldMeta::new("matches", "Vec<WafMatch>"))
            .field(FieldMeta::new("top_match", "String").nullable()),
        ModelMeta::new("HeaderAnalysis", "header_analyses")
            .description("Individual HTTP header analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("name", "String"))
            .field(FieldMeta::new("present", "bool"))
            .field(FieldMeta::new("value", "String").nullable())
            .field(FieldMeta::new("severity", "String"))
            .field(FieldMeta::new("recommendation", "String")),
        ModelMeta::new("SecurityHeadersResult", "security_headers_results")
            .description("HTTP security headers assessment")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("score", "u32"))
            .field(FieldMeta::new("headers", "Vec<HeaderAnalysis>")),
        ModelMeta::new("SslAnalysisResult", "ssl_analysis_results")
            .description("SSL/TLS security analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("valid", "bool"))
            .field(FieldMeta::new("issuer", "String"))
            .field(FieldMeta::new("protocol", "String"))
            .field(FieldMeta::new("cipher", "String"))
            .field(FieldMeta::new("key_size", "u32"))
            .field(FieldMeta::new("grade", "String"))
            .field(FieldMeta::new("expires_days", "i64"))
            .field(FieldMeta::new("issues", "Vec<String>")),
        ModelMeta::new("CorsPolicyResult", "cors_policy_results")
            .description("CORS policy analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("enabled", "bool"))
            .field(FieldMeta::new("allow_origin", "String").nullable())
            .field(FieldMeta::new("allow_credentials", "bool"))
            .field(FieldMeta::new("issues", "Vec<String>")),
        ModelMeta::new("CookieSecurityResult", "cookie_security_results")
            .description("Cookie security flags audit")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("total", "usize"))
            .field(FieldMeta::new("secure_count", "usize"))
            .field(FieldMeta::new("httponly_count", "usize"))
            .field(FieldMeta::new("issues", "Vec<String>")),
        ModelMeta::new("HttpMethodsResult", "http_methods_results")
            .description("Allowed HTTP methods analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("allowed", "Vec<String>"))
            .field(FieldMeta::new("dangerous", "Vec<String>"))
            .field(FieldMeta::new("issues", "Vec<String>")),
        ModelMeta::new("ServerInfoResult", "server_info_results")
            .description("Server information disclosure")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("server", "String").nullable())
            .field(FieldMeta::new("powered_by", "String").nullable())
            .field(FieldMeta::new("technologies", "Vec<String>"))
            .field(FieldMeta::new("issues", "Vec<String>")),
        ModelMeta::new("VulnerabilityFound", "vulnerabilities_found")
            .description("Individual vulnerability finding")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("name", "String"))
            .field(FieldMeta::new("severity", "String"))
            .field(FieldMeta::new("description", "String"))
            .field(FieldMeta::new("remediation", "String")),
        ModelMeta::new("VulnScanResult", "vuln_scan_results")
            .description("Vulnerability scan results")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("total", "usize"))
            .field(FieldMeta::new("critical", "usize"))
            .field(FieldMeta::new("findings", "Vec<VulnerabilityFound>")),
        ModelMeta::new("SecurityScoreResult", "security_score_results")
            .description("Overall security score computation")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("score", "u32"))
            .field(FieldMeta::new("grade", "String"))
            .field(FieldMeta::new("summary", "String")),

        // ── seo_analysis ────────────────────────────────────────
        ModelMeta::new("SeoAnalysisResult", "seo_analysis_results")
            .description("Comprehensive SEO analysis report")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("overall_score", "u32"))
            .field(FieldMeta::new("basic", "BasicSeoResult"))
            .field(FieldMeta::new("content", "ContentAnalysisResult"))
            .field(FieldMeta::new("technical", "TechnicalSeoResult"))
            .field(FieldMeta::new("social", "SocialMediaResult"))
            .field(FieldMeta::new("performance", "PerformanceResult"))
            .field(FieldMeta::new("accessibility", "MobileAccessibilityResult"))
            .field(FieldMeta::new("schema_markup", "SchemaMarkupResult")),
        ModelMeta::new("TitleAnalysis", "title_analyses")
            .description("HTML title tag analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("text", "String"))
            .field(FieldMeta::new("length", "usize"))
            .field(FieldMeta::new("is_optimal", "bool")),
        ModelMeta::new("MetaDescAnalysis", "meta_desc_analyses")
            .description("Meta description analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("text", "String"))
            .field(FieldMeta::new("length", "usize"))
            .field(FieldMeta::new("is_optimal", "bool")),
        ModelMeta::new("BasicSeoResult", "basic_seo_results")
            .description("Basic SEO metrics — title, description, canonical, etc.")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("title", "TitleAnalysis"))
            .field(FieldMeta::new("meta_description", "MetaDescAnalysis"))
            .field(FieldMeta::new("has_canonical", "bool"))
            .field(FieldMeta::new("has_robots_meta", "bool"))
            .field(FieldMeta::new("has_viewport", "bool"))
            .field(FieldMeta::new("has_lang", "bool"))
            .field(FieldMeta::new("score", "u32")),
        ModelMeta::new("HeadingInfo", "heading_infos")
            .description("Heading element info")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("level", "String"))
            .field(FieldMeta::new("text", "String")),
        ModelMeta::new("KeywordInfo", "keyword_infos")
            .description("Keyword density analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("word", "String"))
            .field(FieldMeta::new("count", "usize"))
            .field(FieldMeta::new("density", "f64")),
        ModelMeta::new("ContentAnalysisResult", "content_analysis_results")
            .description("Content quality and keyword analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("word_count", "usize"))
            .field(FieldMeta::new("headings", "Vec<HeadingInfo>"))
            .field(FieldMeta::new("keywords", "Vec<KeywordInfo>"))
            .field(FieldMeta::new("images_count", "usize"))
            .field(FieldMeta::new("links_internal", "usize"))
            .field(FieldMeta::new("links_external", "usize"))
            .field(FieldMeta::new("score", "u32")),
        ModelMeta::new("TechnicalSeoResult", "technical_seo_results")
            .description("Technical SEO audit")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("has_sitemap", "bool"))
            .field(FieldMeta::new("has_robots_txt", "bool"))
            .field(FieldMeta::new("is_https", "bool"))
            .field(FieldMeta::new("is_mobile_friendly", "bool"))
            .field(FieldMeta::new("structured_data_count", "usize"))
            .field(FieldMeta::new("score", "u32")),
        ModelMeta::new("SocialMediaResult", "social_media_results")
            .description("Open Graph and Twitter Card presence")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("has_og_tags", "bool"))
            .field(FieldMeta::new("has_twitter_cards", "bool"))
            .field(FieldMeta::new("score", "u32")),
        ModelMeta::new("PerformanceResult", "performance_results")
            .description("Page size and performance metrics")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("html_size", "usize"))
            .field(FieldMeta::new("total_resources", "usize"))
            .field(FieldMeta::new("has_minified_css", "bool"))
            .field(FieldMeta::new("has_minified_js", "bool"))
            .field(FieldMeta::new("has_compression", "bool"))
            .field(FieldMeta::new("score", "u32")),
        ModelMeta::new("AltAttributeResult", "alt_attribute_results")
            .description("Image alt attribute accessibility audit")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("total_images", "usize"))
            .field(FieldMeta::new("with_alt", "usize"))
            .field(FieldMeta::new("without_alt", "usize"))
            .field(FieldMeta::new("empty_alt", "usize")),
        ModelMeta::new("MobileAccessibilityResult", "mobile_accessibility_results")
            .description("Mobile-friendliness and accessibility")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("has_viewport", "bool"))
            .field(FieldMeta::new("has_aria", "bool"))
            .field(FieldMeta::new("alt_attributes", "AltAttributeResult"))
            .field(FieldMeta::new("score", "u32")),
        ModelMeta::new("SchemaMarkupResult", "schema_markup_results")
            .description("JSON-LD / schema.org structured data")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("has_schema", "bool"))
            .field(FieldMeta::new("types", "Vec<String>"))
            .field(FieldMeta::new("score", "u32")),

        // ── domain_validator ────────────────────────────────────
        ModelMeta::new("ValidationResult", "validation_results")
            .description("Single domain validation result")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("is_valid", "bool"))
            .field(FieldMeta::new("dns", "DnsValidation"))
            .field(FieldMeta::new("http", "HttpValidation"))
            .field(FieldMeta::new("ssl", "SslValidation")),
        ModelMeta::new("DnsValidation", "dns_validations")
            .description("DNS reachability check")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("resolves", "bool"))
            .field(FieldMeta::new("ip_addresses", "Vec<String>")),
        ModelMeta::new("HttpValidation", "http_validations")
            .description("HTTP reachability and redirect check")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("reachable", "bool"))
            .field(FieldMeta::new("status_code", "u16").nullable())
            .field(FieldMeta::new("redirects_to_https", "bool"))
            .field(FieldMeta::new("response_time_ms", "u64").nullable()),
        ModelMeta::new("SslValidation", "ssl_validations")
            .description("SSL certificate validity check")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("valid", "bool"))
            .field(FieldMeta::new("issuer", "String").nullable())
            .field(FieldMeta::new("expires_in_days", "i64").nullable()),
        ModelMeta::new("ValidationStats", "validation_stats")
            .description("Bulk validation statistics")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("total", "usize"))
            .field(FieldMeta::new("valid", "usize"))
            .field(FieldMeta::new("invalid", "usize"))
            .field(FieldMeta::new("dns_ok", "usize"))
            .field(FieldMeta::new("http_ok", "usize"))
            .field(FieldMeta::new("ssl_ok", "usize"))
            .field(FieldMeta::new("duration_ms", "u64")),
        ModelMeta::new("BulkValidationResult", "bulk_validation_results")
            .description("Bulk domain validation results with stats")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("results", "Vec<ValidationResult>"))
            .field(FieldMeta::new("stats", "ValidationStats")),

        // ── subdomain_discovery ─────────────────────────────────
        ModelMeta::new("SubdomainDiscoveryResult", "subdomain_discovery_results")
            .description("Discovered subdomains via Subfinder")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("subdomains", "Vec<String>"))
            .field(FieldMeta::new("total", "usize"))
            .field(FieldMeta::new("sources", "Vec<String>")),

        // ── contact_spy ─────────────────────────────────────────
        ModelMeta::new("SocialProfile", "social_profiles")
            .description("Social media profile link")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("platform", "String"))
            .field(FieldMeta::new("url", "String"))
            .field(FieldMeta::new("username", "String").nullable()),
        ModelMeta::new("ContactSpyResult", "contact_spy_results")
            .description("Extracted contact information from website crawl")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("emails", "Vec<String>"))
            .field(FieldMeta::new("phones", "Vec<String>"))
            .field(FieldMeta::new("social_profiles", "Vec<SocialProfile>"))
            .field(FieldMeta::new("pages_scanned", "usize")),

        // ── advanced_content_scanner ────────────────────────────
        ModelMeta::new("SecretFinding", "secret_findings")
            .description("Exposed secret or credential in page content")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("secret_type", "String"))
            .field(FieldMeta::new("value", "String"))
            .field(FieldMeta::new("location", "String"))
            .field(FieldMeta::new("severity", "String")),
        ModelMeta::new("JsVulnerability", "js_vulnerabilities")
            .description("JavaScript vulnerability finding")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("library", "String"))
            .field(FieldMeta::new("version", "String").nullable())
            .field(FieldMeta::new("issue", "String"))
            .field(FieldMeta::new("severity", "String")),
        ModelMeta::new("SsrfFinding", "ssrf_findings")
            .description("Server-Side Request Forgery indicator")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("url", "String"))
            .field(FieldMeta::new("parameter", "String"))
            .field(FieldMeta::new("evidence", "String")),
        ModelMeta::new("ScanSummary", "scan_summaries")
            .description("Content scan summary metrics")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("pages_scanned", "usize"))
            .field(FieldMeta::new("secrets_found", "usize"))
            .field(FieldMeta::new("js_issues", "usize"))
            .field(FieldMeta::new("ssrf_indicators", "usize")),
        ModelMeta::new("ScannerResult", "scanner_results")
            .description("Advanced content scanner full result")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("secrets", "Vec<SecretFinding>"))
            .field(FieldMeta::new("js_vulnerabilities", "Vec<JsVulnerability>"))
            .field(FieldMeta::new("ssrf_findings", "Vec<SsrfFinding>"))
            .field(FieldMeta::new("summary", "ScanSummary")),

        // ── subdomain_takeover ──────────────────────────────────
        ModelMeta::new("DnsCheckResult", "dns_check_results")
            .description("DNS check for a subdomain (CNAME, A, resolved status)")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("subdomain", "String"))
            .field(FieldMeta::new("cname", "String").nullable())
            .field(FieldMeta::new("a_records", "Vec<String>"))
            .field(FieldMeta::new("is_dangling", "bool")),
        ModelMeta::new("TakeoverVulnerability", "takeover_vulnerabilities")
            .description("Subdomain potentially vulnerable to takeover")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("subdomain", "String"))
            .field(FieldMeta::new("service", "String"))
            .field(FieldMeta::new("cname", "String"))
            .field(FieldMeta::new("status", "String"))
            .field(FieldMeta::new("confidence", "String"))
            .field(FieldMeta::new("fingerprint", "String")),
        ModelMeta::new("ScanStatistics", "scan_statistics")
            .description("Subdomain takeover scan statistics")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("total_checked", "usize"))
            .field(FieldMeta::new("vulnerable", "usize"))
            .field(FieldMeta::new("dangling_cnames", "usize"))
            .field(FieldMeta::new("duration_ms", "u64")),
        ModelMeta::new("TakeoverResult", "takeover_results")
            .description("Full subdomain takeover scan results")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("vulnerabilities", "Vec<TakeoverVulnerability>"))
            .field(FieldMeta::new("dns_results", "Vec<DnsCheckResult>"))
            .field(FieldMeta::new("statistics", "ScanStatistics")),

        // ── cloudflare_bypass ───────────────────────────────────
        ModelMeta::new("FoundIp", "found_ips")
            .description("IP address found behind Cloudflare")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("ip", "String"))
            .field(FieldMeta::new("source", "String"))
            .field(FieldMeta::new("confidence", "String")),
        ModelMeta::new("CloudflareBypassResult", "cloudflare_bypass_results")
            .description("Cloudflare real-IP discovery results")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("is_cloudflare", "bool"))
            .field(FieldMeta::new("found_ips", "Vec<FoundIp>"))
            .field(FieldMeta::new("methods_tried", "Vec<String>")),

        // ── nmap_zero_day ───────────────────────────────────────
        ModelMeta::new("PortInfo", "port_infos")
            .description("Open port with service details")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("port", "u16"))
            .field(FieldMeta::new("protocol", "String"))
            .field(FieldMeta::new("state", "String"))
            .field(FieldMeta::new("service", "String"))
            .field(FieldMeta::new("version", "String").nullable())
            .field(FieldMeta::new("banner", "String").nullable()),
        ModelMeta::new("NmapVulnerabilityInfo", "nmap_vulnerability_infos")
            .description("Vulnerability associated with an open port/service")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("cve_id", "String"))
            .field(FieldMeta::new("title", "String"))
            .field(FieldMeta::new("severity", "SeverityInfo")),
        ModelMeta::new("SeverityInfo", "severity_infos")
            .description("Vulnerability severity rating")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("level", "String"))
            .field(FieldMeta::new("score", "f64")),
        ModelMeta::new("NmapDnsInfo", "nmap_dns_infos")
            .description("DNS resolution info used by Nmap scanner")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("hostname", "String"))
            .field(FieldMeta::new("ip_addresses", "Vec<String>"))
            .field(FieldMeta::new("reverse_dns", "String").nullable()),
        ModelMeta::new("NmapScanResult", "nmap_scan_results")
            .description("Full Nmap port scan and service enumeration results")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("target", "String"))
            .field(FieldMeta::new("dns", "NmapDnsInfo"))
            .field(FieldMeta::new("ports", "Vec<PortInfo>"))
            .field(FieldMeta::new("vulnerabilities", "Vec<NmapVulnerabilityInfo>"))
            .field(FieldMeta::new("os_detection", "String").nullable()),

        // ── api_security_scanner ────────────────────────────────
        ModelMeta::new("ApiEndpoint", "api_endpoints")
            .description("Discovered API endpoint")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("url", "String"))
            .field(FieldMeta::new("method", "String"))
            .field(FieldMeta::new("status", "u16")),
        ModelMeta::new("ApiVulnerabilityFinding", "api_vulnerability_findings")
            .description("API security vulnerability finding (SQLi, XSS, SSRF, etc.)")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("endpoint", "String"))
            .field(FieldMeta::new("vuln_type", "String"))
            .field(FieldMeta::new("severity", "String"))
            .field(FieldMeta::new("description", "String"))
            .field(FieldMeta::new("evidence", "String").nullable())
            .field(FieldMeta::new("remediation", "String")),
        ModelMeta::new("ApiScanResult", "api_scan_results")
            .description("API security scan results")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("endpoints", "Vec<ApiEndpoint>"))
            .field(FieldMeta::new("findings", "Vec<ApiVulnerabilityFinding>"))
            .field(FieldMeta::new("total_endpoints", "usize"))
            .field(FieldMeta::new("total_vulnerabilities", "usize")),

        // ── geo_analysis ────────────────────────────────────────
        ModelMeta::new("GeoAnalysisResult", "geo_analysis_results")
            .description("IP geolocation and hosting infrastructure analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("domain", "String"))
            .field(FieldMeta::new("ip", "String").nullable())
            .field(FieldMeta::new("country", "String").nullable())
            .field(FieldMeta::new("city", "String").nullable())
            .field(FieldMeta::new("isp", "String").nullable())
            .field(FieldMeta::new("hosting_provider", "String").nullable()),
        ModelMeta::new("LlmsTxtResult", "llms_txt_results")
            .description("LLMs.txt file analysis result")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("exists", "bool"))
            .field(FieldMeta::new("content", "String").nullable()),
        ModelMeta::new("WebMcpResult", "web_mcp_results")
            .description("Web MCP server discovery result")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("has_mcp", "bool"))
            .field(FieldMeta::new("endpoint", "String").nullable())
            .field(FieldMeta::new("capabilities", "Vec<String>")),
        ModelMeta::new("AiCrawlerResult", "ai_crawler_results")
            .description("AI crawler policy analysis")
            .source_crate("web-analyzer")
            .field(FieldMeta::new("allows_ai_crawlers", "bool"))
            .field(FieldMeta::new("blocked_bots", "Vec<String>"))
            .field(FieldMeta::new("allowed_bots", "Vec<String>")),
    ]
}
