use qicro_data_core::endpoint_registry::{EndpointMeta, ParamMeta};
use qicro_data_core::graphql_registry::{GraphqlFieldMeta, GraphqlOperationMeta, GraphqlTypeMeta};
use qicro_data_core::mcp::McpToolDef;
use qicro_data_core::proto::{MethodDescriptor, ServiceDescriptor};
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
            .summary("Domain WHOIS and registration data")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("registrar", "String"))
            .field(GraphqlFieldMeta::new("creation_date", "String"))
            .field(GraphqlFieldMeta::new("expiration_date", "String"))
            .field(GraphqlFieldMeta::new("name_servers", "[String!]!")),
        GraphqlTypeMeta::new("DomainDnsResult", "object")
            .summary("DNS records for a domain")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("a_records", "[String!]!"))
            .field(GraphqlFieldMeta::new("aaaa_records", "[String!]!"))
            .field(GraphqlFieldMeta::new("mx_records", "[String!]!"))
            .field(GraphqlFieldMeta::new("ns_records", "[String!]!"))
            .field(GraphqlFieldMeta::new("txt_records", "[String!]!")),
        GraphqlTypeMeta::new("SecurityAnalysisResult", "object")
            .summary("Security assessment report")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("grade", "String!"))
            .field(GraphqlFieldMeta::new("score", "Int!"))
            .field(GraphqlFieldMeta::new("waf_detected", "Boolean!"))
            .field(GraphqlFieldMeta::new("ssl_grade", "String")),
        GraphqlTypeMeta::new("SeoAnalysisResult", "object")
            .summary("SEO analysis report")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("overall_score", "Int!"))
            .field(GraphqlFieldMeta::new("issues_count", "Int!"))
            .field(GraphqlFieldMeta::new("categories", "JSON!")),
        GraphqlTypeMeta::new("WebTechResult", "object")
            .summary("Detected web technologies")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("technologies", "JSON!")),
        GraphqlTypeMeta::new("ContactSpyResult", "object")
            .summary("Contact information extracted from website")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("emails", "[String!]!"))
            .field(GraphqlFieldMeta::new("phones", "[String!]!"))
            .field(GraphqlFieldMeta::new("social_media", "JSON!"))
            .field(GraphqlFieldMeta::new("pages_scanned", "Int!")),
        GraphqlTypeMeta::new("TakeoverResult", "object")
            .summary("Subdomain takeover vulnerability report")
            .field(GraphqlFieldMeta::new("domain", "String!"))
            .field(GraphqlFieldMeta::new("statistics", "JSON!"))
            .field(GraphqlFieldMeta::new("vulnerable", "JSON!")),
        GraphqlTypeMeta::new("GeoAnalysisResult", "object")
            .summary("IP geolocation and hosting data")
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
