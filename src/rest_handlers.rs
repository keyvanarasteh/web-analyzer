use qicro_data_core::graphql_registry::GraphqlTypeMeta;
use qicro_data_core::endpoint_registry::EndpointMeta;
use qicro_data_core::proto::{ServiceDescriptor, MethodDescriptor};
use qicro_data_core::mcp::McpToolDef;
use qicro_data_core::ws_registry::{ChannelMeta, WsEventMeta};
use qicro_data_core::graphql_registry::GraphqlOperationMeta;

pub fn web_analyzer_proto_services() -> Vec<ServiceDescriptor> {
    vec![
        ServiceDescriptor::new("WebAnalyzerService", "qicro.web_analyzer")
            .description("Web security & intelligence platform — domain info, DNS, SEO, subdomain discovery, security analysis, API scanner")
            .method(MethodDescriptor::unary("DomainInfo", "DomainRequest", "DomainInfoResult")
                .description("Domain WHOIS and registration info"))
            .method(MethodDescriptor::unary("DomainDns", "DnsRequest", "DnsResult")
                .description("DNS record analysis"))
            .method(MethodDescriptor::unary("SeoAnalysis", "SeoRequest", "SeoReport")
                .description("SEO analysis of a URL"))
            .method(MethodDescriptor::unary("SubdomainDiscovery", "SubdomainRequest", "SubdomainList")
                .description("Discover subdomains"))
            .method(MethodDescriptor::unary("SecurityAnalysis", "SecurityRequest", "SecurityReport")
                .description("Security assessment of a domain"))
            .method(MethodDescriptor::unary("ApiSecurityScan", "ApiScanRequest", "ApiSecurityReport")
                .description("API endpoint security scanning")),
    ]
}

pub fn web_analyzer_mcp_tools() -> Vec<McpToolDef> {
    vec![
        McpToolDef::new("web_domain_info", "Get domain WHOIS and registration info")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string" } },
                "required": ["domain"]
            })),
        McpToolDef::new("web_seo_analysis", "SEO analysis for a URL")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "url": { "type": "string" } },
                "required": ["url"]
            })),
        McpToolDef::new("web_security_scan", "Security assessment of a domain")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": { "domain": { "type": "string" } },
                "required": ["domain"]
            })),
    ]
}

pub fn web_analyzer_websockets() -> Vec<ChannelMeta> {
    vec![
        ChannelMeta::new("web-analyzer", "/ws/web-analyzer")
            .description("Web Security & Intelligence Analysis Platform")
            .module("web-analyzer")
            .event(WsEventMeta::new("domain_info", "client_to_server").summary("Get domain WHOIS and registration info").payload_type("DomainInfoRequest"))
            .event(WsEventMeta::new("domain_dns", "client_to_server").summary("Get DNS records for a domain").payload_type("DnsRequest"))
            .event(WsEventMeta::new("security_analysis", "client_to_server").summary("Determine security posture of a domain").payload_type("SecurityRequest"))
            .event(WsEventMeta::new("seo_analysis", "client_to_server").summary("SEO analysis of a URL/domain").payload_type("SeoRequest"))
            .event(WsEventMeta::new("subdomain_discovery", "client_to_server").summary("Discover subdomains").payload_type("SubdomainRequest"))
            .event(WsEventMeta::new("api_security_scan", "client_to_server").summary("Scan API for security vulnerabilities").payload_type("ApiScanRequest"))
            .event(WsEventMeta::new("domain_info_result", "server_to_client").summary("Result of domain info gather").payload_type("DomainInfoResult"))
            .event(WsEventMeta::new("domain_dns_result", "server_to_client").summary("Result of DNS analysis").payload_type("DnsResult"))
            .event(WsEventMeta::new("security_analysis_result", "server_to_client").summary("Result of security analysis").payload_type("SecurityReport"))
            .event(WsEventMeta::new("seo_analysis_result", "server_to_client").summary("Result of SEO analysis").payload_type("SeoReport"))
            .event(WsEventMeta::new("subdomain_discovery_result", "server_to_client").summary("Result of subdomain discovery").payload_type("SubdomainList"))
            .event(WsEventMeta::new("api_security_scan_result", "server_to_client").summary("Result of API security scan").payload_type("ApiSecurityReport"))
    ]
}

pub fn web_analyzer_graphql_operations() -> Vec<GraphqlOperationMeta> {
    vec![
        GraphqlOperationMeta::new("webDomainInfo", "query")
            .summary("Domain WHOIS info").module("web-analyzer").source_crate("qicro-web-analyzer").return_type("DomainInfoResult!"),
        GraphqlOperationMeta::new("webSeoAnalysis", "query")
            .summary("SEO analysis").module("web-analyzer").source_crate("qicro-web-analyzer").return_type("SeoReport!"),
        GraphqlOperationMeta::new("webSecurityScan", "query")
            .summary("Security assessment").module("web-analyzer").source_crate("qicro-web-analyzer").return_type("SecurityReport!"),
    ]
}

pub fn web_analyzer_endpoint_metas() -> Vec<EndpointMeta> {
    vec![]
}

pub fn web_analyzer_graphql_types() -> Vec<GraphqlTypeMeta> {
    vec![]
}
