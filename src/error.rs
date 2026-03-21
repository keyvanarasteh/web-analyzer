use qicro_data_core::error::ErrorMeta;

pub fn web_analyzer_errors() -> Vec<ErrorMeta> {
    vec![
        ErrorMeta::new(500, "WEB_ANALYZER_INTERNAL_ERROR")
            .description("An internal error occurred in web-analyzer")
            .http_status(500)
            .source("qicro-web-analyzer"),
        ErrorMeta::new(400, "WEB_ANALYZER_INVALID_INPUT")
            .description("Invalid input provided to web-analyzer")
            .http_status(400)
            .source("qicro-web-analyzer"),
        ErrorMeta::new(404, "WEB_ANALYZER_DOMAIN_NOT_FOUND")
            .description("The specified domain could not be resolved")
            .http_status(404)
            .source("qicro-web-analyzer"),
        ErrorMeta::new(504, "WEB_ANALYZER_TIMEOUT")
            .description("Analysis operation timed out")
            .http_status(504)
            .source("qicro-web-analyzer"),
        ErrorMeta::new(501, "WEB_ANALYZER_FEATURE_DISABLED")
            .description("The requested analysis feature is not enabled")
            .http_status(501)
            .source("qicro-web-analyzer"),
        ErrorMeta::new(502, "WEB_ANALYZER_DNS_FAILURE")
            .description("DNS resolution failed for the target domain")
            .http_status(502)
            .source("qicro-web-analyzer"),
        ErrorMeta::new(500, "WEB_ANALYZER_SCAN_FAILED")
            .description("Security scan or content analysis failed unexpectedly")
            .http_status(500)
            .source("qicro-web-analyzer"),
        ErrorMeta::new(429, "WEB_ANALYZER_RATE_LIMITED")
            .description("Too many analysis requests — rate limit exceeded")
            .http_status(429)
            .source("qicro-web-analyzer"),
    ]
}
