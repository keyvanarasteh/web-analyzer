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
    ]
}
