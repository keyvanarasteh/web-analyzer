//! Error types for the web-analyzer crate.

/// Errors that can occur during web analysis operations.
#[derive(Debug, thiserror::Error)]
pub enum WebAnalyzerError {
    /// An HTTP request failed.
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// DNS resolution failed for a target domain.
    #[error("DNS resolution failed for {domain}: {detail}")]
    Dns {
        /// The domain that failed to resolve.
        domain: String,
        /// Details about the failure.
        detail: String,
    },

    /// An external tool (dig, nmap, subfinder, etc.) was not found or failed.
    #[error("External tool '{tool}' failed: {detail}")]
    ExternalTool {
        /// Name of the tool (e.g. "dig", "nmap", "subfinder").
        tool: String,
        /// Details about the failure.
        detail: String,
    },

    /// An operation timed out.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// A parsing error occurred while processing output.
    #[error("Parse error: {0}")]
    Parse(String),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A generic error for uncategorized failures.
    #[error("{0}")]
    Other(String),

    /// A feature was invoked on an incompatible operating system architecture.
    #[error("Platform unsupported: {0}")]
    UnsupportedPlatform(String),
}

/// Convenience alias for `Result<T, WebAnalyzerError>`.
pub type Result<T> = std::result::Result<T, WebAnalyzerError>;
