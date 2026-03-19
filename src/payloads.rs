//! Compile-time embedded payload data from the `payloads/` directory.
//!
//! Uses `include_str!()` to bake all payload files into the binary at compile time.
//! This gives zero runtime I/O overhead while keeping the data as editable `.txt` files.

/// SQL injection payloads (26 patterns)
pub const SQL_INJECTION: &str = include_str!("../payloads/sql_injection.txt");

/// Cross-site scripting payloads (24 patterns)
pub const XSS: &str = include_str!("../payloads/xss.txt");

/// Server-side request forgery probe URLs (31 patterns)
pub const SSRF: &str = include_str!("../payloads/ssrf.txt");

/// XML external entity injection payloads (7 patterns)
pub const XXE: &str = include_str!("../payloads/xxe.txt");

/// Command injection payloads (29 patterns)
pub const COMMAND_INJECTION: &str = include_str!("../payloads/command_injection.txt");

/// Local file inclusion paths (24 patterns)
pub const LFI: &str = include_str!("../payloads/lfi.txt");

/// NoSQL injection payloads (20 patterns)
pub const NOSQL_INJECTION: &str = include_str!("../payloads/nosql_injection.txt");

/// Server-side template injection payloads (24 patterns)
pub const SSTI: &str = include_str!("../payloads/ssti.txt");

/// Authentication bypass headers (26 patterns)
pub const AUTH_BYPASS_HEADERS: &str = include_str!("../payloads/auth_bypass_headers.txt");

/// API endpoint paths (846 paths)
pub const API_ENDPOINTS: &str = include_str!("../payloads/api_endpoints.txt");

/// Parse a payload file into lines, skipping comments and empty lines.
pub fn lines(payload: &str) -> Vec<&str> {
    payload
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Parse auth bypass headers into (header_name, header_value) tuples.
pub fn auth_headers(payload: &str) -> Vec<(&str, &str)> {
    lines(payload)
        .into_iter()
        .filter_map(|l| {
            let idx = l.find(':')?;
            let name = l[..idx].trim();
            let value = l[idx + 1..].trim();
            Some((name, value))
        })
        .collect()
}
