# Security Analysis

> **Module:** `security_analysis`
> **Feature Flag:** `security-analysis`
> **Source:** [`src/security_analysis.rs`](../src/security_analysis.rs)
> **Lines:** ~450 | **Dependencies:** `reqwest`, `regex`, `serde`, `tokio`

Comprehensive security analysis covering WAF detection (7 providers), security headers with importance levels, SSL/TLS cipher grading, CORS policy, cookie security, HTTP methods, server info disclosure, vulnerability scanning, weighted composite scoring, and automated recommendations.

---

## Table of Contents

- [Overview](#overview)
- [Public API](#public-api)
  - [`analyze_security()`](#analyze_security)
- [Data Structures](#data-structures)
  - [`SecurityAnalysisResult`](#securityanalysisresult)
  - [`WafDetectionResult`](#wafdetectionresult) / [`WafMatch`](#wafmatch)
  - [`SecurityHeadersResult`](#securityheadersresult)
  - [`SslAnalysisResult`](#sslanalysisresult)
  - [`CorsPolicyResult`](#corspolicyresult)
  - [`CookieSecurityResult`](#cookiesecurityresult)
  - [`HttpMethodsResult`](#httpmethodsresult)
  - [`ServerInfoResult`](#serverinforesult)
  - [`VulnScanResult`](#vulnscanresult)
  - [`SecurityScoreResult`](#securityscoreresult)
- [Analysis Modules](#analysis-modules)
  - [1. WAF Detection (7 Providers)](#1-waf-detection-7-providers)
  - [2. Security Headers (7 Headers)](#2-security-headers-7-headers)
  - [3. SSL/TLS Analysis](#3-ssltls-analysis)
  - [4. CORS Policy](#4-cors-policy)
  - [5. Cookie Security](#5-cookie-security)
  - [6. HTTP Methods](#6-http-methods)
  - [7. Server Information Disclosure](#7-server-information-disclosure)
  - [8. Vulnerability Scanning](#8-vulnerability-scanning)
- [Security Score (Weighted Composite)](#security-score-weighted-composite)
  - [Weight Distribution](#weight-distribution)
  - [Grade Scale](#grade-scale)
  - [Risk Levels](#risk-levels)
- [Recommendations Engine](#recommendations-engine)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌────────────────────────────────────────────────────────────┐
│                analyze_security(domain)                     │
├──────────────┬─────────────────────────────────────────────┤
│ HTTP Check   │ HTTP (no-redirect) + HTTPS requests        │
│              │ Detect 301/302/307/308 → HTTPS redirect    │
├──────────────┼─────────────────────────────────────────────┤
│ Analysis     │ 1. WAF Detection (7 providers)             │
│ (8 modules)  │ 2. Security Headers (7 headers, weighted)  │
│              │ 3. SSL/TLS via openssl (cipher grading)    │
│              │ 4. CORS Policy (credential issues)         │
│              │ 5. Cookie Security (3 flags)               │
│              │ 6. HTTP Methods (OPTIONS, dangerous check) │
│              │ 7. Server Info Disclosure                   │
│              │ 8. Vulnerability Scan (error patterns)     │
├──────────────┼─────────────────────────────────────────────┤
│ Scoring      │ Weighted composite (0-100) + Grade A+-F    │
│ Recommends   │ Up to 10 prioritized recommendations       │
└──────────────┴─────────────────────────────────────────────┘
```

---

## Public API

### `analyze_security()`

```rust
pub async fn analyze_security(
    domain: &str
) -> Result<SecurityAnalysisResult, Box<dyn std::error::Error + Send + Sync>>
```

---

## Analysis Modules

### 1. WAF Detection (7 Providers)

| Provider | Header Signatures | Server Signatures |
|----------|-------------------|-------------------|
| Cloudflare | `cf-ray`, `cf-cache-status`, `__cfduid` | `cloudflare` |
| Akamai | `akamai-transformed`, `akamai-cache-status` | `akamaighost` |
| Imperva Incapsula | `x-iinfo`, `incap_ses` | `imperva` |
| Sucuri | `x-sucuri-id`, `x-sucuri-cache` | `sucuri` |
| Barracuda | `barra` | `barracuda` |
| F5 BIG-IP | `f5-http-lb`, `bigip` | `bigip`, `f5` |
| AWS WAF | `x-amz-cf-id`, `x-amzn-requestid` | `awselb` |

**Confidence scoring:** Header match = +40, Server match = +30. ≥50 = High, ≥30 = Medium, else Low.

### 2. Security Headers (7 Headers)

| Header | Importance | Weight |
|--------|-----------|--------|
| `Strict-Transport-Security` | Critical | 30 |
| `Content-Security-Policy` | Critical | 30 |
| `X-Frame-Options` | High | 20 |
| `X-Content-Type-Options` | Medium | 10 |
| `X-XSS-Protection` | Medium | 10 |
| `Referrer-Policy` | Medium | 10 |
| `Permissions-Policy` | Medium | 10 |

### 3. SSL/TLS Analysis

Uses `openssl s_client` for cipher suite and protocol detection.

| Grade | Condition |
|-------|-----------|
| A+ | TLSv1.3 |
| A | TLSv1.2 + Strong cipher |
| B | TLSv1.2 |
| C | TLSv1.1 or TLSv1 |
| F | Anything else / unavailable |

**Cipher strength:** Strong (AES256, CHACHA20), Medium (AES128), Weak (DES, RC4, NULL).

### 4. CORS Policy

Checks `Access-Control-Allow-Origin`, `Allow-Methods`, `Allow-Headers`, `Allow-Credentials`.
- Critical issue: Wildcard origin (`*`) + credentials (`true`)
- Warning: Wildcard origin without credentials

### 5. Cookie Security

Checks `Set-Cookie` header for:
- `Secure` flag
- `HttpOnly` flag
- `SameSite` attribute

Score = 100 − 25 × (missing flags count)

### 6. HTTP Methods

Sends OPTIONS request, extracts `Allow` header.
Dangerous methods: `DELETE`, `PUT`, `PATCH`, `TRACE`, `CONNECT`.

### 7. Server Information Disclosure

Checks for `Server` and `X-Powered-By` headers.

### 8. Vulnerability Scanning

| Pattern | Description |
|---------|-------------|
| `fatal error` | PHP Fatal Error |
| `warning.*mysql` | MySQL Warning |
| `error.*sql` | SQL Error |

Risk level: score per vuln (High=3, Medium=2, Low=1). Total ≥6 = Critical, ≥4 = High, ≥2 = Medium.

---

## Security Score (Weighted Composite)

### Weight Distribution

| Component | Weight | Max Points |
|-----------|--------|-----------|
| Security Headers | 40% | 100 |
| SSL/TLS | 30% | 100 |
| WAF Protection | 15% | 100 (detected=100, not=60) |
| Vulnerabilities | 15% | 100 (−20 per vuln) |

### Grade Scale

| Score | Grade |
|-------|-------|
| ≥95 | A+ |
| ≥90 | A |
| ≥80 | B |
| ≥70 | C |
| ≥60 | D |
| <60 | F |

### Risk Levels

| Score | Risk |
|-------|------|
| ≥85 | Low Risk |
| ≥70 | Medium Risk |
| ≥50 | High Risk |
| <50 | Critical Risk |

---

## Recommendations Engine

Generates up to 10 prioritized recommendations based on:
- Missing critical/high security headers
- SSL grade D/F or C
- No WAF detected
- HTTPS not available or no redirect

---

## Usage Example

```rust
use web_analyzer::security_analysis::analyze_security;

#[tokio::main]
async fn main() {
    let result = analyze_security("example.com").await.unwrap();

    println!("Score: {}/100 ({})", result.security_score.overall_score, result.security_score.grade);
    println!("WAF: {} ({})", result.waf_detection.detected,
        result.waf_detection.primary_waf.as_ref().map(|w| w.provider.as_str()).unwrap_or("None"));
    println!("SSL Grade: {}", result.ssl_analysis.overall_grade);

    for rec in &result.recommendations {
        println!("  → {}", rec);
    }
}
```

---

## Testing

```bash
cargo test --features security-analysis -- --nocapture
```
