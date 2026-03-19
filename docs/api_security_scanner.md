# API Security Scanner

> **Module:** `api_security_scanner`
> **Feature Flag:** `api-security-scanner`
> **Source:** [`src/api_security_scanner.rs`](../src/api_security_scanner.rs)
> **Lines:** ~1,047 | **Dependencies:** `reqwest`, `scraper`, `regex`, `serde`, `serde_json`, `urlencoding`

A professional-grade bug-bounty API security scanner that discovers real API endpoints through multiple techniques, then tests each against 9 vulnerability classes. Ported from the Python `modules/api_security_scanner.py` (1,741 lines) with full feature parity.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
  - [Scan Pipeline](#scan-pipeline)
  - [Dependency Graph](#dependency-graph)
- [Public API](#public-api)
  - [`scan_api_endpoints()`](#scan_api_endpoints)
- [Data Structures](#data-structures)
  - [`ApiEndpoint`](#apiendpoint)
  - [`VulnerabilityFinding`](#vulnerabilityfinding)
  - [`ApiScanResult`](#apiscanresult)
- [Phase 1: Endpoint Discovery](#phase-1-endpoint-discovery)
  - [1a. Embedded Path Probing](#1a-embedded-path-probing)
  - [1b. JavaScript Endpoint Extraction](#1b-javascript-endpoint-extraction)
  - [1c. robots.txt & sitemap.xml Analysis](#1c-robotstxt--sitemapxml-analysis)
  - [1d. Swagger / OpenAPI Scraping](#1d-swagger--openapi-scraping)
  - [1e. API Subdomain Discovery](#1e-api-subdomain-discovery)
- [Advanced API Detection](#advanced-api-detection)
  - [Multi-Method Verification](#multi-method-verification)
  - [HTML Killer Filter (24 patterns)](#html-killer-filter-24-patterns)
  - [Documentation File Detection](#documentation-file-detection)
  - [Content-Type API Detection](#content-type-api-detection)
  - [Auth-Protected Endpoint Detection](#auth-protected-endpoint-detection)
  - [API Structure Scoring (14 patterns)](#api-structure-scoring-14-patterns)
  - [API Header Scoring](#api-header-scoring)
  - [Framework Server Detection](#framework-server-detection)
  - [Composite Score & Majority Voting](#composite-score--majority-voting)
- [Phase 2: Vulnerability Testing](#phase-2-vulnerability-testing)
  - [SQL Injection](#sql-injection)
  - [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
  - [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
  - [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
  - [Authentication Bypass](#authentication-bypass)
  - [Command Injection](#command-injection)
  - [NoSQL Injection](#nosql-injection)
  - [XML External Entity (XXE)](#xml-external-entity-xxe)
  - [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
- [Internal Functions](#internal-functions)
  - [`verify_endpoint()`](#verify_endpoint)
  - [`detect_api_from_headers()`](#detect_api_from_headers)
  - [`extract_js_endpoints()`](#extract_js_endpoints)
  - [`extract_robots_sitemap_endpoints()`](#extract_robots_sitemap_endpoints)
  - [`scrape_documentation_endpoints()`](#scrape_documentation_endpoints)
  - [`check_api_subdomains()`](#check_api_subdomains)
  - [`test_endpoint()`](#test_endpoint)
  - [`is_payload_safe_context()`](#is_payload_safe_context)
  - [`fetch_body()`](#fetch_body)
  - [`resolve_url()`](#resolve_url)
- [Payload Files Used](#payload-files-used)
- [Constants Reference](#constants-reference)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

The scanner executes two phases on every target:

1. **Endpoint Discovery** — 5 complementary techniques to find real API endpoints
2. **Vulnerability Testing** — 9 attack classes tested on every confirmed endpoint

Early exit: scanning stops after **10 CRITICAL** findings to avoid excessive probing.

---

## Architecture

### Scan Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        scan_api_endpoints(domain)                          │
├────────────────────┬────────────────────────────────────────────────────────┤
│  Phase 1           │                                                       │
│  Discovery         │  1a. Probe 733+ paths from api_endpoints.txt          │
│                    │  1b. Extract JS endpoints (fetch/axios/jQuery)         │
│                    │  1c. Parse robots.txt + sitemap.xml for API paths      │
│                    │  1d. Scrape Swagger/OpenAPI docs for "paths" keys      │
│                    │  1e. Check 8 API subdomains (api., rest., etc.)        │
│                    │                                                       │
│                    │  Each candidate → verify_endpoint()                    │
│                    │    ├─ GET / OPTIONS / HEAD (3 methods)                 │
│                    │    ├─ HTML killer filter (24 patterns)                 │
│                    │    ├─ Doc file detection (skip Swagger specs)          │
│                    │    ├─ Content-type detection                           │
│                    │    ├─ Auth-protected detection (401/403)               │
│                    │    ├─ API structure scoring (14 patterns)              │
│                    │    ├─ Header + framework scoring                       │
│                    │    └─ Majority voting across methods                   │
├────────────────────┼────────────────────────────────────────────────────────┤
│  Phase 2           │  For each verified endpoint → test_endpoint()         │
│  Vuln Testing      │    ├─ SQL Injection (error + time-based)              │
│                    │    ├─ XSS (reflected, safe-context filtering)          │
│                    │    ├─ SSTI (template math verification)               │
│                    │    ├─ SSRF (internal metadata probe)                  │
│                    │    ├─ Auth Bypass (header-based)                       │
│                    │    ├─ Command Injection (time-based)                   │
│                    │    ├─ NoSQL Injection (JSON operators)                 │
│                    │    ├─ XXE (XML entity expansion)                       │
│                    │    └─ LFI (path traversal)                             │
│                    │                                                       │
│                    │  Early exit: ≥10 CRITICAL findings                     │
└────────────────────┴────────────────────────────────────────────────────────┘
```

### Dependency Graph

```
api_security_scanner
├── crate::payloads             (embedded payload files)
│   ├── API_ENDPOINTS           (733 paths from api_endpoints.txt)
│   ├── SQL_INJECTION           (sql_injection.txt)
│   ├── XSS                    (xss.txt)
│   ├── SSRF                   (ssrf.txt)
│   ├── COMMAND_INJECTION       (command_injection.txt)
│   ├── NOSQL_INJECTION         (nosql_injection.txt)
│   ├── XXE                    (xxe.txt)
│   ├── LFI                    (lfi.txt)
│   └── AUTH_BYPASS_HEADERS     (auth_bypass_headers.txt)
├── reqwest::Client             (HTTP with 15s timeout, TLS skip)
├── scraper::{Html,Selector}    (HTML parsing for JS extraction)
├── regex::Regex                (pattern matching)
├── serde::{Serialize,Deserialize}  (JSON serialization)
├── serde_json                  (JSON parsing for Swagger docs)
└── urlencoding                 (URL-encoding payloads)
```

---

## Public API

### `scan_api_endpoints()`

```rust
pub async fn scan_api_endpoints(
    domain: &str
) -> Result<ApiScanResult, Box<dyn std::error::Error + Send + Sync>>
```

| Param | Type | Description |
|-------|------|-------------|
| `domain` | `&str` | Target. Accepts `example.com` or `https://example.com`. If no scheme, `https://` is prepended. |

**Returns:** `Result<ApiScanResult, Error>` — Full discovery + vulnerability results.

**Behavior:**
- Creates HTTP client with 15s timeout, TLS skip, max 3 redirects
- Executes Phase 1 (5 discovery techniques) then Phase 2 (9 vuln tests)
- Deduplicates endpoints across discovery techniques

---

## Data Structures

### `ApiEndpoint`

A verified API endpoint.

```rust
pub struct ApiEndpoint {
    pub url: String,         // Full URL: "https://example.com/api/v1/users"
    pub status_code: u16,    // HTTP status code (200, 401, 403, etc.)
    pub api_type: String,    // "REST/JSON", "REST/XML", "GraphQL", "Protected API", etc.
}
```

### `VulnerabilityFinding`

A security vulnerability found on an endpoint.

```rust
pub struct VulnerabilityFinding {
    pub vuln_type: String,    // "SQL_INJECTION", "XSS", "SSTI", "SSRF", etc.
    pub subtype: String,      // "Error-based", "Time-based Blind", "Reflected", etc.
    pub endpoint: String,     // URL where found
    pub parameter: String,    // Query parameter exploited (or empty)
    pub payload: String,      // Payload that triggered the finding
    pub severity: String,     // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub confidence: String,   // "HIGH", "MEDIUM", "LOW"
    pub evidence: String,     // What proves the vulnerability exists
}
```

### `ApiScanResult`

Top-level result container.

```rust
pub struct ApiScanResult {
    pub domain: String,                        // Target domain
    pub endpoints_found: Vec<ApiEndpoint>,      // Verified API endpoints
    pub vulnerabilities: Vec<VulnerabilityFinding>, // Vulns found across all endpoints
    pub total_paths_probed: usize,             // Paths from api_endpoints.txt tested
    pub endpoints_tested: usize,               // Endpoints that went through vuln testing
}
```

---

## Phase 1: Endpoint Discovery

### 1a. Embedded Path Probing

Probes **733+ API paths** from `payloads/api_endpoints.txt` against the target:

```
/api, /api/v1, /api/v2, /graphql, /rest/v1, /swagger,
/api/users, /api/auth, /api/login, /api/health, /api/status,
/openapi.json, /actuator, /actuator/health, /admin/api, ...
```

Each path is appended to the base URL and verified through `verify_endpoint()`.

### 1b. JavaScript Endpoint Extraction

Fetches the main page, then:
1. Extracts all inline `<script>` content
2. Fetches up to **10 external JS files** (`<script src="...">`)
3. Scans all JS content against 9 regex patterns:

| # | Pattern | Matches |
|---|---------|---------|
| 1 | `fetch('...')` | Modern fetch API calls |
| 2 | `axios.get('...')` | Axios HTTP library calls |
| 3 | `$.ajax({url:'...'})` | jQuery AJAX calls |
| 4 | `$.get('...')` | jQuery shorthand GET |
| 5 | `$.post('...')` | jQuery shorthand POST |
| 6 | `apiUrl = '...'` | API URL configuration |
| 7 | `API_URL = '...'` | API URL constants |
| 8 | `baseURL = '...'` | Base URL configuration |
| 9 | `endpoint = '...'` | Endpoint assignments |

**Filtering:** Static assets (`.js`, `.css`, `.png`, `.jpg`, `.gif`, `.ico`, `.svg`) are excluded.

### 1c. robots.txt & sitemap.xml Analysis

**robots.txt:**
- Fetches `/robots.txt`
- Parses `Disallow:` and `Allow:` directives
- Extracts paths containing `api`, `graphql`, or `rest` keywords

**sitemap.xml:**
- Fetches `/sitemap.xml`
- Extracts `<loc>` URLs via regex: `<loc>([^<]+)</loc>`
- Filters for URLs containing API-related keywords

### 1d. Swagger / OpenAPI Scraping

Fetches 7 documentation endpoints:

| Path | Purpose |
|------|---------|
| `/swagger.json` | Swagger 2.0 spec |
| `/openapi.json` | OpenAPI 3.0 spec |
| `/api-docs` | Generic API docs |
| `/docs` | Documentation root |
| `/swagger` | Swagger UI |
| `/api/swagger.json` | Nested Swagger spec |
| `/api/docs` | Nested API docs |

For JSON responses, parses the `"paths"` object keys and `"basePath"` value, converting each to a full URL for verification.

### 1e. API Subdomain Discovery

Checks up to 8 common API subdomain prefixes against the target's base domain:

```
api, rest, graphql, gateway,
api-v1, api-v2, api-dev, dev-api
```

For each, tries `https://` then `http://`. Endpoints returning `200`, `401`, or `403` are added.

---

## Advanced API Detection

### Multi-Method Verification

`verify_endpoint()` tests each candidate URL with **3 HTTP methods** sequentially:

1. **GET** — Full body analysis (HTML killers, structure scoring, auth detection)
2. **OPTIONS** — Header-only analysis
3. **HEAD** — Header-only analysis

Results from all methods are collected as "votes", and majority voting determines whether the URL is a real API.

### HTML Killer Filter (24 patterns)

Response bodies are scanned (case-insensitive) for definitive NOT-API indicators. If **any** match, the response is discarded:

| Category | Patterns |
|----------|----------|
| HTML tags | `<!doctype html`, `<html`, `<head>`, `<body>`, `<title>`, `<div`, `<form`, `<table`, `<script` |
| Error pages | `not found</title>`, `404 not found`, `404 - not found`, `page not found`, `file not found` |
| Server pages | `apache/2.`, `nginx/`, `microsoft-iis`, `server error` |
| Access control | `access denied`, `forbidden`, `directory listing`, `index of /` |
| Error headings | `<h1>404</h1>`, `<h1>error</h1>` |

### Documentation File Detection

URLs containing documentation hints (`openapi`, `swagger`, `docs`, `spec`, `schema`, `definition`, `.json`, `.yaml`, `.yml`) are checked for Swagger/OpenAPI spec content. If **≥ 3** of the following 11 indicators are found, the response is classified as documentation and **skipped**:

```
"openapi":, "swagger":, "info":, "paths":, "components":,
"definitions":, "host":, "basepath":, "schemes":, "consumes":, "produces":
```

### Content-Type API Detection

Definitive API detection by `Content-Type` header:

| Content-Type | API Type |
|-------------|----------|
| `application/json` | REST/JSON (requires valid JSON body) |
| `application/xml` or `text/xml` | REST/XML |
| `application/graphql` | GraphQL |
| `application/vnd.api+json` | JSON:API |
| `application/hal+json` | HAL+JSON |
| `application/problem+json` | Problem Details |

### Auth-Protected Endpoint Detection

For **401** and **403** responses:

**Header check:** If any of these headers are present, it's a protected API:
- `www-authenticate`, `x-api-key`, `x-auth-token`, `x-rate-limit`

**Body check:** 8 regex patterns detect API-style auth errors:

| Pattern | Matches |
|---------|---------|
| `"error": "unauthorized"` | Unauthorized error |
| `"message": "forbidden"` | Forbidden message |
| `"code": "401"` | Auth error code |
| `"status": "unauthorized"` | Auth status |
| `"access_token"` | Token reference |
| `"api_key"` | API key reference |
| `"authentication.*required"` | Auth required |
| `"invalid.*credentials"` | Invalid creds |

### API Structure Scoring (14 patterns)

Regex patterns match RESTful API response structures:

| # | Pattern | Matches |
|---|---------|---------|
| 1 | `{"data": [{...}]` | RESTful data arrays |
| 2 | `{"result": [{...}]` | Result objects |
| 3 | `{"results": [...]` | Results lists |
| 4 | `{"items": [...]` | Item collections |
| 5 | `{"records": [...]` | Record sets |
| 6 | `{"version": "..."}` | Version metadata |
| 7 | `{"api_version": "..."}` | API version |
| 8 | `{"timestamp": 123}` | Timestamp field |
| 9 | `{"error": {"code": ...}` | Structured errors |
| 10 | `{"error": {"message": ...}` | Error messages |
| 11 | `{"errors": [...{message}` | Error arrays |
| 12 | `{"success": true/false}` | Success flags |
| 13 | `{"status": "ok/healthy/..."}` | Status responses |
| 14 | `{"health": "up/down/ok"}` | Health checks |

### API Header Scoring

7 API-specific headers are checked:

```
x-api-version, x-api-key, x-rate-limit, x-ratelimit,
x-request-id, x-correlation-id, x-trace-id
```

Each present header adds +1 to the score.

### Framework Server Detection

The `Server` header is checked against 10 known API framework identifiers:

```
express, koa, fastify, spring, django,
flask, tornado, rails, sinatra, fastapi
```

Each match adds **+2** to the score.

### Composite Score & Majority Voting

```
total_score = structure_score + api_header_score + framework_score
```

| Condition | Result |
|-----------|--------|
| `total_score ≥ 4` | API confirmed |
| `total_score ≥ 2` AND `status == 200` | API confirmed |
| `< 2` | Not an API |

Across all 3 HTTP methods, the **best vote** (preferring 2xx status) is selected for the final result.

---

## Phase 2: Vulnerability Testing

### SQL Injection

**Payloads:** From `payloads/sql_injection.txt`
**Parameters tested:** `id`, `user`, `search` (first 3)
**Method:** GET with URL-encoded payloads

| Subtype | Detection | Severity | Confidence |
|---------|-----------|----------|------------|
| **Error-based** | 8 SQL error regex patterns (MySQL, PostgreSQL, Oracle, SQLite) appear in response but NOT in baseline | CRITICAL | HIGH |
| **Time-based Blind** | Response delay > 4.8s for `SLEEP`/`WAITFOR` payloads | CRITICAL | MEDIUM |

**Baseline comparison:** A clean request (`?param=1`) is made first. If the baseline already contains SQL errors, the parameter is skipped.

**SQL Error Patterns (8):**

| # | Pattern | Database |
|---|---------|----------|
| 1 | `You have an error in your SQL syntax` | MySQL |
| 2 | `MySQL server version for the right syntax` | MySQL |
| 3 | `PostgreSQL.*ERROR.*syntax error` | PostgreSQL |
| 4 | `ORA-[0-9]{5}.*invalid identifier` | Oracle |
| 5 | `SQLite error.*syntax error` | SQLite |
| 6 | `SQLException.*invalid column name` | Generic JDBC |
| 7 | `mysql_fetch_array().*expects parameter` | PHP/MySQL |
| 8 | `Warning.*mysql_.*().*supplied argument` | PHP/MySQL |

### Cross-Site Scripting (XSS)

**Payloads:** From `payloads/xss.txt` (first 5)
**Parameters tested:** `q`, `search`, `query` (first 3)

| Detection Criteria | All must be true |
|--------------------|-----------------|
| Response `Content-Type` contains `text/html` | ✓ |
| Payload reflected **unencoded** in response body | ✓ |
| Payload is NOT in safe context (comment or encoded) | ✓ |

**Safe Context Checks:**
- Inside HTML comment (`<!-- ... payload ... -->`)
- HTML-encoded version present (`&lt;script&gt;` instead of `<script>`)

**Severity:** HIGH | **Confidence:** HIGH

### Server-Side Template Injection (SSTI)

**Test expressions:**

| Payload | Expected Result |
|---------|-----------------|
| `{{7*7*7}}` | `343` |
| `{{9*9*9}}` | `729` |
| `${8*8*8}` | `512` |
| `{{42*13}}` | `546` |

**Parameters tested:** `template`, `name`, `msg` (first 3)

**Detection criteria (all must be true):**
1. Expected result present in response
2. Raw payload NOT present in response (proves execution)
3. Expected result NOT present in baseline response

**Severity:** CRITICAL | **Confidence:** HIGH

### Server-Side Request Forgery (SSRF)

**Payloads:** From `payloads/ssrf.txt` (first 3)
**Parameters tested:** `url`, `uri`, `path` (first 3)

**Detection:** Response body contains internal data indicators:

```
root:, daemon:, localhost, metadata, ami-id, instance-id
```

**Severity:** CRITICAL | **Confidence:** HIGH

### Authentication Bypass

**Prerequisite:** Endpoint must return **401** or **403** normally.

**Header payloads:** From `payloads/auth_bypass_headers.txt` (first 10), parsed as `Name: Value` pairs:

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
```

**Detection:** Response changes from 401/403 to **200** with bypass header applied.

**Severity:** CRITICAL | **Confidence:** HIGH

### Command Injection

**Payloads:** From `payloads/command_injection.txt` (first 3)
**Parameters tested:** `cmd`, `exec`, `command` (first 3)

**Detection:** For payloads containing `sleep`, response delay > 4.5s indicates command execution.

**Severity:** CRITICAL | **Confidence:** HIGH

### NoSQL Injection

**Payloads:** From `payloads/nosql_injection.txt` (first 3)
**Method:** POST with `Content-Type: application/json`

Example payloads:
```json
{"$ne": null}
{"$ne": ""}
{"$gt": ""}
{"$exists": true}
```

**Detection:** Response status 200/201, body > 100 chars, no `error` in response.

**Severity:** HIGH | **Confidence:** MEDIUM

### XML External Entity (XXE)

**Payloads:** From `payloads/xxe.txt` (first 2)
**Method:** POST with `Content-Type: application/xml`

Example payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>
<root>&test;</root>
```

**Detection:** Response contains file content indicators: `root:`, `daemon:`, `Windows`, `[fonts]`

**Severity:** CRITICAL | **Confidence:** HIGH

### Local File Inclusion (LFI)

**Payloads:** From `payloads/lfi.txt` (first 3)
**Parameters tested:** `file`, `path`, `page` (first 3)

Example payloads:
```
../../../etc/passwd
../../../../etc/passwd
..\..\..\..\windows\win.ini
/etc/passwd
```

**Detection:** Response contains: `root:x:`, `daemon:`, `[fonts]`, `[extensions]`

**Severity:** HIGH | **Confidence:** HIGH

---

## Internal Functions

### `verify_endpoint()`
```rust
async fn verify_endpoint(client: &Client, url: &str) -> Option<ApiEndpoint>
```
Multi-method API endpoint verification with scoring and majority voting. Returns `None` if URL is not a real API.

### `detect_api_from_headers()`
```rust
fn detect_api_from_headers(content_type: &str, headers: &[(String, String)], status: u16) -> Option<String>
```
Header-only API detection for OPTIONS/HEAD responses. Checks content-type and auth headers.

### `extract_js_endpoints()`
```rust
async fn extract_js_endpoints(client: &Client, base_url: &str) -> Vec<String>
```
Fetches main page, collects inline + external JS, and extracts API paths using 9 regex patterns.

### `extract_robots_sitemap_endpoints()`
```rust
async fn extract_robots_sitemap_endpoints(client: &Client, base_url: &str) -> Vec<String>
```
Parses robots.txt directives and sitemap.xml `<loc>` URLs for API-related paths.

### `scrape_documentation_endpoints()`
```rust
async fn scrape_documentation_endpoints(client: &Client, base_url: &str) -> Vec<String>
```
Fetches 7 documentation URLs, parses Swagger/OpenAPI JSON for `"paths"` keys and `"basePath"`.

### `check_api_subdomains()`
```rust
async fn check_api_subdomains(client: &Client, domain: &str) -> Vec<String>
```
Checks 8 API subdomain prefixes with both HTTPS and HTTP.

### `test_endpoint()`
```rust
async fn test_endpoint(client: &Client, endpoint: &str) -> Vec<VulnerabilityFinding>
```
Runs all 9 vulnerability tests on a single endpoint and aggregates findings.

### `is_payload_safe_context()`
```rust
fn is_payload_safe_context(content: &str, payload: &str) -> bool
```
Checks if an XSS payload is inside an HTML comment or is properly HTML-encoded.

### `fetch_body()`
```rust
async fn fetch_body(client: &Client, url: &str) -> Option<String>
```
GET request helper. Returns `None` on 404 or error.

### `resolve_url()`
```rust
fn resolve_url(base: &str, href: &str) -> Option<String>
```
Resolves relative URLs to absolute. Skips `javascript:`, `mailto:`, `tel:`, `#` anchors.

---

## Payload Files Used

| Constant | File | Count | Purpose |
|----------|------|-------|---------|
| `payloads::API_ENDPOINTS` | `api_endpoints.txt` | 733+ | API path enumeration |
| `payloads::SQL_INJECTION` | `sql_injection.txt` | 8+ | SQLi test payloads |
| `payloads::XSS` | `xss.txt` | 5+ | XSS test payloads |
| `payloads::SSRF` | `ssrf.txt` | 4+ | SSRF probe URLs |
| `payloads::COMMAND_INJECTION` | `command_injection.txt` | 5+ | Command injection payloads |
| `payloads::NOSQL_INJECTION` | `nosql_injection.txt` | 4+ | NoSQL operator payloads |
| `payloads::XXE` | `xxe.txt` | 1+ | XXE XML payloads |
| `payloads::LFI` | `lfi.txt` | 4+ | Path traversal payloads |
| `payloads::AUTH_BYPASS_HEADERS` | `auth_bypass_headers.txt` | 4+ | Auth bypass headers |

All payloads are embedded at compile time via `include_str!()`.

---

## Constants Reference

| Constant | Value | Description |
|----------|-------|-------------|
| HTTP timeout | `15s` | Per-request timeout |
| TLS validation | `disabled` | Accepts self-signed certs |
| Max redirects | `3` | Redirect follow limit |
| `HTML_KILLERS` | 24 patterns | Non-API response indicators |
| `DOC_INDICATORS` | 11 patterns | Swagger/OpenAPI spec indicators |
| `DOC_URL_HINTS` | 9 patterns | Documentation URL patterns |
| `API_HEADERS` | 7 headers | API-specific response headers |
| `FRAMEWORK_SERVERS` | 10 frameworks | Known API framework names |
| `AUTH_ERROR_PATTERNS` | 8 regexes | API auth error response patterns |
| `API_STRUCTURE_PATTERNS` | 14 regexes | RESTful response structure patterns |
| `SQL_ERROR_PATTERNS` | 8 regexes | SQL syntax error patterns |
| `JS_API_PATTERNS` | 9 regexes | JS API endpoint patterns |
| Doc detection threshold | `≥ 3` matches | Min indicators to classify as docs |
| API score threshold (high) | `≥ 4` | Confirmed API |
| API score threshold (medium) | `≥ 2` + `200 OK` | Confirmed API |
| SQLi time threshold | `> 4.8s` | Time-based blind detection |
| Command injection time threshold | `> 4.5s` | Time-based detection |
| Max CRITICAL before exit | `10` | Early scan termination |
| Subdomain prefixes tested | `8` | Max subdomains checked |
| External JS files limit | `10` | Max fetched per page |
| Doc endpoints checked | `7` | Swagger/OpenAPI paths |

---

## Usage Example

```rust
use web_analyzer::api_security_scanner::scan_api_endpoints;

#[tokio::main]
async fn main() {
    let result = scan_api_endpoints("example.com").await.unwrap();

    println!("Probed {} paths, found {} real API endpoints",
        result.total_paths_probed, result.endpoints_found.len());

    for ep in &result.endpoints_found {
        println!("[{}] {} ({})", ep.status_code, ep.url, ep.api_type);
    }

    println!("\nVulnerabilities: {}", result.vulnerabilities.len());
    for vuln in &result.vulnerabilities {
        println!("[{}] {} — {} at {}",
            vuln.severity, vuln.vuln_type, vuln.subtype, vuln.endpoint);
        if !vuln.parameter.is_empty() {
            println!("  Param: {}", vuln.parameter);
        }
        println!("  Payload: {}", vuln.payload);
        println!("  Evidence: {}", vuln.evidence);
        println!("  Confidence: {}", vuln.confidence);
    }
}
```

---

## Testing

```bash
# Run all api-security-scanner tests
cargo test --features api-security-scanner -- --nocapture
```

**Test suite (12 tests):**

| # | Test | What it verifies |
|---|------|------------------|
| 1 | `test_scan_api_endpoints` | End-to-end scan against `example.com`, probes 733+ paths |
| 2 | `test_vulnerability_struct_serialization` | `VulnerabilityFinding` round-trips JSON correctly |
| 3 | `test_api_endpoint_serialization` | `ApiEndpoint` serializes to JSON |
| 4 | `test_scan_result_serialization` | `ApiScanResult` serializes to JSON |
| 5 | `test_sql_injection_patterns` | All 8 SQL error regexes compile and match expected strings |
| 6 | `test_xss_safe_context` | Encoded/commented payloads detected as safe |
| 7 | `test_ssti_expected_results` | SSTI math expressions produce unique results > 100 |
| 8 | `test_auth_bypass_header_parsing` | Auth bypass headers parse into name:value pairs |
| 9 | `test_payload_loading` | All 7 payload files load with expected minimum counts |
| 10 | `test_api_endpoints_payload` | API endpoints file has 700+ paths including `/api` and `/graphql` |
| 11 | `test_html_killer_filter` | HTML pages match killers, JSON responses do not |
| 12 | `test_api_structure_scoring` | RESTful patterns match API responses, not HTML |
