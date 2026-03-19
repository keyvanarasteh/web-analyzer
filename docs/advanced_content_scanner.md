# Advanced Content Scanner

> **Module:** `advanced_content_scanner`
> **Feature Flag:** `advanced-content-scanner`
> **Source:** [`src/advanced_content_scanner.rs`](../src/advanced_content_scanner.rs)
> **Lines:** ~755 | **Dependencies:** `reqwest`, `scraper`, `regex`, `serde`

A comprehensive web content security scanner that crawls target domains and performs deep analysis for leaked secrets, JavaScript vulnerabilities, SSRF attack surfaces, and misconfigured security policies. Ported from the Python WebAnalyzer `modules/advanced_content_scanner.py` (1,516 lines) with full feature parity.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
  - [Scan Pipeline](#scan-pipeline)
  - [Dependency Graph](#dependency-graph)
- [Public API](#public-api)
  - [`scan_content()`](#scan_content)
- [Data Structures](#data-structures)
  - [`ScannerResult`](#scannerresult)
  - [`SecretFinding`](#secretfinding)
  - [`JsVulnerability`](#jsvulnerability)
  - [`SsrfFinding`](#ssrffinding)
  - [`ScanSummary`](#scansummary)
- [Scan Phases](#scan-phases)
  - [Phase 1: Pre-Crawl Reconnaissance](#phase-1-pre-crawl-reconnaissance)
    - [robots.txt Parsing](#robotstxt-parsing)
    - [sitemap.xml Processing](#sitemapxml-processing)
  - [Phase 2: BFS Web Crawling](#phase-2-bfs-web-crawling)
    - [Crawl Configuration](#crawl-configuration)
    - [Link Extraction & Queueing](#link-extraction--queueing)
    - [Same-Domain Filtering](#same-domain-filtering)
  - [Phase 3: Secret Detection](#phase-3-secret-detection)
    - [Secret Pattern Catalog (24 patterns)](#secret-pattern-catalog-24-patterns)
    - [Shannon Entropy Validation](#shannon-entropy-validation)
    - [False Positive Filtering](#false-positive-filtering)
    - [Secret Masking](#secret-masking)
  - [Phase 4: JavaScript Security Analysis](#phase-4-javascript-security-analysis)
    - [Inline JS Extraction](#inline-js-extraction)
    - [External JS Fetching](#external-js-fetching)
    - [Known Library Exclusion](#known-library-exclusion)
    - [Vulnerability Categories (13 types)](#vulnerability-categories-13-types)
    - [Minified File Handling](#minified-file-handling)
  - [Phase 5: SSRF Detection](#phase-5-ssrf-detection)
    - [Form Parameter Scanning](#form-parameter-scanning)
    - [URL Parameter Scanning](#url-parameter-scanning)
    - [API Endpoint SSRF Probing](#api-endpoint-ssrf-probing)
    - [SSRF Parameter Name List (60+ params)](#ssrf-parameter-name-list-60-params)
  - [Phase 6: HTML/Meta Security Checks](#phase-6-htmlmeta-security-checks)
    - [Weak CSP Detection](#weak-csp-detection)
    - [Missing CSRF Token Detection](#missing-csrf-token-detection)
  - [Phase 7: API Endpoint Discovery](#phase-7-api-endpoint-discovery)
    - [Regex-Based Extraction](#regex-based-extraction)
  - [Phase 8: Post-Processing](#phase-8-post-processing)
    - [Deduplication](#deduplication)
- [Internal Functions](#internal-functions)
  - [`scan_for_secrets()`](#scan_for_secrets)
  - [`scan_js_security()`](#scan_js_security)
  - [`check_url_params_ssrf()`](#check_url_params_ssrf)
  - [`extract_api_endpoints()`](#extract_api_endpoints)
  - [`resolve_url()`](#resolve_url)
  - [`is_same_domain()`](#is_same_domain)
  - [`shannon_entropy()`](#shannon_entropy)
  - [`mask_secret()`](#mask_secret)
  - [`is_false_positive_context()`](#is_false_positive_context)
  - [`is_known_library()`](#is_known_library)
  - [`dedup_secrets()`](#dedup_secrets)
  - [`dedup_js_vulns()`](#dedup_js_vulns)
- [Usage Example](#usage-example)
- [Testing](#testing)
- [Configuration Constants](#configuration-constants)

---

## Overview

The scanner performs 8 sequential phases on every target domain:

1. **Pre-Crawl Recon** — Parse `robots.txt` and `sitemap.xml`
2. **BFS Crawl** — Breadth-first crawl up to `max_depth=2`, `max_pages=50`
3. **Secret Detection** — Regex scan all content for 24 types of leaked secrets
4. **JS Security Analysis** — Analyze inline + external JS for 13 vulnerability categories
5. **SSRF Detection** — Scan forms, URL params, and actively probe API endpoints
6. **HTML/Meta Checks** — Detect weak CSP and missing CSRF tokens
7. **API Endpoint Discovery** — Extract API endpoints from HTML and JS content
8. **Post-Processing** — Deduplicate findings and assemble the result

---

## Architecture

### Scan Pipeline

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          scan_content(domain)                           │
├─────────────────┬────────────────────────────────────────────────────────┤
│  Phase 1        │  Fetch /robots.txt → parse Disallow rules             │
│  Pre-Crawl      │  Fetch /sitemap.xml → extract <loc> URLs → seed queue │
├─────────────────┼────────────────────────────────────────────────────────┤
│  Phase 2        │  BFS queue loop (max_depth=2, max_pages=50)           │
│  Crawl          │  ├─ Check robots.txt disallow                         │
│                 │  ├─ Check URL params for SSRF                         │
│                 │  ├─ Fetch page                                        │
│                 │  ├─ Run scan_for_secrets() on body                    │
│                 │  ├─ Run extract_api_endpoints() on body               │
│                 │  └─ If HTML:                                          │
│                 │     ├─ Extract <a href> → queue new links             │
│                 │     ├─ Extract <script> inline JS                     │
│                 │     │  ├─ scan_js_security()                          │
│                 │     │  └─ scan_for_secrets()                          │
│                 │     ├─ Collect <script src> external JS URLs          │
│                 │     ├─ Check forms for SSRF params                    │
│                 │     ├─ Check <meta> for weak CSP                      │
│                 │     └─ Check forms for missing CSRF                   │
├─────────────────┼────────────────────────────────────────────────────────┤
│  Phase 3        │  Fetch external JS files (skip known libraries)       │
│  External JS    │  ├─ scan_js_security()                                │
│                 │  ├─ scan_for_secrets()                                │
│                 │  └─ extract_api_endpoints()                           │
├─────────────────┼────────────────────────────────────────────────────────┤
│  Phase 4        │  Active SSRF probing on discovered API endpoints      │
│  SSRF Probing   │  └─ Up to 20 endpoints × 5 SSRF payloads             │
├─────────────────┼────────────────────────────────────────────────────────┤
│  Phase 5        │  Deduplicate all findings                             │
│  Post-Process   │  └─ Assemble ScannerResult                           │
└─────────────────┴────────────────────────────────────────────────────────┘
```

### Dependency Graph

```
advanced_content_scanner
├── crate::payloads        (SSRF probe URLs from payloads/ssrf.txt)
├── reqwest::Client        (HTTP client with 15s timeout, TLS skip)
├── scraper::{Html,Selector}  (CSS selector-based HTML parsing)
├── regex::Regex           (Pattern matching for secrets, JS vulns, API paths)
└── serde::{Serialize,Deserialize}  (JSON serialization for results)
```

---

## Public API

### `scan_content()`

```rust
pub async fn scan_content(
    domain: &str
) -> Result<ScannerResult, Box<dyn std::error::Error + Send + Sync>>
```

**Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `domain` | `&str` | Target domain. Accepts bare domain (`example.com`) or full URL (`https://example.com`). If no scheme is provided, `https://` is prepended. |

**Returns:** `Result<ScannerResult, Error>` — Full scan results or an error.

**Behavior:**
- Creates an HTTP client with 15-second timeout and TLS certificate validation disabled
- Executes all 8 scan phases sequentially
- All regex patterns are compiled once at scan start for performance

---

## Data Structures

### `ScannerResult`

Top-level result container returned by `scan_content()`.

```rust
pub struct ScannerResult {
    pub domain: String,                         // Target domain
    pub secrets: Vec<SecretFinding>,             // Leaked secrets found
    pub js_vulnerabilities: Vec<JsVulnerability>,// JavaScript security issues
    pub ssrf_vulnerabilities: Vec<SsrfFinding>,  // SSRF attack surfaces
    pub api_endpoints_discovered: Vec<String>,   // API endpoints found in content
    pub summary: ScanSummary,                    // Aggregate stats
}
```

### `SecretFinding`

Represents a single leaked secret or credential.

```rust
pub struct SecretFinding {
    pub secret_type: String,    // e.g. "AWS Access Key", "JWT Token"
    pub severity: String,       // "High", "Medium", or "Low"
    pub masked_value: String,   // e.g. "AKIA****WXYZ" (first 4 + last 4)
    pub source_url: String,     // URL where the secret was found
    pub line: usize,            // Line number in the source content
    pub entropy: f64,           // Shannon entropy (rounded to 2 decimals)
    pub recommendation: String, // Remediation guidance
}
```

### `JsVulnerability`

Represents a JavaScript security vulnerability or misconfiguration.

```rust
pub struct JsVulnerability {
    pub vuln_type: String,      // e.g. "DOM XSS", "Weak CSP"
    pub severity: String,       // "High", "Medium", or "Low"
    pub source_url: String,     // URL where the vulnerability was found
    pub matched_code: String,   // Code snippet (truncated to 200 chars)
    pub description: String,    // What the vulnerability means
    pub recommendation: String, // How to fix it
}
```

### `SsrfFinding`

Represents a Server-Side Request Forgery attack surface.

```rust
pub struct SsrfFinding {
    pub finding_type: String,          // "Potential SSRF in Form", "Potential SSRF in URL Parameter",
                                       // or "Confirmed SSRF in API Endpoint"
    pub severity: String,              // "Medium" (passive) or "High" (confirmed)
    pub source_url: String,            // URL containing the vulnerability
    pub vulnerable_params: Vec<String>,// Parameter names flagged
    pub description: String,           // Details of the finding
}
```

### `ScanSummary`

Aggregate statistics for the scan run.

```rust
pub struct ScanSummary {
    pub total_urls_crawled: usize,          // Pages visited by the BFS crawler
    pub total_js_files: usize,              // External JS files fetched and analyzed
    pub total_api_endpoints: usize,         // API endpoints discovered in content
    pub secrets_count: usize,               // Total unique secrets found
    pub js_vulnerabilities_count: usize,    // Total unique JS vulnerabilities
    pub ssrf_vulnerabilities_count: usize,  // Total SSRF findings
}
```

---

## Scan Phases

### Phase 1: Pre-Crawl Reconnaissance

#### robots.txt Parsing

- Fetches `{base_url}/robots.txt`
- Parses `User-agent: *` blocks
- Collects all `Disallow:` paths into a list
- During BFS crawl, any URL path matching a disallowed prefix is **skipped**
- Gracefully handles missing or inaccessible `robots.txt`

#### sitemap.xml Processing

- Fetches `{base_url}/sitemap.xml`
- Extracts all `<loc>` URLs using regex: `<loc>([^<]+)</loc>`
- Filters to same-domain URLs only
- Seeds the BFS queue at depth 1 (giving the crawler better starting coverage)
- Gracefully handles missing or malformed sitemaps

---

### Phase 2: BFS Web Crawling

#### Crawl Configuration

| Constant | Value | Description |
|----------|-------|-------------|
| `max_depth` | `2` | Maximum link-following depth from the root URL |
| `max_pages` | `50` | Maximum total pages to visit before stopping |
| HTTP timeout | `15s` | Per-request timeout |
| TLS validation | `disabled` | Accepts self-signed certificates |

#### Link Extraction & Queueing

For every HTML page visited, all `<a href="...">` elements are extracted. Each `href` is:
1. Resolved to an absolute URL via `resolve_url()`
2. Filtered to same-domain only via `is_same_domain()`
3. Checked for duplicates against the `visited` set
4. Added to the BFS queue with `depth + 1`

The following URL schemes are **skipped** by `resolve_url()`:
- `javascript:`, `mailto:`, `tel:`, `#` (anchor fragments)

#### Same-Domain Filtering

`is_same_domain()` extracts the hostname from both URLs (stripping scheme and path) and performs a case-insensitive comparison. Only URLs on the same host are queued.

---

### Phase 3: Secret Detection

#### Secret Pattern Catalog (24 patterns)

| # | Secret Type | Regex Pattern | Severity |
|---|-------------|---------------|----------|
| 1 | AWS Access Key | `\bAKIA[0-9A-Z]{16}\b` | Medium |
| 2 | AWS Secret Key | `\b[0-9a-zA-Z/+]{40}\b` | High |
| 3 | Google API Key | `\bAIza[0-9A-Za-z\-_]{35}\b` | Medium |
| 4 | Google OAuth | `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com` | Medium |
| 5 | Stripe API Key | `\b(?:sk\|pk)_(live\|test)_[0-9a-zA-Z]{24,34}\b` | High |
| 6 | GitHub Token | `\b(?:github\|gh)(?:_pat)?_[0-9a-zA-Z]{36,40}\b` | High |
| 7 | GitHub OAuth | `\bgho_[0-9a-zA-Z]{36,40}\b` | High |
| 8 | Facebook Access Token | `EAACEdEose0cBA[0-9A-Za-z]+` | Medium |
| 9 | JWT Token | `eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*` | Medium |
| 10 | SSH Private Key | `-----BEGIN\s+(?:RSA\|DSA\|EC\|OPENSSH)\s+PRIVATE\s+KEY` | High |
| 11 | Password in URL | `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}` | High |
| 12 | Firebase URL | `https://[a-z0-9-]+\.firebaseio\.com` | Low |
| 13 | MongoDB Connection String | `mongodb(?:\+srv)?://[^/\s]+:[^/\s]+@[^/\s]+` | High |
| 14 | Slack Token | `xox[baprs]-[0-9a-zA-Z\-]{10,48}` | Medium |
| 15 | Slack Webhook | `https://hooks\.slack\.com/services/T.../B.../...` | Medium |
| 16 | API Key (generic) | `(?i)\b(?:api[_\-]?key\|apikey)\b\s*[=:]\s*["'\`](...)[\"'\`]` | Medium |
| 17 | Secret Key (generic) | `(?i)\b(?:secret[_\-]?key\|secretkey)\b\s*[=:]\s*["'\`](...)[\"'\`]` | Medium |
| 18 | Auth Token (generic) | `(?i)\b(?:auth[_\-]?token\|authtoken)\b\s*[=:]\s*["'\`](...)[\"'\`]` | Medium |
| 19 | Access Token (generic) | `(?i)\b(?:access[_\-]?token\|accesstoken)\b\s*[=:]\s*["'\`](...)[\"'\`]` | Medium |
| 20 | Encryption Key | `(?i)(?:encryption\|aes\|des\|blowfish)[\s_-]?key[\s=:]+["'\`]...[\"'\`]` | High |
| 21 | Stripe Publishable Key | `\bpk_(live\|test)_[0-9a-zA-Z]{24,34}\b` | Low |
| 22 | Twitter Bearer | `AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+` | Medium |
| 23 | Password (hardcoded) | `(?i)(?:password\|passwd\|pwd)[\s=:]+["'\`](...)[\"'\`]` | High |
| 24 | Database Credentials | `(?i)(?:db_pass\|db_password\|database_password)[\s=:]+["'\`](...)[\"'\`]` | High |

#### Shannon Entropy Validation

Calculates the [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of matched strings:

```
H(X) = -Σ p(x) × log₂(p(x))
```

- **Threshold: 3.5 bits** — Matches below this entropy are discarded for the following pattern types: `AWS Secret Key`, `Google API Key`, `API Key`, `Secret Key`
- Low-entropy strings like `aaaaaaaaaaaaaaaa` (H=0.0) or `abcabcabcabc` are filtered out
- High-entropy strings like `aB3xZ9kL2mN7pQ4s` (H≈4.0) pass through

#### False Positive Filtering

The **80-character context window** around each match is checked against 12 false-positive indicators:

| Indicator | Example |
|-----------|---------|
| `example` | `"key": "example-api-key-here"` |
| `sample` | `sample_token = "..."` |
| `placeholder` | `placeholder_secret` |
| `dummy` | `dummy_password` |
| `test` | `test_api_key` |
| `demo` | `demo_credentials` |
| `your_` | `your_api_key_here` |
| `my_` | `my_secret_key` |
| `template` | `template_token` |
| `undefined` | `undefined` |
| `localhost` | `mongodb://user:pass@localhost` |
| `127.0.0.1` | `http://127.0.0.1:3000` |

#### Secret Masking

All reported secret values are masked for safe display:

| Input Length | Format | Example |
|-------------|--------|---------|
| ≤ 2 chars | `****` | `****` |
| 3–8 chars | `****XX` | `****xy` |
| > 8 chars | `XXXX****XXXX` | `AKIA****WXYZ` |

---

### Phase 4: JavaScript Security Analysis

#### Inline JS Extraction

All `<script>` tags without a `src` attribute are collected. Inline scripts shorter than 10 characters are skipped.

#### External JS Fetching

All `<script src="...">` URLs are:
1. Resolved to absolute URLs
2. Filtered through `is_known_library()` — known libraries are skipped
3. Collected in a dedicated set
4. Fetched and analyzed after the BFS crawl completes

#### Known Library Exclusion

External JS URLs containing any of these 19 substrings are skipped entirely:

`jquery`, `bootstrap`, `modernizr`, `polyfill`, `vendor`, `bundle`, `analytics`, `tracking`, `ga.js`, `gtm.js`, `react`, `angular`, `vue`, `lodash`, `moment`, `cdn`, `static`, `dist`, `chunk`

#### Vulnerability Categories (13 types)

| # | Category | Severity | Patterns | Description |
|---|----------|----------|----------|-------------|
| 1 | **DOM XSS** | High | 4 | User-controllable data (`location`, `URL`, `referrer`, `hash`) passed to `document.write()`, `.innerHTML`, `.outerHTML`, or `eval()` |
| 2 | **Open Redirect** | High | 3 | `location.href`, `location.replace()`, `location.assign()` set from user-controlled variables |
| 3 | **CORS Misconfiguration** | Medium | 3 | `Access-Control-Allow-Origin: *`, `null`, or `Allow-Credentials: true` |
| 4 | **Insecure Cookie** | Medium | 1 | Direct `document.cookie =` assignment without flags |
| 5 | **Insecure Data Transmission** | Medium | 1 | `postMessage()` with wildcard `"*"` origin |
| 6 | **Prototype Pollution** | Medium | 2 | `__proto__` assignment or `prototype[` access |
| 7 | **Command Injection** | High | 2 | `exec()` or `spawn()` with user-input arguments |
| 8 | **Insecure Data Storage** | Low | 2 | `localStorage.setItem()` / `sessionStorage.setItem()` storing passwords, tokens, keys, etc. |
| 9 | **Event Handler XSS** | Medium | 1 | `.setAttribute('on...',` dynamic event handler assignment |
| 10 | **CSP Bypass** | Medium | 1 | `document.createElement('script')` dynamic script injection |
| 11 | **WebSocket Insecurity** | High | 1 | `new WebSocket('ws://...')` using unencrypted protocol |
| 12 | **Insecure Crypto** | High | 2 | Use of MD5/SHA1 or `Math.random()` for security purposes |
| 13 | **Path Traversal** | Medium | 1 | `../` or `..\` path traversal patterns |

#### Minified File Handling

Files are detected as **minified** when:
- Content length > 5,000 characters **AND**
- Newline count < 50

For minified files, **only High-severity** vulnerability checks are performed. Medium and Low severity checks are skipped to reduce noise.

---

### Phase 5: SSRF Detection

#### Form Parameter Scanning

For every `<form>` on each crawled HTML page:
1. All `<input name="...">` and `<textarea name="...">` elements are extracted
2. Each parameter name is checked (case-insensitive) against the SSRF parameter list
3. If any matches, an `SsrfFinding` with `finding_type: "Potential SSRF in Form"` is emitted

#### URL Parameter Scanning

For every URL the crawler visits:
1. The query string is parsed (`?key=value&key2=value2`)
2. Each parameter name is checked against the SSRF parameter list
3. If any matches, an `SsrfFinding` with `finding_type: "Potential SSRF in URL Parameter"` is emitted

#### API Endpoint SSRF Probing

After all crawling and JS analysis completes:
1. Up to **20 discovered API endpoints** are selected
2. For each, the **top 5 SSRF probe URLs** from `payloads/ssrf.txt` are tested
3. A `GET` request is sent to `{endpoint}?url={probe}`
4. If the response is a **redirect** and the `Location` header contains the probe URL, a **confirmed SSRF** finding with `severity: "High"` is emitted

SSRF probes include AWS metadata (`http://169.254.169.254/...`), GCP metadata, Azure metadata, localhost ports, and local file schemes.

#### SSRF Parameter Name List (60+ params)

The full list of parameter names checked:

```
url, uri, link, src, href, target, destination, redirect, redirect_to,
redirecturl, redirect_uri, return, return_to, returnurl, return_path,
path, load, file, filename, folder, folder_url, image, img, image_url,
image_path, avatar, document, doc, document_url, fetch, get, view,
content, domain, callback, reference, site, page, data, data_url,
resource, template, api_endpoint, endpoint, proxy, feed, host, webhook,
address, media, video, audio, download, upload, preview, source,
location, goto, callback_url, forward, next, origin, continue
```

---

### Phase 6: HTML/Meta Security Checks

#### Weak CSP Detection

Scans for `<meta http-equiv="Content-Security-Policy" content="...">` tags. Flags as vulnerable if the `content` attribute contains:
- `unsafe-inline`
- `unsafe-eval`

Reported as `JsVulnerability` with `vuln_type: "Weak CSP"`, severity Medium.

#### Missing CSRF Token Detection

For every `<form>` element, checks for the presence of hidden inputs named `csrf`, `xsrf`, or `token` (case-insensitive substring match). If none are found, reported as `JsVulnerability` with `vuln_type: "Missing CSRF Protection"`, severity Medium.

---

### Phase 7: API Endpoint Discovery

#### Regex-Based Extraction

All fetched content (HTML bodies and JS files) is scanned for API path patterns:

| Pattern | Matches |
|---------|---------|
| `/api/v\d+/` | `/api/v1/`, `/api/v2/users` |
| `/api/` | `/api/login` |
| `/graphql` | `/graphql` |
| `/rest/` | `/rest/v1/endpoint` |
| `/v\d+/\w+` | `/v2/users` |
| `/service/` | `/service/auth` |
| `/json/` | `/json/data` |
| `/rpc/` | `/rpc/call` |
| `/gateway/` | `/gateway/api` |
| `/ajax/` | `/ajax/handler` |
| `/data/` | `/data/export` |
| `/query/` | `/query/search` |
| `/feeds/` | `/feeds/rss` |
| `/svc/` | `/svc/core` |
| `/soap/` | `/soap/endpoint` |

Discovered paths are appended to the base URL and collected in a `HashSet` for deduplication.

---

### Phase 8: Post-Processing

#### Deduplication

Both `secrets` and `js_vulnerabilities` are deduplicated using composite hash keys:

- **Secrets:** `{secret_type}:{source_url}:{masked_value}`
- **JS Vulns:** `{vuln_type}:{source_url}:{matched_code}`

Duplicate entries with the same key are removed, keeping the first occurrence.

---

## Internal Functions

### `scan_for_secrets()`

```rust
fn scan_for_secrets(content, source_url, patterns, results)
```
Iterates all 24 compiled regex patterns against the content. For each match: calculates entropy, checks false positive context, masks the value, and appends a `SecretFinding`.

### `scan_js_security()`

```rust
fn scan_js_security(content, source_url, categories, results)
```
Iterates all 13 vulnerability categories. Detects minified files and skips non-critical checks. Truncates matched code to 200 chars.

### `check_url_params_ssrf()`

```rust
fn check_url_params_ssrf(url, findings)
```
Parses query string from a URL and checks each parameter name against the 60+ SSRF parameter list.

### `extract_api_endpoints()`

```rust
fn extract_api_endpoints(content, base_url, patterns, endpoints)
```
Runs 15 API path regexes against content and inserts full URLs into the endpoints set.

### `resolve_url()`

```rust
fn resolve_url(base, href) -> Option<String>
```
Resolves relative URLs to absolute. Handles `//protocol-relative`, `http(s)://absolute`, and `relative/path` forms. Returns `None` for `javascript:`, `mailto:`, `tel:`, and `#` anchors.

### `is_same_domain()`

```rust
fn is_same_domain(base, url) -> bool
```
Extracts hostnames from both URLs and compares case-insensitively.

### `shannon_entropy()`

```rust
fn shannon_entropy(data) -> f64
```
Calculates Shannon entropy in bits per character. Uses a 256-slot byte frequency table.

### `mask_secret()`

```rust
fn mask_secret(s) -> String
```
Returns a masked version showing only the first 4 and last 4 characters with `****` in between.

### `is_false_positive_context()`

```rust
fn is_false_positive_context(context) -> bool
```
Checks 80 chars of surrounding context against 12 false positive indicator strings.

### `is_known_library()`

```rust
fn is_known_library(url) -> bool
```
Checks if a JS URL contains any of 19 known library/framework substrings.

### `dedup_secrets()`

```rust
fn dedup_secrets(v: &mut Vec<SecretFinding>)
```
Removes duplicate secrets using composite hash key `{type}:{url}:{masked_value}`.

### `dedup_js_vulns()`

```rust
fn dedup_js_vulns(v: &mut Vec<JsVulnerability>)
```
Removes duplicate JS vulnerabilities using composite hash key `{type}:{url}:{code}`.

---

## Usage Example

```rust
use web_analyzer::advanced_content_scanner::scan_content;

#[tokio::main]
async fn main() {
    let result = scan_content("example.com").await.unwrap();

    println!("Crawled {} pages, found {} JS files",
        result.summary.total_urls_crawled,
        result.summary.total_js_files);

    for secret in &result.secrets {
        println!("[{}] {} at {} (line {}, entropy {:.2})",
            secret.severity, secret.secret_type,
            secret.source_url, secret.line, secret.entropy);
        println!("  Value: {}", secret.masked_value);
        println!("  Fix: {}", secret.recommendation);
    }

    for vuln in &result.js_vulnerabilities {
        println!("[{}] {} at {}",
            vuln.severity, vuln.vuln_type, vuln.source_url);
        println!("  Code: {}", vuln.matched_code);
        println!("  Fix: {}", vuln.recommendation);
    }

    for ssrf in &result.ssrf_vulnerabilities {
        println!("[{}] {} at {} — params: {:?}",
            ssrf.severity, ssrf.finding_type,
            ssrf.source_url, ssrf.vulnerable_params);
    }

    println!("API endpoints discovered: {:?}", result.api_endpoints_discovered);
}
```

---

## Testing

```bash
# Run scanner tests only
cargo test --features advanced-content-scanner

# Run with output
cargo test --features advanced-content-scanner -- --nocapture
```

**Test suite covers:**
- `test_scan_content` — End-to-end scan against `example.com`, verifies result structure and crawl metrics
- `test_shannon_entropy` — Validates entropy calculation: high-entropy strings > 3.5, low-entropy < 1.0

---

## Configuration Constants

| Constant | Value | Location | Description |
|----------|-------|----------|-------------|
| `max_depth` | `2` | `scan_content()` | Maximum BFS crawl depth |
| `max_pages` | `50` | `scan_content()` | Maximum pages to visit |
| HTTP timeout | `15s` | `Client::builder()` | Per-request timeout |
| TLS validation | `false` | `danger_accept_invalid_certs(true)` | Accept self-signed certs |
| Entropy threshold | `3.5` | `scan_for_secrets()` | Minimum entropy for key-type secrets |
| Context window | `±80 chars` | `scan_for_secrets()` | Chars around match for FP check |
| Minified threshold | `>5000 chars, <50 newlines` | `scan_js_security()` | Minified file detection |
| Matched code limit | `200 chars` | `scan_js_security()` | Truncation for `matched_code` field |
| SSRF endpoint limit | `20` | SSRF probing | Max API endpoints to actively probe |
| SSRF probes per endpoint | `5` | SSRF probing | Top N SSRF payloads per endpoint |
| `SECRET_PATTERNS` | `24` | module-level | Number of secret regex patterns |
| `JS_VULN_CATEGORIES` | `13` | module-level | Number of JS vulnerability categories |
| `SSRF_PARAMS` | `60+` | module-level | Number of SSRF-vulnerable parameter names |
| Known libraries | `19` | `is_known_library()` | Library substrings to skip |
| False positive indicators | `12` | `is_false_positive_context()` | Context-based FP filters |
