# Cloudflare Bypass

> **Module:** `cloudflare_bypass`
> **Feature Flag:** `cloudflare-bypass`
> **Source:** [`src/cloudflare_bypass.rs`](../src/cloudflare_bypass.rs)
> **Lines:** ~230 | **Dependencies:** `reqwest`, `regex`, `serde`, `tokio`

Discovers the real origin IP addresses of websites hidden behind Cloudflare's reverse proxy. Uses 4 complementary techniques with IP verification and confidence-ranked results.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Public API](#public-api)
  - [`find_real_ip()`](#find_real_ip)
- [Data Structures](#data-structures)
  - [`FoundIp`](#foundip)
  - [`CloudflareBypassResult`](#cloudflarebypassresult)
- [Detection Techniques](#detection-techniques)
  - [1. Direct DNS Resolution](#1-direct-dns-resolution)
  - [2. Subdomain Enumeration](#2-subdomain-enumeration)
  - [3. Response Header IP Leak Detection](#3-response-header-ip-leak-detection)
  - [4. IP History Lookup](#4-ip-history-lookup)
- [IP Classification](#ip-classification)
  - [Cloudflare IP Detection](#cloudflare-ip-detection)
  - [Private IP Filtering](#private-ip-filtering)
  - [IP Validation](#ip-validation)
- [Post-Processing](#post-processing)
  - [Deduplication & Confidence Sorting](#deduplication--confidence-sorting)
  - [IP Verification via TCP Connect](#ip-verification-via-tcp-connect)
- [Internal Functions](#internal-functions)
  - [`is_cloudflare_ip()`](#is_cloudflare_ip)
  - [`is_private_ip()`](#is_private_ip)
  - [`is_valid_ip()`](#is_valid_ip)
  - [`confidence_score()`](#confidence_score)
  - [`check_ip_history()`](#check_ip_history)
  - [`verify_ip()`](#verify_ip)
- [Constants Reference](#constants-reference)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌───────────────────────────────────────────────────────────────┐
│                    find_real_ip(domain)                       │
├──────────────┬────────────────────────────────────────────────┤
│ Step 1       │ Direct DNS resolution → Cloudflare check      │
│ Step 2       │ Subdomain probing (11 subdomains)             │
│ Step 3       │ Response header IP leak scan (8 headers)      │
│ Step 4       │ IP history lookup (3 sources)                 │
│ Step 5       │ Deduplicate + confidence sort                 │
│ Step 6       │ TCP verify top 5 IPs                          │
└──────────────┴────────────────────────────────────────────────┘
```

Steps 2–4 only run if the domain is confirmed behind Cloudflare.

---

## Public API

### `find_real_ip()`

```rust
pub async fn find_real_ip(
    domain: &str
) -> Result<CloudflareBypassResult, Box<dyn std::error::Error + Send + Sync>>
```

| Param | Type | Description |
|-------|------|-------------|
| `domain` | `&str` | Target domain. Accepts `example.com` or `https://example.com`. |

---

## Data Structures

### `FoundIp`

```rust
pub struct FoundIp {
    pub ip: String,          // "1.2.3.4"
    pub source: String,      // "direct_dns", "subdomain_mail", "header_x-real-ip", "history_ViewDNS"
    pub confidence: String,  // "Very High", "High", "Medium", "Low"
    pub description: Option<String>,  // Optional description
    pub status: Option<String>,       // "active", "inactive", "unverified"
}
```

### `CloudflareBypassResult`

```rust
pub struct CloudflareBypassResult {
    pub domain: String,
    pub cloudflare_protected: bool,
    pub found_ips: Vec<FoundIp>,     // Sorted by confidence (highest first)
    pub scan_time_ms: u128,
}
```

---

## Detection Techniques

### 1. Direct DNS Resolution

Resolves the domain via `tokio::net::lookup_host()`. If the resolved IP is **not** a Cloudflare IP, it's added with **Very High** confidence. If it **is** a CF IP, `cloudflare_protected` is set to `true` and bypass techniques (2–4) are activated.

### 2. Subdomain Enumeration

Probes **11 subdomains** — 7 common + 4 domain-specific:

| Common (7) | Domain-Specific (4) |
|-----------|---------------------|
| `direct.{domain}` | `origin-{name}.{domain}` |
| `origin.{domain}` | `{name}-origin.{domain}` |
| `api.{domain}` | `direct-{name}.{domain}` |
| `mail.{domain}` | `{name}-direct.{domain}` |
| `cpanel.{domain}` | |
| `server.{domain}` | |
| `ftp.{domain}` | |

Each resolved IP is filtered for CF and private ranges. Matches get **Medium** confidence.

### 3. Response Header IP Leak Detection

Sends an HTTPS GET to the domain and inspects **8 response headers**:

| Header | Why it leaks |
|--------|-------------|
| `X-Forwarded-For` | Proxy chain includes origin |
| `X-Real-IP` | Origin IP set by reverse proxy |
| `X-Origin-IP` | Explicit origin IP header |
| `CF-Connecting-IP` | Cloudflare sets client IP |
| `X-Server-IP` | Backend server IP |
| `Server-IP` | Server identification |
| `X-Backend-Server` | Load balancer backend |
| `X-Origin-Server` | Origin server header |

IPs extracted via regex `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`, filtered for CF/private. Matches get **High** confidence.

### 4. IP History Lookup

Queries **3 external IP history databases**:

| Source | URL Pattern |
|--------|------------|
| **ViewDNS** | `viewdns.info/iphistory/?domain={domain}` |
| **SecurityTrails** | `securitytrails.com/domain/{domain}/history/a` |
| **WhoIs** | `who.is/whois/{domain}` |

Sends requests with randomized User-Agent, Accept, and Referer headers. Extracts all IPv4 addresses from response bodies, filters CF/private. Matches get **Medium** confidence.

---

## IP Classification

### Cloudflare IP Detection

28 prefix-based checks covering all Cloudflare IPv4 ranges:

```
173.245.x, 103.21.x, 103.22.x, 103.31.x, 141.101.x,
108.162.x, 190.93.x, 188.114.x, 197.234.x, 198.41.x,
162.158.x, 162.159.x, 104.16-27.x, 172.64-67.x, 131.0.x
```

### Private IP Filtering

Excludes RFC 1918, loopback, and link-local addresses:

```
10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 0.x.x.x, 169.254.x.x
```

### IP Validation

Validates IPv4 format: 4 octets, each 0–255.

---

## Post-Processing

### Deduplication & Confidence Sorting

Duplicate IPs are merged, keeping the entry with the **highest** confidence level:

| Level | Score |
|-------|-------|
| Very High | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |

Results are sorted descending by score.

### IP Verification via TCP Connect

Top **5** IPs are verified with a TCP connection to port 80 (3s timeout):

| Status | Meaning |
|--------|---------|
| `active` | TCP connect succeeded |
| `inactive` | TCP connect failed or timed out |
| `unverified` | Beyond top 5, not tested |

---

## Internal Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `is_cloudflare_ip()` | `fn(ip: &str) -> bool` | Prefix-based CF range check |
| `is_private_ip()` | `fn(ip: &str) -> bool` | RFC 1918 + loopback check |
| `is_valid_ip()` | `fn(ip: &str) -> bool` | IPv4 format validation |
| `confidence_score()` | `fn(c: &str) -> u8` | Map confidence string to numeric score |
| `check_ip_history()` | `async fn(client, domain, regex) -> Vec<FoundIp>` | Query 3 IP history sources |
| `verify_ip()` | `async fn(ip: &str) -> String` | TCP connect test on port 80 |

---

## Constants Reference

| Constant | Count | Description |
|----------|-------|-------------|
| `CF_PREFIXES` | 28 | Cloudflare IPv4 prefix strings |
| `HEADERS_TO_CHECK` | 8 | Response headers to scan for IP leaks |
| `IP_HISTORY_SOURCES` | 3 | External IP history databases |
| `PRIVATE_PREFIXES` | 21 | Private/reserved IP prefixes |
| HTTP timeout | 8s | Per-request timeout |
| TLS validation | disabled | Accepts self-signed certs |
| TCP verify timeout | 3s | IP verification timeout |
| Max redirects | 3 | Redirect follow limit |
| Verify count | 5 | Top N IPs to TCP-verify |

---

## Usage Example

```rust
use web_analyzer::cloudflare_bypass::find_real_ip;

#[tokio::main]
async fn main() {
    let result = find_real_ip("example.com").await.unwrap();

    println!("CF Protected: {}", result.cloudflare_protected);
    println!("Scan time: {}ms", result.scan_time_ms);

    for ip in &result.found_ips {
        println!("[{}] {} — {} ({})",
            ip.status.as_deref().unwrap_or("?"),
            ip.ip, ip.source, ip.confidence);
    }
}
```

---

## Testing

```bash
cargo test --features cloudflare-bypass -- --nocapture
```
