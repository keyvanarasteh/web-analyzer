# Domain Validator

> **Module:** `domain_validator`
> **Feature Flag:** `domain-validator`
> **Source:** [`src/domain_validator.rs`](../src/domain_validator.rs)
> **Lines:** ~320 | **Dependencies:** `reqwest`, `serde`, `tokio`

Comprehensive domain validation with parallel DNS, HTTP, and SSL checks. Supports single-domain and bulk validation with configurable concurrency, skip patterns, and detailed statistics.

---

## Table of Contents

- [Overview](#overview)
- [Public API](#public-api)
  - [`validate_domain()`](#validate_domain)
  - [`validate_domains_bulk()`](#validate_domains_bulk)
- [Data Structures](#data-structures)
  - [`ValidationResult`](#validationresult)
  - [`DnsValidation`](#dnsvalidation)
  - [`HttpValidation`](#httpvalidation)
  - [`SslValidation`](#sslvalidation)
  - [`ValidationStats`](#validationstats)
  - [`BulkValidationResult`](#bulkvalidationresult)
- [Validation Pipeline](#validation-pipeline)
  - [1. Skip Check](#1-skip-check)
  - [2. DNS Validation](#2-dns-validation)
  - [3. HTTP Validation](#3-http-validation)
  - [4. SSL Validation](#4-ssl-validation)
- [Skip Patterns](#skip-patterns)
  - [Noise Patterns (17)](#noise-patterns-17)
  - [Internal/RFC1918 Patterns (17)](#internalrfc1918-patterns-17)
  - [Additional Checks](#additional-checks)
- [Parallel Bulk Processing](#parallel-bulk-processing)
- [Usage Examples](#usage-examples)
- [Prerequisites](#prerequisites)
- [Testing](#testing)

---

## Overview

```
┌───────────────────────────────────────────────────────────┐
│ validate_domain(domain)  /  validate_domains_bulk(...)    │
├───────────────┬───────────────────────────────────────────┤
│ 1. Skip Check │ 17 noise + 17 internal patterns          │
│               │ IP detection, length, TLD check          │
├───────────────┼───────────────────────────────────────────┤
│ 2. DNS        │ dig +short A → IP addresses              │
│               │ dig +short MX → mail exchange check      │
├───────────────┼───────────────────────────────────────────┤
│ 3. HTTP       │ HTTPS HEAD (primary) → HTTP fallback     │
│               │ Redirect-to-HTTPS detection              │
│               │ Response time measurement                │
├───────────────┼───────────────────────────────────────────┤
│ 4. SSL        │ openssl s_client → protocol + cipher     │
├───────────────┼───────────────────────────────────────────┤
│ Result        │ valid = dns_valid AND http_valid          │
└───────────────┴───────────────────────────────────────────┘

Bulk Mode: Tokio semaphore for concurrency limiting
           Atomic counters for thread-safe statistics
```

---

## Public API

### `validate_domain()`

```rust
pub async fn validate_domain(domain: &str) -> ValidationResult
```

Validates a single domain through the full pipeline (skip → DNS → HTTP → SSL).

### `validate_domains_bulk()`

```rust
pub async fn validate_domains_bulk(
    domains: &[String],
    max_concurrency: usize,
) -> BulkValidationResult
```

Validates multiple domains in parallel with configurable concurrency.

---

## Data Structures

### `ValidationResult`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `String` | Domain name |
| `valid` | `bool` | Overall validity (DNS + HTTP) |
| `skip_reason` | `Option<String>` | Why it was skipped |
| `dns_valid` | `bool` | DNS resolution passed |
| `http_valid` | `bool` | HTTP connectivity passed |
| `ssl_valid` | `bool` | SSL/TLS available |
| `dns_info` | `Option<DnsValidation>` | DNS details |
| `http_info` | `Option<HttpValidation>` | HTTP details |
| `ssl_info` | `Option<SslValidation>` | SSL details |
| `errors` | `Vec<String>` | Error messages |

### `DnsValidation`

| Field | Type | Description |
|-------|------|-------------|
| `ip_addresses` | `Vec<String>` | Resolved A records |
| `mx_exists` | `bool` | Has MX records |

### `HttpValidation`

| Field | Type | Description |
|-------|------|-------------|
| `http_reachable` | `bool` | HTTP works |
| `https_reachable` | `bool` | HTTPS works |
| `http_status` | `Option<u16>` | HTTP status code |
| `https_status` | `Option<u16>` | HTTPS status code |
| `redirects_to_https` | `bool` | HTTP → HTTPS redirect |
| `response_time_ms` | `u128` | Response time |

### `SslValidation`

| Field | Type | Description |
|-------|------|-------------|
| `ssl_available` | `bool` | SSL connection succeeded |
| `protocol_version` | `String` | e.g. TLSv1.3 |
| `cipher_suite` | `String` | Active cipher suite |

### `ValidationStats`

| Field | Type | Description |
|-------|------|-------------|
| `total` | `usize` | Total domains |
| `valid` | `usize` | Passed validation |
| `invalid` | `usize` | Failed validation |
| `skipped` | `usize` | Skipped (noise/internal) |
| `dns_failed` | `usize` | DNS failures |
| `http_failed` | `usize` | HTTP failures |
| `ssl_failed` | `usize` | SSL failures |
| `success_rate` | `f64` | Percentage valid |
| `processing_time_secs` | `f64` | Total time |
| `domains_per_sec` | `f64` | Throughput |

### `BulkValidationResult`

| Field | Type | Description |
|-------|------|-------------|
| `stats` | `ValidationStats` | Overall statistics |
| `valid_domains` | `Vec<String>` | Domains that passed |
| `results` | `Vec<ValidationResult>` | Per-domain details |

---

## Skip Patterns

### Noise Patterns (17)

`stun.l.google.com`, `.cloudapp.azure.com`, `clients6.google.com`, `.cdn.cloudflare.net`, `rr1-5.sn-*`, `e-0014.e-msedge`, `s-part-`, `.t-msedge.net`, `perimeterx.map`, `i.ytimg.com`, `analytics-alv.google.com`, `signaler-pa.clients`, `westus-0.in.applicationinsights`

### Internal/RFC1918 Patterns (17)

`localhost`, `127.0.0.1`, `0.0.0.0`, `192.168.*`, `10.*`, `172.16-31.*`

### Additional Checks

- IP address detection (`std::net::IpAddr::parse`)
- Length validation (4-253 characters)
- TLD presence (must contain `.`)

---

## Parallel Bulk Processing

- **Concurrency control:** `tokio::sync::Semaphore` limits concurrent tasks
- **Thread-safe stats:** `AtomicUsize` counters (no mutex overhead)
- **Connection pooling:** `reqwest` client shared across tasks with `pool_max_idle_per_host`
- **Task spawning:** Each domain is a `tokio::spawn` task

---

## Usage Examples

### Single Domain

```rust
use web_analyzer::domain_validator::validate_domain;

#[tokio::main]
async fn main() {
    let result = validate_domain("example.com").await;
    println!("{}: valid={}, dns={}, http={}, ssl={}",
        result.domain, result.valid,
        result.dns_valid, result.http_valid, result.ssl_valid);
}
```

### Bulk Validation

```rust
use web_analyzer::domain_validator::validate_domains_bulk;

#[tokio::main]
async fn main() {
    let domains = vec![
        "example.com".into(), "google.com".into(),
        "invalid.tld".into(), "localhost".into(),
    ];

    let result = validate_domains_bulk(&domains, 10).await;

    println!("Valid: {}/{} ({:.1}%)",
        result.stats.valid, result.stats.total, result.stats.success_rate);
    println!("Speed: {:.2} domains/sec", result.stats.domains_per_sec);

    for domain in &result.valid_domains {
        println!("  ✅ {}", domain);
    }
}
```

---

## Prerequisites

- **dig** (dnsutils) — for DNS resolution
- **openssl** — for SSL validation

---

## Testing

```bash
cargo test --features domain-validator -- --nocapture
```
