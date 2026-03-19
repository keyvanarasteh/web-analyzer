# Subdomain Discovery

> **Module:** `subdomain_discovery`
> **Feature Flag:** `subdomain-discovery`
> **Source:** [`src/subdomain_discovery.rs`](../src/subdomain_discovery.rs)
> **Lines:** ~100 | **Dependencies:** `serde`, `tokio`

Subdomain enumeration via the [Subfinder](https://github.com/projectdiscovery/subfinder) tool with noise filtering, deduplication, and a subdomain detection utility.

---

## Table of Contents

- [Overview](#overview)
- [Public API](#public-api)
  - [`discover_subdomains()`](#discover_subdomains)
  - [`is_subdomain()`](#is_subdomain)
- [Data Structures](#data-structures)
  - [`SubdomainDiscoveryResult`](#subdomaindiscoveryresult)
- [Skip Patterns (17)](#skip-patterns-17)
- [Multi-Part TLD Support (12)](#multi-part-tld-support-12)
- [Pipeline](#pipeline)
- [Usage Example](#usage-example)
- [Prerequisites](#prerequisites)
- [Testing](#testing)

---

## Overview

```
┌──────────────────────────────────────────┐
│       discover_subdomains(domain)        │
├──────────────┬───────────────────────────┤
│ subfinder    │ Execute subfinder -d -silent │
│ Parse        │ Split lines, lowercase, trim  │
│ Deduplicate  │ HashSet-based uniqueness      │
│ Filter       │ Skip 17 noise patterns        │
│ Result       │ subdomains + counts + timing  │
└──────────────┴───────────────────────────┘
```

---

## Public API

### `discover_subdomains()`

```rust
pub async fn discover_subdomains(
    domain: &str
) -> Result<SubdomainDiscoveryResult, Box<dyn std::error::Error + Send + Sync>>
```

### `is_subdomain()`

```rust
pub fn is_subdomain(domain: &str) -> bool
```

Detects whether a domain is a subdomain. Handles:
- IP addresses (returns `false`)
- Multi-part TLDs (e.g., `co.uk`, `com.tr`)
- Standard TLDs

---

## Data Structures

### `SubdomainDiscoveryResult`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `String` | Target domain |
| `subdomains` | `Vec<String>` | Clean, filtered subdomains |
| `total_found` | `usize` | Raw count before filtering |
| `filtered_count` | `usize` | Number of noise domains removed |
| `response_time_ms` | `u128` | Subfinder execution time |

---

## Skip Patterns (17)

Noise patterns automatically filtered:

| Pattern | Reason |
|---------|--------|
| `stun.l.google.com` | STUN server |
| `.cloudapp.azure.com` | Azure compute |
| `clients6.google.com` | Google internal |
| `.cdn.cloudflare.net` | CDN edge nodes |
| `rr1-5.sn-*` | Google video routing |
| `e-0014.e-msedge` | Microsoft Edge CDN |
| `s-part-` | CDN partitions |
| `.t-msedge.net` | Microsoft Edge CDN |
| `perimeterx.map` | Bot protection |
| `i.ytimg.com` | YouTube images |
| `analytics-alv.google.com` | Google Analytics |
| `signaler-pa.clients` | Google signaling |
| `westus-0.in.applicationinsights` | Azure monitoring |

---

## Multi-Part TLD Support (12)

`co.uk`, `com.tr`, `gov.tr`, `edu.tr`, `org.tr`, `net.tr`, `co.jp`, `co.kr`, `co.id`, `co.in`, `com.br`, `com.au`

---

## Usage Example

```rust
use web_analyzer::subdomain_discovery::{discover_subdomains, is_subdomain};

#[tokio::main]
async fn main() {
    let result = discover_subdomains("example.com").await.unwrap();

    println!("Found {} subdomains ({} filtered)", result.total_found, result.filtered_count);
    for sub in &result.subdomains {
        println!("  {} (subdomain: {})", sub, is_subdomain(sub));
    }
}
```

---

## Prerequisites

[Subfinder](https://github.com/projectdiscovery/subfinder) must be installed and available in `$PATH`.

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## Testing

```bash
cargo test --features subdomain-discovery -- --nocapture
```
