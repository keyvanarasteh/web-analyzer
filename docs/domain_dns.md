# Domain DNS

> **Module:** `domain_dns`
> **Feature Flag:** `domain-dns`
> **Source:** [`src/domain_dns.rs`](../src/domain_dns.rs)
> **Lines:** ~80 | **Dependencies:** `serde`, `chrono`, `tokio`

Ultra-fast DNS record analyzer that queries 7 record types concurrently via the `dig` command and measures response latency.

---

## Table of Contents

- [Overview](#overview)
- [Public API](#public-api)
  - [`get_dns_records()`](#get_dns_records)
- [Data Structures](#data-structures)
  - [`DnsRecords`](#dnsrecords)
  - [`DomainDnsResult`](#domaindnsresult)
- [Record Types](#record-types)
- [Resolution Mechanism](#resolution-mechanism)
- [Internal Functions](#internal-functions)
  - [`resolve_record()`](#resolve_record)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌─────────────────────────────────────────────┐
│           get_dns_records(domain)           │
├─────────────────────────────────────────────┤
│  tokio::join! (concurrent resolution)       │
│  ├─ dig +short A {domain}                   │
│  ├─ dig +short AAAA {domain}                │
│  ├─ dig +short MX {domain}                  │
│  ├─ dig +short NS {domain}                  │
│  ├─ dig +short SOA {domain}                 │
│  ├─ dig +short TXT {domain}                 │
│  └─ dig +short CNAME {domain}               │
│                                             │
│  + Response time measurement (ms)           │
│  + RFC 3339 timestamp                       │
└─────────────────────────────────────────────┘
```

All 7 record types are resolved in parallel using `tokio::join!`.

---

## Public API

### `get_dns_records()`

```rust
pub async fn get_dns_records(
    domain: &str
) -> Result<DomainDnsResult, Box<dyn std::error::Error + Send + Sync>>
```

| Param | Type | Description |
|-------|------|-------------|
| `domain` | `&str` | Target domain to query DNS records for |

**Returns:** `Result<DomainDnsResult, Error>` with all 7 record types and timing.

---

## Data Structures

### `DnsRecords`

```rust
pub struct DnsRecords {
    pub a: Vec<String>,      // IPv4 addresses
    pub aaaa: Vec<String>,   // IPv6 addresses
    pub mx: Vec<String>,     // Mail exchange servers
    pub ns: Vec<String>,     // Name servers
    pub soa: Vec<String>,    // Start of authority
    pub txt: Vec<String>,    // Text records (SPF, DKIM, DMARC, etc.)
    pub cname: Vec<String>,  // Canonical name aliases
}
```

### `DomainDnsResult`

```rust
pub struct DomainDnsResult {
    pub timestamp: String,      // RFC 3339 format: "2025-01-15T12:00:00+00:00"
    pub domain: String,
    pub records: DnsRecords,
    pub response_time_ms: u128, // Total resolution time in milliseconds
}
```

---

## Record Types

| Type | Field | Description | Common Use |
|------|-------|-------------|------------|
| **A** | `records.a` | IPv4 address mappings | Identify hosting provider |
| **AAAA** | `records.aaaa` | IPv6 address mappings | IPv6 support check |
| **MX** | `records.mx` | Mail servers with priority | Email infrastructure |
| **NS** | `records.ns` | Authoritative name servers | DNS provider identification |
| **SOA** | `records.soa` | Zone authority + serial number | Zone metadata |
| **TXT** | `records.txt` | Arbitrary text records | SPF, DKIM, DMARC, domain verification |
| **CNAME** | `records.cname` | Canonical name aliases | CDN/hosting detection |

---

## Resolution Mechanism

Each record type is resolved via `tokio::process::Command` calling `dig`:

```bash
dig +short {RECORD_TYPE} {DOMAIN}
```

**Output parsing:**
1. Split stdout by newlines
2. Trim whitespace
3. Filter empty lines and comment lines (starting with `;`)
4. Collect remaining lines as record values
5. Return empty `Vec` on failure

**Concurrency:** All 7 `dig` commands execute in parallel via `tokio::join!`, reducing total latency to the time of the **slowest** single query.

**Timing:** `std::time::Instant` measures wall-clock time from start to completion of all 7 queries (includes process spawn overhead).

---

## Internal Functions

### `resolve_record()`

```rust
async fn resolve_record(domain: &str, record_type: &str) -> Vec<String>
```

Spawns a `dig +short {record_type} {domain}` process, parses stdout, and returns record values. Returns empty `Vec` on any error (process failure, UTF-8 decode, etc.).

---

## Usage Example

```rust
use web_analyzer::domain_dns::get_dns_records;

#[tokio::main]
async fn main() {
    let result = get_dns_records("example.com").await.unwrap();

    println!("DNS for {} ({}ms)", result.domain, result.response_time_ms);

    println!("A: {:?}", result.records.a);
    println!("AAAA: {:?}", result.records.aaaa);
    println!("MX: {:?}", result.records.mx);
    println!("NS: {:?}", result.records.ns);
    println!("SOA: {:?}", result.records.soa);
    println!("TXT: {:?}", result.records.txt);
    println!("CNAME: {:?}", result.records.cname);
}
```

---

## Testing

```bash
cargo test --features domain-dns -- --nocapture
```
