# Domain Info

> **Module:** `domain_info`
> **Feature Flag:** `domain-info`
> **Source:** [`src/domain_info.rs`](../src/domain_info.rs)
> **Lines:** ~350 | **Dependencies:** `reqwest`, `regex`, `serde`, `tokio`, `urlencoding`

Comprehensive domain intelligence gathering — resolves IPs, performs WHOIS lookups via raw TCP sockets, analyzes SSL certificates, queries DNS records, scans common ports, checks HTTP status, and calculates a security score.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Public API](#public-api)
  - [`get_domain_info()`](#get_domain_info)
- [Data Structures](#data-structures)
  - [`DomainInfoResult`](#domaininforesult)
  - [`WhoisInfo`](#whoisinfo)
  - [`SslInfo`](#sslinfo)
  - [`DnsInfo`](#dnsinfo)
  - [`SecurityInfo`](#securityinfo)
- [IP Resolution](#ip-resolution)
  - [IPv4 and IPv6](#ipv4-and-ipv6)
  - [Reverse DNS](#reverse-dns)
- [WHOIS via TCP Socket](#whois-via-tcp-socket)
  - [WHOIS Server Database (25 TLDs)](#whois-server-database-25-tlds)
  - [TCP Query Protocol](#tcp-query-protocol)
  - [Referral Following](#referral-following)
  - [Field Parsing (7 fields)](#field-parsing-7-fields)
  - [Privacy Detection](#privacy-detection)
- [SSL Certificate Analysis](#ssl-certificate-analysis)
  - [Certificate Fields](#certificate-fields)
  - [Subject Alternative Names (SANs)](#subject-alternative-names-sans)
- [DNS Records](#dns-records)
  - [Record Types](#record-types)
  - [SPF and DMARC Detection](#spf-and-dmarc-detection)
- [Port Scanning](#port-scanning)
  - [Ports Scanned (9)](#ports-scanned-9)
  - [Parallel TCP Connect](#parallel-tcp-connect)
- [HTTP Status Check](#http-status-check)
- [Security Analysis](#security-analysis)
  - [Security Headers (5)](#security-headers-5)
  - [HTTPS Redirect Detection](#https-redirect-detection)
- [Security Score (0-100)](#security-score-0-100)
  - [Scoring Breakdown](#scoring-breakdown)
- [Internal Functions](#internal-functions)
- [Constants Reference](#constants-reference)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌───────────────────────────────────────────────────────────────────┐
│                     get_domain_info(domain)                       │
├───────────────┬───────────────────────────────────────────────────┤
│ IP Resolution │ Resolve IPv4/IPv6 + Reverse DNS                  │
├───────────────┼───────────────────────────────────────────────────┤
│ Parallel      │ ┌─ WHOIS via TCP socket (25-TLD DB)              │
│ Execution     │ ├─ SSL cert via openssl s_client                 │
│ (tokio::join!) │ ├─ DNS records via dig (NS/MX/TXT/SPF/DMARC)   │
│               │ ├─ Port scan (9 ports, parallel TCP connect)     │
│               │ ├─ HTTP status (HTTPS→HTTP fallback)             │
│               │ └─ Security headers + HTTPS redirect check       │
├───────────────┼───────────────────────────────────────────────────┤
│ Scoring       │ Calculate security score (0-100)                 │
└───────────────┴───────────────────────────────────────────────────┘
```

All 6 analysis tasks run concurrently via `tokio::join!`.

---

## Public API

### `get_domain_info()`

```rust
pub async fn get_domain_info(
    domain: &str
) -> Result<DomainInfoResult, Box<dyn std::error::Error + Send + Sync>>
```

| Param | Type | Description |
|-------|------|-------------|
| `domain` | `&str` | Target domain. Accepts `example.com`, `https://www.example.com`, etc. |

---

## Data Structures

### `DomainInfoResult`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `String` | Cleaned domain name |
| `ipv4` | `Option<String>` | Primary IPv4 address |
| `ipv6` | `Vec<String>` | All IPv6 addresses |
| `all_ipv4` | `Vec<String>` | All resolved IPv4 addresses |
| `reverse_dns` | `Option<String>` | Reverse DNS hostname |
| `whois` | `WhoisInfo` | WHOIS registration data |
| `ssl` | `SslInfo` | SSL certificate details |
| `dns` | `DnsInfo` | DNS record data |
| `open_ports` | `Vec<String>` | Open ports (e.g., `"22/SSH"`) |
| `http_status` | `Option<String>` | HTTP status (e.g., `"200 - HTTPS"`) |
| `web_server` | `Option<String>` | Server header value |
| `response_time_ms` | `Option<f64>` | HTTP response time |
| `security` | `SecurityInfo` | Security analysis results |
| `security_score` | `u32` | Overall score (0-100) |

### `WhoisInfo`

| Field | Type | Parsed From |
|-------|------|-------------|
| `registrar` | `String` | `Registrar:`, `Registrar Name:`, `Registrar Organization:` |
| `creation_date` | `String` | `Creation Date:`, `Created:`, `Registration Time:` |
| `expiry_date` | `String` | `Registry Expiry Date:`, `Expiry Date:`, `expires:` |
| `last_updated` | `String` | `Updated Date:`, `Last Updated:`, `Modified Date:` |
| `domain_status` | `Vec<String>` | `Status:` or `Domain Status:` (up to 3) |
| `registrant` | `String` | `Registrant Name:`, `Registrant Organization:` |
| `privacy_protection` | `String` | Detects 6 privacy keywords → `"Active"` / `"Inactive"` |
| `name_servers` | `Vec<String>` | `Name Server:` (up to 4) |

### `SslInfo`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `String` | `"Valid"`, `"HTTPS not available"`, `"Error"` |
| `issued_to` | `Option<String>` | Subject CN |
| `issuer` | `Option<String>` | Issuer CN |
| `protocol_version` | `Option<String>` | TLS version |
| `expiry_date` | `Option<String>` | Certificate expiry |
| `days_until_expiry` | `Option<i64>` | Days remaining |
| `alternative_names` | `Vec<String>` | SANs (up to 5 DNS names) |

### `DnsInfo`

| Field | Type | Description |
|-------|------|-------------|
| `nameservers` | `Vec<String>` | NS records |
| `mx_records` | `Vec<String>` | MX records |
| `txt_records` | `Vec<String>` | TXT records |
| `spf` | `Option<String>` | SPF record (`v=spf1...`) |
| `dmarc` | `Option<String>` | DMARC record (`v=DMARC1...`) |

### `SecurityInfo`

| Field | Type | Description |
|-------|------|-------------|
| `https_available` | `bool` | HTTPS responds successfully |
| `https_redirect` | `bool` | HTTP redirects to HTTPS |
| `security_headers` | `HashMap<String, String>` | Present security headers |
| `headers_count` | `usize` | Number of security headers found |

---

## WHOIS via TCP Socket

### WHOIS Server Database (25 TLDs)

Covers: `com`, `net`, `org`, `info`, `biz`, `us`, `uk`, `de`, `fr`, `it`, `nl`, `eu`, `ru`, `cn`, `jp`, `br`, `au`, `ca`, `in`, `tr`, `co`, `io`, `me`, `tv`, `cc`. Falls back to `whois.iana.org`.

### TCP Query Protocol

1. Connect to WHOIS server on port 43
2. Send `{domain}\r\n`
3. Read all response data
4. 10-second timeout on connect and read

### Referral Following

If response contains `Registrar WHOIS Server:`, follows the referral to the specific registrar's WHOIS server for more detailed information.

### Privacy Detection

Scans WHOIS output for keywords: `REDACTED`, `Privacy`, `GDPR`, `Protected`, `Proxy`, `PRIVATE`.

---

## Port Scanning

### Ports Scanned (9)

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 25 | SMTP |
| 80 | HTTP |
| 443 | HTTPS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 8080 | HTTP-Alt |
| 8443 | HTTPS-Alt |

### Parallel TCP Connect

Each port is scanned via `tokio::spawn` with a 1-second timeout. All 9 ports are checked concurrently.

---

## Security Score (0-100)

### Scoring Breakdown

| Component | Points | Condition |
|-----------|--------|-----------|
| HTTPS available | +30 | Server responds on HTTPS |
| HTTPS redirect | +10 | HTTP → HTTPS redirect |
| SSL valid | +20 | Certificate status is "Valid" |
| Security headers | +4 each (max 20) | 5 headers checked |
| SPF record | +10 | TXT record with `v=spf1` |
| DMARC record | +10 | `_dmarc.{domain}` TXT with `v=DMARC1` |

---

## Internal Functions

| Function | Description |
|----------|-------------|
| `clean_domain()` | Strips protocol, `www.`, path, port |
| `reverse_dns_lookup()` | `dig +short -x {ip}` |
| `get_whois_server()` | TLD → WHOIS server mapping |
| `query_whois_tcp()` | Raw TCP socket query to WHOIS server |
| `query_whois()` | Full WHOIS with referral and parsing |
| `check_ssl()` | openssl s_client + x509 certificate analysis |
| `dig_query()` | DNS record query via dig |
| `get_dns_records()` | NS + MX + TXT + SPF + DMARC |
| `scan_ports()` | Parallel TCP connect for 9 ports |
| `check_http_status()` | HTTPS/HTTP fallback status check |
| `check_security()` | Security headers + redirect detection |
| `calculate_security_score()` | 0-100 score from SSL, DNS, security |

---

## Constants Reference

| Constant | Count | Description |
|----------|-------|-------------|
| `WHOIS_SERVERS` | 25 | TLD-to-WHOIS-server mappings |
| `COMMON_PORTS` | 9 | Ports to scan |
| `SECURITY_HEADERS` | 5 | Headers to check |
| `PRIVACY_KEYWORDS` | 6 | WHOIS privacy indicators |
| HTTP timeout | 5s | reqwest client timeout |
| WHOIS timeout | 10s | TCP socket timeout |
| Port scan timeout | 1s | Per-port TCP timeout |

---

## Usage Example

```rust
use web_analyzer::domain_info::get_domain_info;

#[tokio::main]
async fn main() {
    let info = get_domain_info("example.com").await.unwrap();

    println!("IP: {:?}", info.ipv4);
    println!("WHOIS Registrar: {}", info.whois.registrar);
    println!("SSL: {}", info.ssl.status);
    println!("Open Ports: {:?}", info.open_ports);
    println!("Security Score: {}/100", info.security_score);
}
```

---

## Testing

```bash
cargo test --features domain-info -- --nocapture
```
