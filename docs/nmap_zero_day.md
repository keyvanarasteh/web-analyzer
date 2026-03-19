# Nmap Zero-Day Scanner

> **Module:** `nmap_zero_day`
> **Feature Flag:** `nmap-zero-day`
> **Source:** [`src/nmap_zero_day.rs`](../src/nmap_zero_day.rs)
> **Lines:** ~250 | **Dependencies:** `reqwest`, `serde`, `serde_json`, `tokio`, `urlencoding`

Advanced network scanner that combines nmap service detection with NVD CVE vulnerability lookup and Exploit-DB queries. Discovers open ports, identifies running services, and maps them to known vulnerabilities with CVSS severity scoring.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Public API](#public-api)
  - [`run_nmap_scan()`](#run_nmap_scan)
- [Data Structures](#data-structures)
  - [`NmapScanResult`](#nmapscanresult)
  - [`PortInfo`](#portinfo)
  - [`VulnerabilityInfo`](#vulnerabilityinfo)
  - [`SeverityInfo`](#severityinfo)
  - [`DnsInfo`](#dnsinfo)
- [Scan Pipeline](#scan-pipeline)
  - [Phase 1: DNS Resolution](#phase-1-dns-resolution)
  - [Phase 2: Nmap Port Scan](#phase-2-nmap-port-scan)
  - [Phase 3: Vulnerability Lookup](#phase-3-vulnerability-lookup)
- [Nmap Integration](#nmap-integration)
  - [Scan Arguments](#scan-arguments)
  - [Grepable Output Parsing](#grepable-output-parsing)
- [Vulnerability Sources](#vulnerability-sources)
  - [NVD CVE API](#nvd-cve-api)
  - [Exploit-DB Query](#exploit-db-query)
- [CVSS Severity Calculation](#cvss-severity-calculation)
  - [Severity Levels](#severity-levels)
- [Internal Functions](#internal-functions)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌──────────────────────────────────────────────────────────┐
│                    run_nmap_scan(domain)                  │
├──────────────┬───────────────────────────────────────────┤
│ Phase 1      │ DNS Resolution (IPv4 + IPv6)              │
│ Phase 2      │ Nmap -sV -Pn -A -T5 --top-ports 1000     │
│              │  → Parse grepable output                  │
│              │  → Extract port/service/version/product   │
│ Phase 3      │ For each open port:                       │
│              │  ├─ NVD CVE keyword search                │
│              │  │  → Parse CVSS v3.1 severity            │
│              │  └─ Exploit-DB search                     │
│ Result       │ NmapScanResult with ports + vulns         │
└──────────────┴───────────────────────────────────────────┘
```

---

## Public API

### `run_nmap_scan()`

```rust
pub async fn run_nmap_scan(
    domain: &str
) -> Result<NmapScanResult, Box<dyn std::error::Error + Send + Sync>>
```

| Param | Type | Description |
|-------|------|-------------|
| `domain` | `&str` | Target domain. Must be a bare domain (e.g., `example.com`). |

**Prerequisites:** The `nmap` binary must be installed and available in `$PATH`.

---

## Data Structures

### `NmapScanResult`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `String` | Scanned domain |
| `ip` | `String` | Resolved IPv4 (or domain fallback) |
| `scan_time_secs` | `f64` | Total scan duration in seconds |
| `dns_info` | `DnsInfo` | IPv4 and IPv6 addresses |
| `open_ports` | `Vec<PortInfo>` | Discovered open ports with service info |
| `vulnerabilities` | `Vec<VulnerabilityInfo>` | Vulnerability findings |

### `PortInfo`

| Field | Type | Description |
|-------|------|-------------|
| `port` | `u16` | Port number |
| `state` | `String` | Port state (`"open"`) |
| `service` | `String` | Service name (e.g., `"ssh"`, `"http"`) |
| `version` | `String` | Version string (e.g., `"OpenSSH 8.9"`) |
| `product` | `Option<String>` | Product name |
| `cpe` | `Vec<String>` | CPE identifiers (when available) |

### `VulnerabilityInfo`

| Field | Type | Description |
|-------|------|-------------|
| `source` | `String` | `"NVD"` or `"Exploit-DB"` |
| `vuln_type` | `String` | `"CVE"` or `"Exploit"` |
| `id` | `String` | CVE ID (e.g., `"CVE-2023-12345"`) or `"N/A"` |
| `description` | `String` | Vulnerability description |
| `severity` | `SeverityInfo` | CVSS severity assessment |

### `SeverityInfo`

| Field | Type | Description |
|-------|------|-------------|
| `level` | `String` | `"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"Unknown"` |
| `score` | `f64` | CVSS v3.1 base score (0.0-10.0) |

### `DnsInfo`

| Field | Type | Description |
|-------|------|-------------|
| `ipv4` | `Option<String>` | Resolved IPv4 address |
| `ipv6` | `Option<String>` | Resolved IPv6 address |

---

## Nmap Integration

### Scan Arguments

```bash
nmap -sV -Pn -A -T5 --top-ports 1000 -oG - {IP}
```

| Flag | Purpose |
|------|---------|
| `-sV` | Service version detection |
| `-Pn` | Skip host discovery (treat as up) |
| `-A` | Aggressive scan (OS detection, scripts, traceroute) |
| `-T5` | Insane timing template (fastest) |
| `--top-ports 1000` | Scan top 1000 most common ports |
| `-oG -` | Grepable output to stdout |

### Grepable Output Parsing

Parses lines containing `Ports:` with format:

```
Host: x.x.x.x () Ports: 22/open/tcp//ssh//OpenSSH 8.9/, 80/open/tcp//http//nginx/
```

**Extracted fields:** port number, state, service name, product, version.

---

## Vulnerability Sources

### NVD CVE API

| Field | Value |
|-------|-------|
| **Endpoint** | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| **Query** | `keywordSearch={service} {product} {version}` |
| **Max results** | 10 per service |
| **Timeout** | 20 seconds |

Extracts CVE ID, description, and CVSS v3.1 base score from each vulnerability.

### Exploit-DB Query

| Field | Value |
|-------|-------|
| **Endpoint** | `https://www.exploit-db.com/search` |
| **Query** | `q={service} {product} {version}` |
| **Detection** | Records HTTP 200 as potential exploit reference |

---

## CVSS Severity Calculation

### Severity Levels

Parses `metrics.cvssMetricV31[0].cvssData.baseScore` from NVD response:

| Base Score | Level |
|-----------|-------|
| ≥ 9.0 | **Critical** |
| ≥ 7.0 | **High** |
| ≥ 4.0 | **Medium** |
| > 0.0 | **Low** |
| 0.0 | **Unknown** |

---

## Internal Functions

| Function | Description |
|----------|-------------|
| `fetch_vulnerabilities()` | Iterates ports, queries NVD + Exploit-DB for each |
| `query_nvd()` | HTTP GET to NVD API, parses JSON cve results |
| `query_exploit_db()` | HTTP GET to Exploit-DB search |
| `calculate_severity()` | Extracts CVSS v3.1 score → severity level |

---

## Usage Example

```rust
use web_analyzer::nmap_zero_day::run_nmap_scan;

#[tokio::main]
async fn main() {
    let result = run_nmap_scan("example.com").await.unwrap();

    println!("Scan completed in {:.1}s", result.scan_time_secs);
    println!("IP: {}", result.ip);

    for port in &result.open_ports {
        println!("  {}/tcp {} {}", port.port, port.service, port.version);
    }

    for vuln in &result.vulnerabilities {
        println!("[{}] {} — {} ({})",
            vuln.severity.level, vuln.id, vuln.description, vuln.source);
    }
}
```

---

## Testing

```bash
cargo test --features nmap-zero-day -- --nocapture
```
