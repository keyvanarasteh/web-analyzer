# Subdomain Takeover

> **Module:** `subdomain_takeover`
> **Feature Flag:** `subdomain-takeover`
> **Source:** [`src/subdomain_takeover.rs`](../src/subdomain_takeover.rs)
> **Lines:** ~300 | **Dependencies:** `reqwest`, `serde`, `tokio`

Advanced subdomain takeover vulnerability scanner with a 36-service fingerprint database, comprehensive DNS checks (6 record types), 5 vulnerability detection cases, exploitation difficulty assessment, and mitigation suggestions.

---

## Table of Contents

- [Overview](#overview)
- [Public API](#public-api)
  - [`check_subdomain_takeover()`](#check_subdomain_takeover)
- [Data Structures](#data-structures)
  - [`TakeoverResult`](#takeoverresult)
  - [`TakeoverVulnerability`](#takeovervulnerability)
  - [`DnsCheckResult`](#dnscheckresult)
  - [`ScanStatistics`](#scanstatistics)
- [Vulnerable Service Database (36)](#vulnerable-service-database-36)
- [Vulnerability Detection Cases](#vulnerability-detection-cases)
  - [Case 1: CNAME Error Pattern](#case-1-cname-error-pattern)
  - [Case 2: Dangling CNAME](#case-2-dangling-cname)
  - [Case 3: Dangling NS](#case-3-dangling-ns)
  - [Case 4: Third-Party Service Error](#case-4-third-party-service-error)
  - [Case 5: Missing SPF](#case-5-missing-spf)
- [DNS Checks (6 Record Types)](#dns-checks-6-record-types)
- [Exploitation Difficulty](#exploitation-difficulty)
- [Mitigation Suggestions](#mitigation-suggestions)
- [Confidence Levels](#confidence-levels)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌──────────────────────────────────────────────────────────┐
│     check_subdomain_takeover(domain, subdomains)         │
├──────────────┬───────────────────────────────────────────┤
│ Per sub      │ 1. DNS check (A/AAAA/CNAME/MX/TXT/NS)   │
│              │ 2. HTTP fetch (HTTPS → HTTP fallback)    │
│              │ 3. Case 1: CNAME + error fingerprint     │
│              │ 4. Case 2: Dangling CNAME               │
│              │ 5. Case 3: Dangling NS                  │
│              │ 6. Case 4: 3rd-party service error      │
│              │ 7. Case 5: Missing SPF + MX             │
├──────────────┼───────────────────────────────────────────┤
│ Result       │ Sorted by confidence (High→Medium→Low)   │
│              │ + statistics + mitigation per vuln        │
└──────────────┴───────────────────────────────────────────┘
```

---

## Public API

### `check_subdomain_takeover()`

```rust
pub async fn check_subdomain_takeover(
    domain: &str,
    subdomains: &[String],
) -> Result<TakeoverResult, Box<dyn std::error::Error + Send + Sync>>
```

---

## Data Structures

### `TakeoverResult`

| Field        | Type                         | Description           |
| ------------ | ---------------------------- | --------------------- |
| `domain`     | `String`                     | Parent domain         |
| `statistics` | `ScanStatistics`             | Scan summary          |
| `vulnerable` | `Vec<TakeoverVulnerability>` | Found vulnerabilities |

### `ScanStatistics`

| Field                | Type    | Description               |
| -------------------- | ------- | ------------------------- |
| `subdomains_scanned` | `usize` | Total subdomains checked  |
| `vulnerable_count`   | `usize` | Total vulnerabilities     |
| `high_confidence`    | `usize` | High confidence count     |
| `medium_confidence`  | `usize` | Medium confidence count   |
| `low_confidence`     | `usize` | Low confidence count      |
| `scan_time_secs`     | `f64`   | Total scan duration       |
| `services_checked`   | `usize` | Services in database (36) |

### `TakeoverVulnerability`

| Field                     | Type             | Description                |
| ------------------------- | ---------------- | -------------------------- |
| `subdomain`               | `String`         | Affected subdomain         |
| `service`                 | `String`         | Identified service         |
| `vulnerability_type`      | `String`         | Detection case type        |
| `cname`                   | `Option<String>` | CNAME record value         |
| `confidence`              | `String`         | High / Medium / Low        |
| `description`             | `String`         | Human-readable description |
| `exploitation_difficulty` | `String`         | Easy / Medium / Hard       |
| `mitigation`              | `String`         | Recommended fix            |
| `dns_info`                | `DnsCheckResult` | Full DNS records           |
| `http_status`             | `Option<u16>`    | HTTP response status       |

### `DnsCheckResult`

| Field           | Type          | Description      |
| --------------- | ------------- | ---------------- |
| `a_records`     | `Vec<String>` | IPv4 addresses   |
| `aaaa_records`  | `Vec<String>` | IPv6 addresses   |
| `cname_records` | `Vec<String>` | CNAME targets    |
| `mx_records`    | `Vec<String>` | Mail exchanges   |
| `txt_records`   | `Vec<String>` | TXT records      |
| `ns_records`    | `Vec<String>` | Nameservers      |
| `has_valid_dns` | `bool`        | Any record found |

---

## Vulnerable Service Database (36)

| #   | Service               | CNAME Pattern           | Error Fingerprint                                  |
| --- | --------------------- | ----------------------- | -------------------------------------------------- |
| 1   | AWS S3 Bucket         | `s3.amazonaws.com`      | `NoSuchBucket`                                     |
| 2   | AWS CloudFront        | `cloudfront.net`        | `The request could not be satisfied`               |
| 3   | GitHub Pages          | `github.io`             | `There isn't a GitHub Pages site here`             |
| 4   | Heroku                | `herokuapp.com`         | `No such app`                                      |
| 5   | Vercel                | `vercel.app`            | `404: Not Found`                                   |
| 6   | Netlify               | `netlify.app`           | `Not found`                                        |
| 7   | Azure App Service     | `azurewebsites.net`     | `Microsoft Azure App Service`                      |
| 8   | Azure TrafficManager  | `trafficmanager.net`    | `Page not found`                                   |
| 9   | Zendesk               | `zendesk.com`           | `Help Center Closed`                               |
| 10  | Shopify               | `myshopify.com`         | `Sorry, this shop is currently unavailable`        |
| 11  | Fastly                | `fastly.net`            | `Fastly error: unknown domain`                     |
| 12  | Pantheon              | `pantheonsite.io`       | `The gods are wise`                                |
| 13  | Tumblr                | `tumblr.com`            | `There's nothing here`                             |
| 14  | WordPress             | `wordpress.com`         | `Do you want to register`                          |
| 15  | Acquia                | `acquia-sites.com`      | `No site found`                                    |
| 16  | Ghost                 | `ghost.io`              | `The thing you were looking for is no longer here` |
| 17  | Cargo                 | `cargocollective.com`   | `404 Not Found`                                    |
| 18  | Webflow               | `webflow.io`            | `The page you are looking for doesn't exist`       |
| 19  | Surge.sh              | `surge.sh`              | `404 Not Found`                                    |
| 20  | Squarespace           | `squarespace.com`       | `Website Expired`                                  |
| 21  | Fly.io                | `fly.dev`               | `404 Not Found`                                    |
| 22  | Brightcove            | `bcvp0rtal.com`         | `Brightcove Error`                                 |
| 23  | Unbounce              | `unbounce.com`          | `The requested URL was not found`                  |
| 24  | Strikingly            | `strikinglydns.com`     | `404 Not Found`                                    |
| 25  | UptimeRobot           | `stats.uptimerobot.com` | `404 Not Found`                                    |
| 26  | UserVoice             | `uservoice.com`         | `This UserVoice is currently being set up`         |
| 27  | Pingdom               | `stats.pingdom.com`     | `404 Not Found`                                    |
| 28  | Desk                  | `desk.com`              | `Please try again`                                 |
| 29  | Tilda                 | `tilda.ws`              | `404 Not Found`                                    |
| 30  | Helpjuice             | `helpjuice.com`         | `404 Not Found`                                    |
| 31  | HelpScout             | `helpscoutdocs.com`     | `No settings were found`                           |
| 32  | Campaign Monitor      | `createsend.com`        | `404 Not Found`                                    |
| 33  | Digital Ocean         | `digitalocean.app`      | `404 Not Found`                                    |
| 34  | AWS Elastic Beanstalk | `elasticbeanstalk.com`  | `404 Not Found`                                    |
| 35  | Readthedocs           | `readthedocs.io`        | `Not Found`                                        |
| 36  | Firebase              | `firebaseapp.com`       | `404 Not Found`                                    |

---

## Vulnerability Detection Cases

### Case 1: CNAME Error Pattern

**Confidence:** High
CNAME points to a known service AND the HTTP response body contains the service's error fingerprint.

### Case 2: Dangling CNAME

**Confidence:** High (known service) / Medium (unknown)
CNAME record exists but the target doesn't resolve to an IP address.

### Case 3: Dangling NS

**Confidence:** Medium
NS record points to a nameserver that doesn't resolve.

### Case 4: Third-Party Service Error

**Confidence:** Medium (known provider) / Low (unknown)
Valid DNS but HTTP returns 404/500/502/503 from a third-party provider.

### Case 5: Missing SPF

**Confidence:** Low
MX records present but no SPF record — email spoofing risk.

---

## Exploitation Difficulty

| Case              | Service Category                          | Difficulty |
| ----------------- | ----------------------------------------- | ---------- |
| CNAME Error       | GitHub, Heroku, Vercel, Netlify, Surge.sh | Easy       |
| CNAME Error       | AWS S3, Firebase, Ghost, WordPress        | Medium     |
| CNAME Error       | Other services                            | Hard       |
| Dangling CNAME    | Known service                             | Medium     |
| Dangling CNAME    | Unknown                                   | Hard       |
| Dangling NS       | Any                                       | Medium     |
| Third-Party Error | Any                                       | Hard       |

---

## Usage Example

```rust
use web_analyzer::subdomain_takeover::check_subdomain_takeover;

#[tokio::main]
async fn main() {
    let subs = vec!["blog.example.com".into(), "shop.example.com".into()];
    let result = check_subdomain_takeover("example.com", &subs).await.unwrap();

    println!("Scanned: {}", result.statistics.subdomains_scanned);
    println!("Vulnerable: {} (H:{} M:{} L:{})",
        result.statistics.vulnerable_count,
        result.statistics.high_confidence,
        result.statistics.medium_confidence,
        result.statistics.low_confidence);

    for vuln in &result.vulnerable {
        println!("[{}] {} — {} ({})", vuln.confidence, vuln.subdomain,
            vuln.vulnerability_type, vuln.exploitation_difficulty);
        println!("  Fix: {}", vuln.mitigation);
    }
}
```

---

## Testing

```bash
cargo test --features subdomain-takeover -- --nocapture
```
