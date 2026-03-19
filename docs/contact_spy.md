# Contact Spy

> **Module:** `contact_spy`
> **Feature Flag:** `contact-spy`
> **Source:** [`src/contact_spy.rs`](../src/contact_spy.rs)
> **Lines:** ~250 | **Dependencies:** `reqwest`, `scraper`, `regex`, `serde`

Multi-page web crawler that discovers contact information — emails, phone numbers, and social media profiles — across an entire website with advanced validation and false-positive filtering.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Public API](#public-api)
  - [`crawl_contacts()`](#crawl_contacts)
- [Data Structures](#data-structures)
  - [`SocialProfile`](#socialprofile)
  - [`ContactSpyResult`](#contactspyresult)
- [BFS Web Crawling](#bfs-web-crawling)
  - [Page Discovery](#page-discovery)
  - [URL Validation](#url-validation)
  - [Content Extraction](#content-extraction)
- [Email Extraction](#email-extraction)
  - [Regex Pattern](#regex-pattern)
  - [False Positive Filters (9 patterns)](#false-positive-filters-9-patterns)
  - [Validation Rules](#validation-rules)
- [Phone Extraction](#phone-extraction)
  - [Regex Pattern](#regex-pattern-1)
  - [Validation Rules](#validation-rules-1)
  - [False Positive Detection](#false-positive-detection)
- [Social Media Extraction](#social-media-extraction)
  - [Supported Platforms (7)](#supported-platforms-7)
  - [Username Validation](#username-validation)
  - [Invalid Username Blocklist](#invalid-username-blocklist)
  - [Platform-Specific Rules](#platform-specific-rules)
  - [Deduplication](#deduplication)
- [Internal Functions](#internal-functions)
  - [`build_social_patterns()`](#build_social_patterns)
  - [`is_valid_phone()`](#is_valid_phone)
  - [`is_valid_social_username()`](#is_valid_social_username)
  - [`is_valid_crawl_url()`](#is_valid_crawl_url)
  - [`resolve_url()`](#resolve_url)
- [Constants Reference](#constants-reference)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                  crawl_contacts(domain, max_pages)              │
├─────────────────┬───────────────────────────────────────────────┤
│ BFS Crawl Loop  │  Pop URL from queue                          │
│ (up to N pages) │  Fetch page → Parse HTML                     │
│                 │  ├─ Extract body text (no script/style)       │
│                 │  ├─ Collect <a href> values                   │
│                 │  ├─ Extract emails (9 false-positive filters) │
│                 │  ├─ Extract phones (3 FP regex patterns)      │
│                 │  ├─ Extract social media (7 platforms)        │
│                 │  └─ Discover new links for queue              │
├─────────────────┼───────────────────────────────────────────────┤
│ Post-process    │  Group social by platform                     │
│                 │  Compute summary statistics                   │
└─────────────────┴───────────────────────────────────────────────┘
```

---

## Public API

### `crawl_contacts()`

```rust
pub async fn crawl_contacts(
    domain: &str,
    max_pages: usize
) -> Result<ContactSpyResult, Box<dyn std::error::Error + Send + Sync>>
```

| Param | Type | Description |
|-------|------|-------------|
| `domain` | `&str` | Target domain. Accepts `example.com` or `https://example.com`. |
| `max_pages` | `usize` | Maximum number of pages to crawl. |

---

## Data Structures

### `SocialProfile`

```rust
pub struct SocialProfile {
    pub platform: String,       // "Facebook", "Twitter", "Instagram", etc.
    pub username: String,       // Extracted username
    pub url: String,            // Full profile URL
    pub found_on: Option<String>, // Page where profile was found
}
```

### `ContactSpyResult`

```rust
pub struct ContactSpyResult {
    pub domain: String,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub social_media: Vec<SocialProfile>,
    pub social_media_by_platform: HashMap<String, Vec<SocialProfile>>,
    pub pages_scanned: usize,
    pub total_emails: usize,
    pub total_phones: usize,
    pub total_social_media: usize,
}
```

---

## BFS Web Crawling

### Page Discovery

The crawler uses breadth-first search (BFS):
1. Start with `https://{domain}`
2. Fetch each page, extract all `<a href>` links
3. Validate and add new same-domain links to the queue
4. Stop when `max_pages` visited or queue empty

### URL Validation

URLs must pass all checks to be crawled:

| Check | Rule |
|-------|------|
| Domain match | URL must contain the base domain |
| Extension filter | Skip 14 static asset extensions (`.pdf`, `.jpg`, `.css`, `.js`, etc.) |
| Directory filter | Skip 8 asset directories (`/assets/`, `/images/`, `/css/`, etc.) |
| Protocol filter | Skip `javascript:`, `mailto:`, `tel:`, `#` anchors |

### Content Extraction

For each page:
1. Parse HTML with `scraper`
2. Extract `<body>` text content (script/style elements excluded via text node extraction)
3. Collect all `<a href>` attribute values separately
4. Combine text + hrefs into `full_text` for extraction

---

## Email Extraction

### Regex Pattern
```regex
[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
```

### False Positive Filters (9 patterns)

| Pattern | Reason |
|---------|--------|
| `example.` | Placeholder domain |
| `test@` | Test email |
| `noreply@` | System email |
| `no-reply@` | System email |
| `admin@example` | Documentation example |
| `user@example` | Documentation example |
| `email@example` | Documentation example |
| `name@example` | Documentation example |
| `.jpg@`, `.png@` | Filename artifacts |

### Validation Rules

- Length > 5 characters
- Exactly one `@` symbol
- Case-insensitive (lowercased)
- Deduplicated across all pages

---

## Phone Extraction

### Regex Pattern
```regex
[\+]?[\d\s\-\(\)\.]{8,20}
```

### Validation Rules

| Rule | Criteria |
|------|----------|
| Digit count | 7–15 digits (after stripping non-digits) |
| All digits | Only digits allowed (after stripping) |
| Format | Must start with `+` or have ≥10 digits |

### False Positive Detection

3 regex patterns reject common false positives:

| Pattern | Rejects |
|---------|---------|
| `^(19\|20)\d{6,8}$` | Date patterns (1900-2099) |
| `^(\d)\1{6,}$` | Same digit repeated 7+ times (e.g., `1111111`) |
| `^(123\|456\|789\|987\|654\|321){2,}$` | Sequential numbers |

---

## Social Media Extraction

### Supported Platforms (7)

| Platform | Regex Pattern | Excludes |
|----------|--------------|----------|
| **Facebook** | `facebook.com/(?!sharer\|dialog\|plugins)(\w+)` | Share buttons, plugins |
| **Twitter** | `(?:twitter.com\|x.com)/(?!share\|intent\|home)(\w+)` | Share intents |
| **Instagram** | `instagram.com/(?!p/\|explore\|accounts)(\w+)` | Posts, explore |
| **LinkedIn** | `linkedin.com/(?:in\|company)/(\w+)` | Personal + company |
| **YouTube** | `youtube.com/(?:channel/\|user/\|c/\|@)(\w+)` | All channel formats |
| **GitHub** | `github.com/(\w+)` | Any user/org |
| **TikTok** | `tiktok.com/@(\w+)` | User profiles |

### Username Validation

Two-stage validation:

**1. Global blocklist (38 entries):**
```
share, sharer, intent, oauth, login, register, signup,
api, www, mobile, m, help, support, about, privacy,
terms, contact, home, index, main, page, site,
web, app, download, install, get, go, redirect,
link, url, http, https, com, org, net,
plugins, dialog, p, explore, accounts
```

**2. Platform-specific rules:**

| Platform | Max Length | Additional |
|----------|-----------|------------|
| Twitter | 15 | Cannot start with `_` |
| Instagram | 30 | — |
| LinkedIn | 100 | — |
| GitHub | 39 | Cannot start with `-` |
| YouTube | 100 | — |
| Facebook | 50 | — |
| TikTok | 24 | — |

### Deduplication

Profiles are deduplicated by `{Platform}:{username_lowercase}` key across all crawled pages.

---

## Internal Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `build_social_patterns()` | `fn() -> Vec<(String, Regex)>` | Builds 7 platform regex patterns |
| `is_valid_phone()` | `fn(digits: &str, fp_regexes: &[Regex]) -> bool` | Validates phone with FP check |
| `is_valid_social_username()` | `fn(username: &str, platform: &str) -> bool` | Validates against blocklist + platform rules |
| `is_valid_crawl_url()` | `fn(url: &str, domain: &str) -> bool` | Checks domain, extension, directory |
| `resolve_url()` | `fn(base: &str, href: &str) -> Option<String>` | Resolves relative URLs to absolute |

---

## Constants Reference

| Constant | Count | Description |
|----------|-------|-------------|
| `INVALID_USERNAMES` | 38 | Social media username blocklist |
| `SKIP_EXTENSIONS` | 14 | Static asset file extensions |
| `SKIP_DIRS` | 8 | Asset directories to skip |
| `EMAIL_SKIP_PATTERNS` | 9 | Email false positive filters |
| `PHONE_FALSE_POSITIVES` | 3 | Phone number false positive regexes |
| Social platforms | 7 | Facebook, Twitter, Instagram, LinkedIn, YouTube, GitHub, TikTok |
| HTTP timeout | 15s | Per-request timeout |
| TLS validation | disabled | Accepts self-signed certs |
| Max redirects | 3 | Redirect follow limit |

---

## Usage Example

```rust
use web_analyzer::contact_spy::crawl_contacts;

#[tokio::main]
async fn main() {
    let result = crawl_contacts("example.com", 10).await.unwrap();

    println!("Scanned {} pages", result.pages_scanned);
    println!("Emails: {:?}", result.emails);
    println!("Phones: {:?}", result.phones);

    for (platform, profiles) in &result.social_media_by_platform {
        println!("{}: {} profiles", platform, profiles.len());
        for p in profiles {
            println!("  @{} → {}", p.username, p.url);
        }
    }
}
```

---

## Testing

```bash
cargo test --features contact-spy -- --nocapture
```
