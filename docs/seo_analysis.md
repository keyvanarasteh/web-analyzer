# SEO Analysis

> **Module:** `seo_analysis`
> **Feature Flag:** `seo-analysis`
> **Source:** [`src/seo_analysis.rs`](../src/seo_analysis.rs)
> **Lines:** ~530 | **Dependencies:** `reqwest`, `scraper`, `regex`, `serde`, `serde_json`

Comprehensive SEO analysis with 13 analysis categories: basic SEO, content structure, technical SEO, social media tags, analytics & tracking, performance, mobile & accessibility, SEO resources, schema markup, link analysis, image SEO, page speed factors, and a weighted composite score.

---

## Table of Contents

- [Overview](#overview)
- [Public API](#public-api)
  - [`analyze_advanced_seo()`](#analyze_advanced_seo)
- [Data Structures](#data-structures)
  - [`SeoAnalysisResult`](#seoanalysisresult)
  - [`BasicSeoResult`](#basicseo)
  - [`ContentAnalysisResult`](#contentanalysis)
  - [`TechnicalSeoResult`](#technicalseo)
  - [`SocialMediaResult`](#socialmedia)
  - [`PerformanceResult`](#performance)
  - [`MobileAccessibilityResult`](#mobileaccessibility)
  - [`SchemaMarkupResult`](#schemamarkup)
  - [`LinkAnalysisResult`](#linkanalysis)
  - [`ImageSeoResult`](#imageseo)
  - [`PageSpeedResult`](#pagespeed)
  - [`SeoScoreResult`](#seoscore)
- [Analysis Categories](#analysis-categories)
  - [1. Basic SEO](#1-basic-seo)
  - [2. Content Analysis](#2-content-analysis)
  - [3. Technical SEO](#3-technical-seo)
  - [4. Social Media Tags](#4-social-media-tags)
  - [5. Analytics & Tracking (13 Tools)](#5-analytics--tracking-13-tools)
  - [6. Performance Metrics](#6-performance-metrics)
  - [7. Mobile & Accessibility](#7-mobile--accessibility)
  - [8. SEO Resources](#8-seo-resources)
  - [9. Schema Markup](#9-schema-markup)
  - [10. Link Analysis](#10-link-analysis)
  - [11. Image SEO](#11-image-seo)
  - [12. Page Speed Factors](#12-page-speed-factors)
  - [13. SEO Score](#13-seo-score)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌───────────────────────────────────────────────────────────────┐
│               analyze_advanced_seo(domain)                    │
├───────────────┬───────────────────────────────────────────────┤
│ HTTP Request  │ GET with timing, parse HTML via scraper       │
├───────────────┼───────────────────────────────────────────────┤
│ 13 Analysis   │  1. Basic SEO (title, desc, canonical, ...)  │
│ Categories    │  2. Content (headings H1-H6, words, ratio)   │
│               │  3. Technical (size, links, schema, crumbs)  │
│               │  4. Social (6 OG + 5 Twitter tags)           │
│               │  5. Analytics (GA4/UA + 11 tracking tools)   │
│               │  6. Performance (load time, cache, ETag)     │
│               │  7. Mobile (viewport, alt attrs, ARIA)       │
│               │  8. SEO Resources (robots, sitemap, ads)     │
│               │  9. Schema Markup (JSON-LD types, microdata) │
│               │ 10. Links (internal/external/nofollow)       │
│               │ 11. Images (lazy, alt, title, score)         │
│               │ 12. Page Speed (CSS/JS/inline counts)        │
│               │ 13. SEO Score (0-100, grade A+-F)            │
└───────────────┴───────────────────────────────────────────────┘
```

---

## Public API

### `analyze_advanced_seo()`

```rust
pub async fn analyze_advanced_seo(
    domain: &str
) -> Result<SeoAnalysisResult, Box<dyn std::error::Error + Send + Sync>>
```

---

## Analysis Categories

### 1. Basic SEO

| Check | Optimal Range | Status Values |
|-------|--------------|---------------|
| Title | 30-60 chars | Good / Too short / Too long / Missing |
| Meta Description | 120-160 chars | Good / Too short / Too long / Missing |
| Meta Keywords | Any | Content or "Not Found" |
| Canonical URL | Any | URL or "Not Found" |
| Meta Robots | Any | Content or "Not Found" |
| Viewport | Any | Content or "Not Found" |
| Language | `lang` attr | Value or "Not specified" |
| Charset | `<meta charset>` | Value or "Unknown" |

### 2. Content Analysis

- **Headings H1-H6**: Count and first 3 text samples per level
- **Heading issues**: Missing H1, multiple H1, skipped levels
- **Word count**: ≥300 = "Good", else "Too short"
- **Text-to-HTML ratio**: Percentage
- **Keyword density**: Top 5 words (>3 chars) with count and density %

### 3. Technical SEO

| Metric | Description |
|--------|-------------|
| Page size | Bytes |
| HTTP status | Status code |
| Redirects | Count |
| Internal/External links | Count |
| Structured data | JSON-LD + Microdata total |
| Breadcrumbs | Detected via `BreadcrumbList` or class |

### 4. Social Media Tags

**Open Graph (6 tags):** `og:title`, `og:description`, `og:image`, `og:url`, `og:type`, `og:site_name`

**Twitter Cards (5 tags):** `twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`, `twitter:site`

### 5. Analytics & Tracking (13 Tools)

| Tool | Detection Patterns |
|------|-------------------|
| Google Analytics GA4 | `gtag('config', 'G-...')` |
| Google Analytics UA | `gtag('config', 'UA-...')` |
| Google Tag Manager | `googletagmanager.com/gtm.js`, `dataLayer` |
| Google Ads | `googleads.g.doubleclick.net`, `googlesyndication.com` |
| Facebook Pixel | `connect.facebook.net`, `fbq(` |
| LinkedIn Insight | `snap.licdn.com`, `_linkedin_partner_id` |
| TikTok Pixel | `analytics.tiktok.com`, `ttq.` |
| Hotjar | `static.hotjar.com`, `hjid` |
| Mixpanel | `cdn.mxpnl.com`, `mixpanel.init` |
| Segment | `cdn.segment.com`, `analytics.load` |
| Intercom | `widget.intercom.io` |
| Zendesk | `static.zdassets.com` |
| Crisp | `client.crisp.chat` |

### 6. Performance Metrics

| Metric | Values |
|--------|--------|
| Load time | Seconds (Excellent <1s, Good <3s, Poor ≥3s) |
| Content size | KB |
| Compression | Content-Encoding header |
| Server | Server header |
| Cache-Control | Header value |
| ETag | Present or not |

### 7. Mobile & Accessibility

| Check | Description |
|-------|-------------|
| Viewport | Present + contains `width=device-width` |
| Alt attributes | Total images, with alt, missing, coverage % |
| ARIA labels | Count of elements with `aria-label` |

### 8. SEO Resources

Checks for: `robots.txt`, `sitemap.xml`, `humans.txt`, `ads.txt`

### 9. Schema Markup

- **JSON-LD**: Count + extracted `@type` values (recursive)
- **Microdata**: Count of elements with `itemtype`
- **Inline detection**: Regex-based `@type` extraction from raw HTML

### 10. Link Analysis

| Metric | Description |
|--------|-------------|
| Total links | All `<a href>` elements |
| Internal links | Same domain or relative |
| External links | Different domain |
| NoFollow links | `rel="nofollow"` |

### 11. Image SEO

| Metric | Description |
|--------|-------------|
| Total images | `<img>` count |
| Lazy loaded | `loading="lazy"` |
| With alt text | `alt` attribute present |
| With title | `title` attribute present |
| Optimization score | `(lazy + alt) / (total × 2) × 100%` |

### 12. Page Speed Factors

| Factor | Selector |
|--------|----------|
| CSS files | `<link rel="stylesheet">` |
| JS files | `<script src>` |
| Inline styles | `<style>` |
| Inline scripts | `<script>` without `src` |
| Compression | Content-Encoding header |

### 13. SEO Score

| Component | Max Points | Condition |
|-----------|-----------|-----------|
| Title | 10 | Status = "Good" |
| Meta Description | 10 | Status = "Good" |
| Canonical URL | 5 | Found |
| Viewport | 5 | Found |
| Word Count | 10 | ≥300 words |
| H1 Tag | 10 | H1 heading exists |
| robots.txt | 5 | Found |
| sitemap.xml | 5 | Found |
| Schema Markup | 10 | Any structured data found |
| Performance | 15 | Excellent or Good load time |
| Security (base) | 5 | Always awarded |
| Mobile Friendly | 5 | viewport + device-width |
| **Total** | **100** | |

**Grades:** A+ (≥90), A (≥80), B (≥70), C (≥60), D (≥50), F (<50)

---

## Usage Example

```rust
use web_analyzer::seo_analysis::analyze_advanced_seo;

#[tokio::main]
async fn main() {
    let result = analyze_advanced_seo("example.com").await.unwrap();

    println!("SEO Score: {}/{} ({}) — Grade {}",
        result.seo_score.score, result.seo_score.max_score,
        result.seo_score.percentage, result.seo_score.grade);

    println!("Title: {} ({})", result.basic_seo.title.text, result.basic_seo.title.status);
    println!("H1-H6: {:?}", result.content_analysis.headings.keys().collect::<Vec<_>>());
    println!("Internal Links: {}", result.link_analysis.internal_links);
    println!("Images: {} ({}% optimized)", result.image_seo.total_images, result.image_seo.optimization_score);
}
```

---

## Testing

```bash
cargo test --features seo-analysis -- --nocapture
```
