# GEO Analysis

> **Module:** `geo_analysis`
> **Feature Flag:** `geo-analysis`
> **Source:** [`src/geo_analysis.rs`](../src/geo_analysis.rs)
> **Lines:** ~170 | **Dependencies:** `reqwest`, `serde`

Generative Engine Optimization (GEO) analysis — evaluates how well a website is prepared for AI/LLM discovery by checking `llms.txt`, WebMCP integration, and AI crawler directives in `robots.txt`.

---

## Table of Contents

- [Overview](#overview)
- [Public API](#public-api)
  - [`analyze_geo()`](#analyze_geo)
- [Data Structures](#data-structures)
  - [`GeoAnalysisResult`](#geoanalysisresult)
  - [`LlmsTxtResult`](#llmstxtresult)
  - [`WebMcpResult`](#webmcpresult)
  - [`AiCrawlerResult`](#aicrawlerresult)
- [Check 1: LLMs.txt](#check-1-llmstxt)
  - [Paths Checked (3)](#paths-checked-3)
  - [Validation](#validation)
- [Check 2: WebMCP Integration](#check-2-webmcp-integration)
  - [Endpoint Probing (2)](#endpoint-probing-2)
  - [HTML Feature Detection](#html-feature-detection)
- [Check 3: AI Crawler Directives](#check-3-ai-crawler-directives)
  - [AI Bots Tracked (7)](#ai-bots-tracked-7)
  - [Directive Parsing](#directive-parsing)
  - [Status Classification](#status-classification)
- [GEO Score Calculation](#geo-score-calculation)
  - [Scoring Breakdown (0-100)](#scoring-breakdown-0-100)
  - [Grade Scale](#grade-scale)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌─────────────────────────────────────────────┐
│            analyze_geo(domain)              │
├────────────┬────────────────────────────────┤
│ Check 1    │ llms.txt (3 paths, up to 40pt) │
│ Check 2    │ WebMCP (2 endpoints + HTML,    │
│            │   up to 40pt)                  │
│ Check 3    │ AI Crawler directives          │
│            │   (7 bots, up to 20pt)         │
├────────────┼────────────────────────────────┤
│ Scoring    │ 0-100 → Grade A-F             │
└────────────┴────────────────────────────────┘
```

---

## Public API

### `analyze_geo()`

```rust
pub async fn analyze_geo(
    domain: &str
) -> Result<GeoAnalysisResult, Box<dyn std::error::Error + Send + Sync>>
```

| Param | Type | Description |
|-------|------|-------------|
| `domain` | `&str` | Target domain. Accepts `example.com` or `https://example.com`. |

---

## Data Structures

### `GeoAnalysisResult`

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `String` | Target domain |
| `llms_txt` | `LlmsTxtResult` | llms.txt check results |
| `webmcp` | `WebMcpResult` | WebMCP integration status |
| `ai_crawler_directives` | `AiCrawlerResult` | robots.txt AI bot analysis |
| `geo_score` | `u32` | Score out of 100 |
| `geo_grade` | `String` | Letter grade (A-F) |

### `LlmsTxtResult`

| Field | Type | Description |
|-------|------|-------------|
| `found` | `bool` | Whether any llms.txt file was found |
| `files` | `Vec<String>` | List of found file paths |

### `WebMcpResult`

| Field | Type | Description |
|-------|------|-------------|
| `found` | `bool` | Whether any MCP endpoint or HTML feature was found |
| `endpoints` | `Vec<String>` | Found MCP endpoint paths |
| `html_features` | `Vec<String>` | Detected HTML/JS features |

### `AiCrawlerResult`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `String` | `"Permissive"` or `"Restrictive"` |
| `bots` | `HashMap<String, String>` | Per-bot directive status |

---

## Check 1: LLMs.txt

### Paths Checked (3)

| Path | Standard |
|------|----------|
| `/llms.txt` | LLMs.txt specification |
| `/llms-full.txt` | Extended/full content version |
| `/.well-known/llms.txt` | Well-known URI convention |

### Validation

A file is considered valid if:
- HTTP status is success (2xx)
- Content-Type contains `text/plain` or `text/html`

---

## Check 2: WebMCP Integration

### Endpoint Probing (2)

| Endpoint | Description |
|----------|-------------|
| `/.well-known/mcp` | Standard MCP discovery endpoint |
| `/mcp.json` | MCP configuration file |

### HTML Feature Detection

The main page HTML is scanned for:

| Pattern | Detection |
|---------|-----------|
| `navigator.modelContext` | JavaScript API for Model Context Protocol |
| `webmcp` or `model context protocol` | References to WebMCP technology (case-insensitive) |

---

## Check 3: AI Crawler Directives

### AI Bots Tracked (7)

| Bot Name | Provider |
|----------|----------|
| `GPTBot` | OpenAI |
| `ChatGPT-User` | OpenAI |
| `ClaudeBot` | Anthropic |
| `Claude-Web` | Anthropic |
| `Applebot-Extended` | Apple |
| `OAI-SearchBot` | OpenAI |
| `PerplexityBot` | Perplexity |

### Directive Parsing

`robots.txt` is parsed line-by-line:

| Directive | Result |
|-----------|--------|
| `Disallow: /` | `"Blocked"` |
| `Disallow: /path` | `"Partially Blocked"` |
| `Allow: /` | `"Allowed"` |
| No specific rule | `"Allowed (Implicit)"` |

### Status Classification

| Status | Condition |
|--------|-----------|
| `Restrictive` | >50% of bots are blocked |
| `Permissive` | ≤50% of bots are blocked |

---

## GEO Score Calculation

### Scoring Breakdown (0-100)

| Component | Max Points | Detail |
|-----------|-----------|--------|
| **llms.txt** | 40 | 20 base + 10 per file found (max 20 bonus) |
| **WebMCP** | 40 | 20 base + 10 for endpoints + 10 for HTML features |
| **AI Crawlers** | 20 | 20 if Permissive, 0 if Restrictive |

### Grade Scale

| Score | Grade |
|-------|-------|
| 80-100 | A (Excellent) |
| 60-79 | B (Good) |
| 40-59 | C (Fair) |
| 20-39 | D (Poor) |
| 0-19 | F (None) |

---

## Usage Example

```rust
use web_analyzer::geo_analysis::analyze_geo;

#[tokio::main]
async fn main() {
    let result = analyze_geo("example.com").await.unwrap();

    println!("GEO Score: {}/100 ({})", result.geo_score, result.geo_grade);
    println!("llms.txt: {}", if result.llms_txt.found { "Found" } else { "Not Found" });
    println!("WebMCP: {}", if result.webmcp.found { "Found" } else { "Not Found" });
    println!("AI Crawlers: {}", result.ai_crawler_directives.status);

    for (bot, status) in &result.ai_crawler_directives.bots {
        println!("  {} → {}", bot, status);
    }
}
```

---

## Testing

```bash
cargo test --features geo-analysis -- --nocapture
```
