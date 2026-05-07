# Feature Request: Archival Data Miner (Wayback Machine & AlienVault OTX)

## Overview
Modern web applications often remove deprecated API endpoints, old administrator panels, or sensitive backup files from their live sites. However, these endpoints are frequently still functional on the backend—they are just "hidden." 

To uncover these, `web-analyzer` needs a module that mines internet archives for historical URLs associated with the target domain.

## Implementation Requirements

1. **New Module**: Create `src/archival_miner.rs`.
2. **Data Sources**:
   - **Wayback Machine (CDX API)**: `http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original&collapse=urlkey`
   - **AlienVault OTX**: `https://otx.alienvault.com/api/v1/indicators/domain/target.com/url_list`
   - **Common Crawl**: (Optional, advanced integration).
3. **Data Processing**:
   - Extract unique URLs.
   - Filter out static assets (`.jpg`, `.css`, `.woff2`) to isolate interesting paths (`.php`, `.aspx`, `/api/v1/`, `.env`, `.bak`).
4. **Live Probing**: Optionally feed these discovered URLs back into the engine's HTTP client to see if they return a `200 OK` on the live server today.

## Why is this Pro-Level?
"Hidden" endpoints are a goldmine for Zero-Day discovery. Automating the extraction and filtering of archival data turns the engine into an advanced attack surface mapper capable of uncovering forgotten, vulnerable legacy code.
