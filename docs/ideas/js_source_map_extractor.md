# Feature Request: JavaScript Source Map Extractor & Decompiler

## Overview
Modern web apps (React, Svelte, Angular) compile and minify their JavaScript, making it hard to read. However, developers often accidentally deploy `.js.map` (Source Map) files to production. These files allow attackers to completely reconstruct the original, unminified source code, including comments and hardcoded internal variables.

We need a module that actively hunts for these source maps and decompiles them to feed into our `advanced_content_scanner`.

## Implementation Requirements

1. **New Module**: Create `src/source_map_extractor.rs`.
2. **Detection Logic**:
   - Crawl the target for `.js` files.
   - Look for the `//# sourceMappingURL=` comment at the bottom of the JS file.
   - If missing, blindly append `.map` to the JS URL (e.g., `app.js.map`) and check for a `200 OK`.
3. **Decompilation**:
   - Download the JSON `.map` file.
   - Parse the `sourcesContent` array which contains the raw TypeScript/JavaScript files.
4. **Secret Scanning Integration**:
   - Stream the decompiled source code directly into the existing `SECRET_PATTERNS` regex engine to hunt for hidden AWS keys, API tokens, and developer comments.

## Why is this Pro-Level?
Finding source maps is like finding the blueprints to a bank vault. Automating the extraction and secret-scanning of source maps is an advanced technique that often yields critical vulnerabilities in Bug Bounties.
