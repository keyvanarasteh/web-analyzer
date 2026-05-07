# Feature Request: Mobile API Endpoint Extractor (APK/IPA Miner)

## Overview
Web applications are often tightly locked down behind WAFs. However, the same company's Android or iOS app often communicates with hidden, legacy, or less-secure staging APIs.

If `web-analyzer` detects a link to a Google Play APK or an Apple App Store IPA on the target's website, it should be able to mine that mobile binary for alternative attack surfaces.

## Implementation Requirements

1. **New Module**: Create `src/mobile_api_miner.rs`.
2. **Binary Acquisition**:
   - If a direct APK link is found, download it.
   - Alternatively, integrate with third-party APK downloader APIs.
3. **Decompilation & Extraction**:
   - Use pure-Rust ZIP extraction to unzip the `.apk` (since APKs are just ZIP files).
   - Parse the `classes.dex` files using a library like `dex` to extract raw string constants.
   - Parse the `AndroidManifest.xml` (requires Android binary XML parsing).
4. **Data Correlation**:
   - Extract all `https://` URLs, API keys, and staging endpoints hidden in the mobile code.
   - Feed these newly discovered staging endpoints back into the `api_security_scanner` for web vulnerability testing.

## Why is this Pro-Level?
Attackers know that mobile APIs are often the weakest link. By automating the extraction of strings from mobile binaries and correlating them back to web vulnerabilities, the engine performs true multi-platform reconnaissance.
