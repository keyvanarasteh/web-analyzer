# Feature Request: GitHub / GitLab Secrets Dumper

## Overview
The `advanced_content_scanner.rs` module already contains fantastic regex signatures for 24 different types of API keys and secrets. However, it only applies these signatures to content it actively crawls on the live website.

Attackers frequently find organization secrets accidentally committed to public GitHub or GitLab repositories. We should leverage our existing secret regex engine against source code repositories via API dorking.

## Implementation Requirements

1. **New Module**: Create `src/repo_scanner.rs`.
2. **API Dorking**:
   - Use the GitHub REST API (`https://api.github.com/search/code`).
   - Construct queries targeting the organization or domain (e.g., `q=org:target_org filename:.env` or `q="target.com" "password"`).
3. **Regex Application**:
   - Fetch the raw file contents of the matched results.
   - Feed these raw files into the existing `SECRET_PATTERNS` regex engine.
4. **Rate Limit Handling**: Implement robust `tokio::time::sleep` backoff logic to handle GitHub's strict secondary rate limits.

## Why is this Pro-Level?
Source code leaks are a primary vector for initial access. Providing automated GitHub reconnaissance that feeds directly into the engine's proprietary secret regex dictionaries bridges the gap between Web Assessment and Open Source Intelligence (OSINT).
