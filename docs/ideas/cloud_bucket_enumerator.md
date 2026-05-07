# Feature Request: Cloud Storage Bucket Enumerator (S3/Azure/GCP)

## Overview
Exposed cloud storage buckets are one of the leading causes of massive data breaches. While `web-analyzer` handles subdomain takeover and Web Technology fingerprinting, it currently lacks the ability to hunt for misconfigured cloud storage containers that belong to the target domain.

We need a high-concurrency brute-force module that generates permutations of the target domain and checks if public read access is enabled on popular cloud providers.

## Implementation Requirements

1. **New Module**: Create `src/cloud_enum.rs`.
2. **Permutation Engine**: 
   - Take the base domain (e.g., `acme.com`).
   - Use a hardcoded dictionary of common suffixes/prefixes (e.g., `dev`, `staging`, `backup`, `assets`, `prod`).
   - Generate names like `acme-dev`, `acme-backup`, `assets-acme`.
3. **Provider Checks**:
   - **AWS S3**: Perform HEAD/GET requests to `https://{name}.s3.amazonaws.com`.
   - **Azure Blob**: Check `https://{name}.blob.core.windows.net`.
   - **GCP Storage**: Check `https://storage.googleapis.com/{name}`.
4. **Concurrency**: Use the existing `tokio::sync::Semaphore` pattern from the bulk domain validator to fire thousands of HTTP requests per second asynchronously.
5. **Access Validation**: Detect `200 OK` (Publicly Readable) or `ListBucketResult` XML responses vs `403 Forbidden` (Exists but secured) or `404 Not Found`.

## Why is this Pro-Level?
Cloud enumeration is a staple in Bug Bounty hunting and Cloud Security Posture Management (CSPM). Adding this directly to the Rust engine provides unmatched speed compared to traditional Python scripts.
