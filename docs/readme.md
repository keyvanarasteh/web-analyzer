# 🕸️ WebAnalyzer: Enterprise Intelligence & Security

`web-analyzer` is a high-performance Rust-based intelligence platform designed for comprehensive domain reconnaissance, security assessment, and technology profiling. It provides a multi-layered analysis pipeline for both OSINT (Open Source Intelligence) and active security scanning.

## 📋 Table of Contents

- [Intelligence Gathering](#intelligence-gathering)
- [Reconnaissance](# reconnaissance)
- [Security Assessment](#security-assessment)
- [Advanced Modules](#advanced-modules)

## 🧠 Intelligence Gathering

- **Domain Intelligence**: Deep introspection of domain registration, WHOIS records, and historical data.
- **DNS Analysis**: Comprehensive mapping of DNS records (A, AAAA, MX, TXT, CNAME) and zone transfers.
- **Technology Profiling**: Passive detection of CMS (WordPress, Drupal, etc.), backend frameworks (Django, Laravel), and frontend libraries (React, Vue).
- **SEO Intelligence**: Analysis of meta tags, sitemaps, robots.txt, and link density for search engine optimization audits.

---

## 🔍 Reconnaissance

- **Subdomain Discovery**: Multi-source subdomain enumeration using active DNS probing and passive intelligence.
- **Contact Spy**: Intelligent scraping for emails, social media profiles, and technical contact information across public surfaces.
- **Advanced Content Scanners**: Deep crawling of web applications to map hidden endpoints, files, and directory structures.

---

## 🛡️ Security Assessment

- **WAF Detection**: Fingerprinting of Web Application Firewalls (Cloudflare, Akamai, AWS WAF, etc.) to understand protection layers.
- **Security Header Audit**: Evaluation of HSTS, CSP, X-Frame-Options, and other critical security headers against industry best practices.
- **Vulnerability Scanning**:
    - **SSL/TLS Audit**: Deep analysis of certificate validity, cipher strength, and protocol support.
    - **CORS & Cookie Safety**: Detection of insecure cross-origin policies and cookie flags (HttpOnly, Secure, SameSite).
    - **Information Disclosure**: Scanning for exposed server versions, stack traces, and sensitive files (.env, .git).
- **API Security**: Specialized scanning for REST/GraphQL endpoints, checking for authentication gaps and insecure methods (PUT, DELETE).

---

## 🚀 Advanced Modules

- **Cloudflare Bypass**: Specialized logic for identifying origin IPs behind Cloudflare proxies.
- **Nmap Zero-Day Integration**: Orchestration of Nmap scans with custom scripts for vulnerability discovery.
- **Geo Analysis**: Geographical mapping of server infrastructure and IP origins.
- **WordPress Deep-Dive**: Specialized scanner for WP version detection, plugin enumeration, and user discovery via the REST API.
