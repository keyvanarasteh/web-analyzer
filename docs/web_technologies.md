# Web Technologies

> **Module:** `web_technologies`
> **Feature Flag:** `web-technologies`
> **Source:** [`src/web_technologies.rs`](../src/web_technologies.rs)
> **Lines:** ~785 | **Dependencies:** `reqwest`, `scraper`, `regex`, `serde`, `serde_json`

Comprehensive web technology fingerprinting with security analysis. Detects 10 web servers, 8 backend technologies, 7 frontend frameworks, 12 JS libraries, 8 CSS frameworks, 11 CMS platforms, 9 e-commerce platforms, 6 CDN providers, 8 analytics tools, 8 WAF providers, security headers, vulnerability scanning, information disclosure, cookie security, full WordPress analysis, and composite security scoring.

---

## Table of Contents

- [Overview](#overview)
- [Public API](#public-api)
  - [`detect_web_technologies()`](#detect_web_technologies)
- [Data Structures](#data-structures)
  - [`WebTechResult`](#webtechresult)
  - [`SecurityHeaderInfo`](#securityheaderinfo)
  - [`VulnerabilityInfo`](#vulnerabilityinfo)
  - [`DisclosureInfo`](#disclosureinfo)
  - [`SecurityServicesInfo`](#securityservicesinfo)
  - [`CookieSecurityInfo`](#cookiesecurityinfo)
  - [`WordPressAnalysis`](#wordpressanalysis)
  - [`SecurityScoreResult`](#securityscoreresult)
- [Detection Categories](#detection-categories)
  - [1. Web Server (10)](#1-web-server-10)
  - [2. Backend Technologies (8)](#2-backend-technologies-8)
  - [3. Frontend Frameworks (7)](#3-frontend-frameworks-7)
  - [4. JavaScript Libraries (12)](#4-javascript-libraries-12)
  - [5. CSS Frameworks (8)](#5-css-frameworks-8)
  - [6. Content Management Systems (11)](#6-content-management-systems-11)
  - [7. E-commerce Platforms (9)](#7-e-commerce-platforms-9)
  - [8. CDN & Cloud Services (6)](#8-cdn--cloud-services-6)
  - [9. Analytics & Tracking (8)](#9-analytics--tracking-8)
- [Security Analysis](#security-analysis)
  - [10. Security Headers (6)](#10-security-headers-6)
  - [11. Security Vulnerabilities](#11-security-vulnerabilities)
  - [12. Information Disclosure](#12-information-disclosure)
  - [13. Security Services / WAF (8)](#13-security-services--waf-8)
  - [14. Cookie Security](#14-cookie-security)
- [WordPress Analysis](#wordpress-analysis)
  - [15. WordPress Detection & Analysis](#15-wordpress-detection--analysis)
- [Security Score](#security-score)
  - [16. Composite Security Score](#16-composite-security-score)
- [Usage Example](#usage-example)
- [Testing](#testing)

---

## Overview

```
┌───────────────────────────────────────────────────────────┐
│          detect_web_technologies(domain)                   │
├───────────────┬───────────────────────────────────────────┤
│ HTTP Request  │ GET + parse HTML via scraper               │
├───────────────┼───────────────────────────────────────────┤
│ Technology    │  1. Web Server (10 servers + version)     │
│ Detection     │  2. Backend (8 technologies)              │
│  (9 cats)     │  3. Frontend (7 frameworks)               │
│               │  4. JS Libraries (12)                     │
│               │  5. CSS Frameworks (8)                    │
│               │  6. CMS (11 platforms)                    │
│               │  7. E-commerce (9 platforms)              │
│               │  8. CDN (6 providers)                     │
│               │  9. Analytics (8 services)                │
├───────────────┼───────────────────────────────────────────┤
│ Security      │ 10. Security Headers (6 headers)          │
│ Analysis      │ 11. Vulnerability Detection               │
│  (5 cats)     │ 12. Information Disclosure                 │
│               │ 13. WAF Detection (8 providers)           │
│               │ 14. Cookie Security                        │
├───────────────┼───────────────────────────────────────────┤
│ WordPress     │ 15. Full WP Analysis                      │
│               │     (version/theme/plugins/users/API/      │
│               │      XMLRPC/admin/login/debug)            │
├───────────────┼───────────────────────────────────────────┤
│ Scoring       │ 16. Composite Score (0-100, A+ to F)      │
└───────────────┴───────────────────────────────────────────┘
```

---

## Public API

### `detect_web_technologies()`

```rust
pub async fn detect_web_technologies(
    domain: &str
) -> Result<WebTechResult, Box<dyn std::error::Error + Send + Sync>>
```

---

## Detection Categories

### 1. Web Server (10)

| Server | Detection Pattern |
|--------|------------------|
| Nginx | `nginx` in Server/X-Powered-By |
| Apache HTTP Server | `apache` |
| Microsoft IIS | `iis` |
| Cloudflare | `cloudflare` |
| LiteSpeed | `litespeed` |
| Caddy | `caddy` |
| Traefik Proxy | `traefik` |
| Envoy Proxy | `envoy` |
| Gunicorn WSGI | `gunicorn` |
| uWSGI | `uwsgi` |

Version extraction via regex on Server header.

### 2. Backend Technologies (8)

| Technology | Detection Patterns |
|-----------|-------------------|
| PHP | `X-Powered-By: php`, `.php`, `phpsessid` |
| ASP.NET | `X-Powered-By: asp.net`, `__viewstate`, `aspxauth` |
| Node.js | `X-Powered-By: express/koa`, Server: `node` |
| Python Django | `django`, `csrfmiddlewaretoken` |
| Python Flask | `flask`, Server: `werkzeug` |
| Ruby on Rails | `X-Powered-By: ruby`, `rails`, `authenticity_token` |
| Java | `jsessionid`, `servlet`, `.jsp`, `spring` |
| Go | `golang`, `gin-gonic` |

### 3. Frontend Frameworks (7)

| Framework | Detection Patterns |
|-----------|-------------------|
| React | `react` in scripts, `data-reactroot`, `__react` |
| Vue.js | `vue` in scripts, `v-app`, `v-cloak` |
| Angular | `angular` in scripts, `ng-app`, `ng-version` |
| Svelte | `svelte` in scripts, `_svelte` |
| Ember.js | `ember` in scripts, `ember-application` |
| Alpine.js | `alpine` in scripts, `x-data` |
| jQuery | `jquery` in scripts |

### 4. JavaScript Libraries (12)

jQuery, Lodash, Moment.js, D3.js, Chart.js, Three.js, GSAP, Axios, Swiper, Bootstrap JS, Popper.js, Font Awesome

### 5. CSS Frameworks (8)

Bootstrap, Tailwind CSS, Bulma, Foundation, Semantic UI, Materialize, UIKit, Pure CSS

### 6. Content Management Systems (11)

WordPress, Drupal, Joomla, Magento, Shopify, Wix, Squarespace, Ghost, Webflow, TYPO3, Concrete5

### 7. E-commerce Platforms (9)

Shopify, WooCommerce, Magento, PrestaShop, BigCommerce, OpenCart, Stripe, PayPal, Square

### 8. CDN & Cloud Services (6)

| Provider | Detection |
|----------|-----------|
| Cloudflare | Server header, `CF-Ray` |
| AWS CloudFront | Server/Via header, `X-Amz-Cf-Id` |
| Fastly | Server/Via header |
| KeyCDN | Server header |
| MaxCDN | HTML content |
| Akamai | Server header, `X-Akamai-Transformed` |

### 9. Analytics & Tracking (8)

Google Analytics, Google Tag Manager, Facebook Pixel, Hotjar, Mixpanel, Segment, Adobe Analytics, Yandex Metrica

---

## Security Analysis

### 10. Security Headers (6)

| Header | Importance |
|--------|-----------|
| Content-Security-Policy | High |
| Strict-Transport-Security | High |
| X-Frame-Options | Medium |
| X-Content-Type-Options | Medium |
| X-XSS-Protection | Medium |
| Referrer-Policy | Medium |

### 11. Security Vulnerabilities

- Missing security headers (5 required)
- Mixed content (HTTP on HTTPS page)
- Debug patterns: `debug.*true`, `error.*trace`, `stack.*trace`, `sql.*error`

### 12. Information Disclosure

- Server version exposure
- Technology stack (X-Powered-By)
- File path exposure: Windows (`c:\`), Linux (`/var/www/`, `/home/`)
- `.env` file references

### 13. Security Services / WAF (8)

Cloudflare, AWS WAF, Incapsula, Akamai, Sucuri, ModSecurity, F5 BIG-IP, Barracuda

### 14. Cookie Security

| Flag | Weight |
|------|--------|
| Secure | 40 |
| HttpOnly | 30 |
| SameSite | 30 |

Levels: Excellent (≥90), Good (≥70), Fair (≥50), Poor (<50)

---

## WordPress Analysis

### 15. WordPress Detection & Analysis

**Detection** (≥2 indicators required): `wp-content/`, `wp-includes/`, `wp-admin/`, `wp-json/`, `xmlrpc.php`

| Check | Method |
|-------|--------|
| Version | Generator meta tag, `ver=` query params |
| Theme | Stylesheet paths `/wp-content/themes/` |
| Plugins | Script/CSS paths + 10 known plugin signatures |
| Users | REST API `/wp-json/wp/v2/users` |
| REST API | Check `/wp-json/` accessibility |
| XML-RPC | Check `/xmlrpc.php` response |
| Admin | Check `/wp-admin/` accessibility |
| Login | Check `/wp-login.php` accessibility |
| Debug | `wp_debug`, `fatal error.*wp-` patterns |

**Known Plugins (10):** Yoast SEO, Akismet, Jetpack, WooCommerce, Contact Form 7, Elementor, Wordfence, WP Super Cache, All in One SEO, Google Analytics

---

## Security Score

### 16. Composite Security Score

| Factor | Impact |
|--------|--------|
| Missing security headers | −8 per header |
| Missing required headers | −5 per header |
| Insecure practices | −10 each |
| Information disclosure | −5 each |
| Insecure cookies | −10 |
| WordPress security issues | −5 each |
| WAF detected | +5 bonus |

**Grades:** A+ (≥90), A (≥85), A- (≥80), B+ (≥75), B (≥70), B- (≥65), C+ (≥60), C (≥55), C- (≥50), D (≥40), F (<40)

**Risk Levels:** Low (≥80), Medium (≥60), High (≥40), Critical (<40)

---

## Usage Example

```rust
use web_analyzer::web_technologies::detect_web_technologies;

#[tokio::main]
async fn main() {
    let result = detect_web_technologies("example.com").await.unwrap();

    println!("Server: {}", result.web_server);
    println!("Backend: {:?}", result.backend);
    println!("Frontend: {:?}", result.frontend);
    println!("CMS: {:?}", result.cms);
    println!("CDN: {:?}", result.cdn);
    println!("Score: {}/100 ({})", result.security_score.overall_score, result.security_score.security_grade);
    println!("Risk: {}", result.security_score.risk_level);

    if result.is_wordpress {
        if let Some(wp) = &result.wordpress_analysis {
            println!("WP Version: {}", wp.version);
            println!("WP Theme: {}", wp.theme);
            println!("WP Plugins: {:?}", wp.plugins);
            println!("WP Users: {}", wp.users_found.len());
        }
    }
}
```

---

## Testing

```bash
cargo test --features web-technologies -- --nocapture
```
