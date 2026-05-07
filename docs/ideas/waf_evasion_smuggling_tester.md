# Feature Request: WAF Evasion & Protocol Smuggling Tester

## Overview
The `security_analysis.rs` module effectively *detects* WAFs (Web Application Firewalls). However, elite security analysts don't just detect WAFs—they try to bypass them.

We need a module that actively tests the resilience of the WAF by mutating HTTP requests and exploiting protocol parsing discrepancies between the frontend proxy and backend server (HTTP Request Smuggling).

## Implementation Requirements

1. **New Module**: Create `src/waf_evasion.rs`.
2. **Path Obfuscation Vectors**:
   - Automatically mutate payloads using techniques like: `/api/v1/user` -> `/api/./v1/user`, `/api/v1/..%2fuser`, `//api//v1//user`.
3. **Header Manipulation**:
   - Inject headers designed to bypass WAF source IP checks: `X-Originating-IP: 127.0.0.1`, `X-Client-IP: 127.0.0.1`.
4. **HTTP Request Smuggling (TE.CL / CL.TE)**:
   - Send malformed requests containing conflicting `Content-Length` and `Transfer-Encoding: chunked` headers.
   - Monitor the timing and response codes to detect if the backend server parses the request differently than the frontend proxy.

## Why is this Pro-Level?
WAF evasion and HTTP Request Smuggling are highly advanced, often yielding critical Remote Code Execution (RCE) or complete firewall bypasses. Integrating this into `web-analyzer` pushes it into the territory of elite offensive tools.
