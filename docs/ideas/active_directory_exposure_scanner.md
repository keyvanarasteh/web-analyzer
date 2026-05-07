# Feature Request: Active Directory / NTLM External Exposure Scanner

## Overview
While the engine performs port scanning via `domain_info.rs`, detecting an open port 389 (LDAP) or 445 (SMB) is only the first step. Enterprise networks frequently misconfigure these protocols, exposing Active Directory authentication mechanisms to the public internet.

We need a module that detects NTLM endpoints (e.g., Microsoft Exchange, OWA, Autodiscover) and attempts to extract the internal Windows Domain name and computer names without authenticating.

## Implementation Requirements

1. **New Module**: Create `src/ntlm_ad_scanner.rs`.
2. **NTLM Info Extraction**:
   - Target common Exchange endpoints (e.g., `https://target.com/EWS/Exchange.asmx`, `https://target.com/Autodiscover/Autodiscover.xml`).
   - Send an HTTP request with an empty NTLM Type 1 authentication header: `Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=`
   - Parse the server's Type 2 Challenge response (Base64 decoded).
   - Extract the internal `NetBIOS Domain Name`, `DNS Domain Name`, and `Computer Name`.
3. **LDAP Anonymous Bind**:
   - If port 389/636 is open, attempt an anonymous LDAP bind request using raw TCP bytes.
   - If successful, dump the base `namingContexts` to reveal the internal Active Directory schema structure.

## Why is this Pro-Level?
Leaking internal Active Directory naming conventions is a massive advantage for Red Teams preparing for spear-phishing or internal pivoting. Automating NTLM extraction directly over HTTP allows `web-analyzer` to profile internal Windows networks purely from external web interfaces.
