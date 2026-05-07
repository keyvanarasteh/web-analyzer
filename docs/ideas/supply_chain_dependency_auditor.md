# Feature Request: Supply Chain Dependency Confusion Auditor

## Overview
When `advanced_content_scanner` or the `archival_data_miner` discover leaked source code files (like `package.json`, `requirements.txt`, or `pom.xml`), they usually just look for hardcoded passwords. 

However, these files contain something much more dangerous: **internal package names**. If an organization uses an internal package (e.g., `@acme-corp/auth-utils`) but fails to reserve that exact name on the public NPM registry, an attacker can register the malicious package publicly. The company's build servers will pull the malicious public package instead of the internal one. This is known as Dependency Confusion.

## Implementation Requirements

1. **New Module**: Create `src/dependency_auditor.rs`.
2. **File Extraction**:
   - Parse any discovered `package.json`, `requirements.txt`, or `Gemfile`.
   - Extract the list of dependencies.
3. **Registry Verification**:
   - For NPM: Query `https://registry.npmjs.org/{package_name}`.
   - For PyPI: Query `https://pypi.org/pypi/{package_name}/json`.
4. **Vulnerability Logic**:
   - If a package name looks like an internal organization namespace (e.g., it contains the target's company name) AND the public registry returns a `404 Not Found`, flag this as a **Critical Supply Chain Vulnerability**.

## Why is this Pro-Level?
Supply chain attacks (like the SolarWinds hack) are devastating. Automating the detection of unreserverd internal dependencies directly within an OSINT scanner bridges the gap between web scanning and infrastructure compromise.
