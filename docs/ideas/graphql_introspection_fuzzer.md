# Feature Request: GraphQL Introspection & Mutation Fuzzer

## Overview
The `api_security_scanner.rs` currently excels at finding traditional REST vulnerabilities (SQLi, SSRF). However, modern enterprise applications are heavily shifting towards GraphQL. 

If a GraphQL endpoint is misconfigured with "Introspection" enabled, an attacker can send a specific query to dump the *entire* schema of the API, instantly mapping every possible Query and Mutation, including hidden administrative endpoints.

## Implementation Requirements

1. **New Module**: Create `src/graphql_fuzzer.rs`.
2. **Endpoint Discovery**:
   - Actively probe common paths: `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`.
3. **Introspection Execution**:
   - Dispatch the standard `__schema` introspection query.
   - If successful, parse the returned JSON to catalog all Types, Queries, and Mutations.
4. **Vulnerability Fuzzing**:
   - Identify sensitive Mutations (e.g., `updateUserRole`, `deleteAccount`).
   - Test for IDOR (Insecure Direct Object Reference) by modifying GraphQL variables.
   - Check for Query Batching attacks (sending 10,000 login queries in a single HTTP request to bypass rate limiting).

## Why is this Pro-Level?
GraphQL requires an entirely different security testing methodology than REST. Adding native GraphQL introspection and schema mapping to `web-analyzer` allows the engine to instantly dissect modern frontend backends without any manual proxying.
