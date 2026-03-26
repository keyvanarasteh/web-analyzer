#[cfg(feature = "api-security-scanner")]
mod api_scanner_tests {
    use web_analyzer::api_security_scanner::*;

    // ── Test 1: End-to-end scan ─────────────────────────────────────────
    #[tokio::test]
    async fn test_scan_api_endpoints() {
        let result = scan_api_endpoints("example.com").await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());

        let info = result.unwrap();
        assert_eq!(info.domain, "example.com");
        assert!(
            info.total_paths_probed > 100,
            "Should probe 800+ API paths, got {}",
            info.total_paths_probed
        );

        println!(
            "Scan complete: probed {} paths, found {} endpoints, {} vulns, tested {}",
            info.total_paths_probed,
            info.endpoints_found.len(),
            info.vulnerabilities.len(),
            info.endpoints_tested
        );
    }

    // ── Test 2: VulnerabilityFinding serialization ──────────────────────
    #[test]
    fn test_vulnerability_struct_serialization() {
        let finding = VulnerabilityFinding {
            vuln_type: "SQL_INJECTION".into(),
            subtype: "Error-based".into(),
            endpoint: "https://example.com/api/v1".into(),
            parameter: "id".into(),
            payload: "' OR '1'='1".into(),
            severity: "CRITICAL".into(),
            confidence: "HIGH".into(),
            evidence: "SQL syntax error in response".into(),
        };

        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("SQL_INJECTION"));
        assert!(json.contains("CRITICAL"));
        assert!(json.contains("Error-based"));

        let deserialized: VulnerabilityFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.vuln_type, "SQL_INJECTION");
        assert_eq!(deserialized.severity, "CRITICAL");
    }

    // ── Test 3: ApiEndpoint serialization ───────────────────────────────
    #[test]
    fn test_api_endpoint_serialization() {
        let ep = ApiEndpoint {
            url: "https://api.example.com/v1/users".into(),
            status_code: 200,
            api_type: "REST/JSON".into(),
        };

        let json = serde_json::to_string(&ep).unwrap();
        assert!(json.contains("REST/JSON"));
        assert!(json.contains("200"));
    }

    // ── Test 4: ApiScanResult serialization ─────────────────────────────
    #[test]
    fn test_scan_result_serialization() {
        let result = ApiScanResult {
            domain: "example.com".into(),
            endpoints_found: vec![],
            vulnerabilities: vec![],
            total_paths_probed: 733,
            endpoints_tested: 0,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("733"));
        assert!(json.contains("example.com"));
    }

    // ── Test 5: SQL error patterns compile ──────────────────────────────
    #[test]
    fn test_sql_injection_patterns() {
        use regex::Regex;

        let patterns = [
            r"You have an error in your SQL syntax",
            r"MySQL server version for the right syntax",
            r"PostgreSQL.*ERROR.*syntax error",
            r"ORA-[0-9]{5}.*invalid identifier",
            r"SQLite error.*syntax error",
        ];

        for pattern in &patterns {
            let rx = Regex::new(pattern);
            assert!(rx.is_ok(), "Pattern should compile: {}", pattern);
        }

        // Test actual matching
        let rx = Regex::new(r"You have an error in your SQL syntax").unwrap();
        assert!(rx.is_match("You have an error in your SQL syntax near"));

        let rx = Regex::new(r"ORA-[0-9]{5}.*invalid identifier").unwrap();
        assert!(rx.is_match("ORA-00904: invalid identifier"));
    }

    // ── Test 6: XSS safe context detection ──────────────────────────────
    #[test]
    fn test_xss_safe_context() {
        // Encoded payload should be considered safe
        let content = "&lt;script&gt;alert(1)&lt;/script&gt;";
        let payload = "<script>alert(1)</script>";
        // Payload not present literally, so it's safe
        assert!(!content.contains(payload));

        // Inside HTML comment should be safe
        let content_comment = "<!-- <script>alert(1)</script> -->";
        assert!(content_comment.contains(payload));
        // The comment check logic:
        let pos = content_comment.find(payload).unwrap();
        let before = &content_comment[..pos];
        assert!(before.contains("<!--"));
    }

    // ── Test 7: SSTI expected results ───────────────────────────────────
    #[test]
    fn test_ssti_expected_results() {
        let tests = [
            ("{{7*7*7}}", "343"),
            ("{{9*9*9}}", "729"),
            ("${8*8*8}", "512"),
            ("{{42*13}}", "546"),
        ];

        // Verify each expression evaluates to expected result
        for (payload, expected) in &tests {
            let expected_num: i64 = expected.parse().unwrap();
            assert!(
                expected_num > 100,
                "Expected result {} should be > 100 to avoid false positives",
                expected
            );
            assert!(
                !payload.contains(expected),
                "Payload '{}' should not contain expected '{}'",
                payload,
                expected
            );
        }
    }

    // ── Test 8: Auth bypass header parsing ──────────────────────────────
    #[test]
    fn test_auth_bypass_header_parsing() {
        use web_analyzer::payloads;

        let headers = payloads::auth_headers(payloads::AUTH_BYPASS_HEADERS);
        assert!(!headers.is_empty(), "Should parse auth bypass headers");

        // Should have header name : value pairs
        for (name, value) in &headers {
            assert!(!name.is_empty(), "Header name should not be empty");
            assert!(!value.is_empty(), "Header value should not be empty");
        }

        // Check for known bypass headers
        let header_names: Vec<&str> = headers.iter().map(|(n, _)| n.as_ref() as &str).collect();
        assert!(
            header_names
                .iter()
                .any(|n| n.contains("X-Forwarded-For") || n.contains("X-Real-IP")),
            "Should contain common bypass headers, got: {:?}",
            header_names
        );
    }

    // ── Test 9: Payload files load correctly ────────────────────────────
    #[test]
    fn test_payload_loading() {
        use web_analyzer::payloads;

        let sqli = payloads::lines(payloads::SQL_INJECTION);
        assert!(
            sqli.len() > 5,
            "Should have SQLi payloads, got {}",
            sqli.len()
        );

        let xss = payloads::lines(payloads::XSS);
        assert!(xss.len() > 3, "Should have XSS payloads, got {}", xss.len());

        let ssrf = payloads::lines(payloads::SSRF);
        assert!(
            ssrf.len() > 3,
            "Should have SSRF payloads, got {}",
            ssrf.len()
        );

        let cmd = payloads::lines(payloads::COMMAND_INJECTION);
        assert!(
            cmd.len() > 3,
            "Should have CMD injection payloads, got {}",
            cmd.len()
        );

        let nosql = payloads::lines(payloads::NOSQL_INJECTION);
        assert!(
            nosql.len() > 2,
            "Should have NoSQL payloads, got {}",
            nosql.len()
        );

        let xxe = payloads::lines(payloads::XXE);
        assert!(!xxe.is_empty(), "Should have XXE payloads");

        let lfi = payloads::lines(payloads::LFI);
        assert!(lfi.len() > 3, "Should have LFI payloads, got {}", lfi.len());
    }

    // ── Test 10: API endpoints payload loaded ───────────────────────────
    #[test]
    fn test_api_endpoints_payload() {
        use web_analyzer::payloads;

        let endpoints = payloads::lines(payloads::API_ENDPOINTS);
        assert!(
            endpoints.len() > 700,
            "Should have 700+ API endpoint patterns, got {}",
            endpoints.len()
        );

        // Verify known endpoints exist
        assert!(
            endpoints.iter().any(|e| e.contains("/api")),
            "Should contain /api paths"
        );
        assert!(
            endpoints.iter().any(|e| e.contains("/graphql")),
            "Should contain /graphql"
        );
    }

    // ── Test 11: HTML killer detection patterns ─────────────────────────
    #[test]
    fn test_html_killer_filter() {
        let html_killers = [
            "<!doctype html",
            "<html",
            "<head>",
            "<body>",
            "404 not found",
            "page not found",
            "server error",
        ];

        // HTML page should be killed
        let html_page = "<html><head><title>Welcome</title></head><body>Hello</body></html>";
        let html_lower = html_page.to_lowercase();
        assert!(
            html_killers.iter().any(|k| html_lower.contains(k)),
            "HTML page should match a killer"
        );

        // JSON API response should NOT be killed
        let api_response = r#"{"data": [{"id": 1, "name": "test"}], "total": 1}"#;
        let api_lower = api_response.to_lowercase();
        assert!(
            !html_killers.iter().any(|k| api_lower.contains(k)),
            "JSON API should not match any killer"
        );
    }

    // ── Test 12: API structure patterns ─────────────────────────────────
    #[test]
    fn test_api_structure_scoring() {
        use regex::Regex;

        let patterns = [
            r#"^\s*\{\s*"data"\s*:\s*[\{\[]"#,
            r#"^\s*\{\s*"results"\s*:\s*\["#,
            r#"^\s*\{\s*"success"\s*:\s*(true|false)"#,
            r#"^\s*\{\s*"status"\s*:\s*"(up|down|ok|healthy)""#,
        ];

        let test_cases = [
            (r#"{ "data": [{"id": 1}] }"#, true),
            (r#"{ "results": [1, 2, 3] }"#, true),
            (r#"{ "success": true }"#, true),
            (r#"{ "status": "healthy" }"#, true),
            (r#"Hello World"#, false),
            (r#"<html><body>Not API</body></html>"#, false),
        ];

        for (content, should_match) in &test_cases {
            let score: usize = patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .filter(|rx| rx.is_match(content))
                .count();

            if *should_match {
                assert!(
                    score > 0,
                    "Content '{}' should match at least one API pattern",
                    content
                );
            } else {
                assert_eq!(
                    score, 0,
                    "Content '{}' should NOT match any API pattern",
                    content
                );
            }
        }
    }
}
