#[test]
fn test_payload_loading() {
    use web_analyzer::payloads;

    // Verify all payload files embedded correctly
    let sql = payloads::lines(payloads::SQL_INJECTION);
    assert!(
        !sql.is_empty(),
        "SQL injection payloads should not be empty"
    );
    assert!(
        sql.len() >= 20,
        "Expected 20+ SQL payloads, got {}",
        sql.len()
    );

    let xss = payloads::lines(payloads::XSS);
    assert!(
        xss.len() >= 20,
        "Expected 20+ XSS payloads, got {}",
        xss.len()
    );

    let ssrf = payloads::lines(payloads::SSRF);
    assert!(
        ssrf.len() >= 25,
        "Expected 25+ SSRF payloads, got {}",
        ssrf.len()
    );

    let xxe = payloads::lines(payloads::XXE);
    assert!(!xxe.is_empty(), "XXE payloads should not be empty");

    let cmd = payloads::lines(payloads::COMMAND_INJECTION);
    assert!(
        cmd.len() >= 20,
        "Expected 20+ command injection payloads, got {}",
        cmd.len()
    );

    let lfi = payloads::lines(payloads::LFI);
    assert!(
        lfi.len() >= 20,
        "Expected 20+ LFI payloads, got {}",
        lfi.len()
    );

    let nosql = payloads::lines(payloads::NOSQL_INJECTION);
    assert!(
        nosql.len() >= 15,
        "Expected 15+ NoSQL payloads, got {}",
        nosql.len()
    );

    let ssti = payloads::lines(payloads::SSTI);
    assert!(
        ssti.len() >= 20,
        "Expected 20+ SSTI payloads, got {}",
        ssti.len()
    );

    let auth = payloads::auth_headers(payloads::AUTH_BYPASS_HEADERS);
    assert!(
        auth.len() >= 20,
        "Expected 20+ auth bypass headers, got {}",
        auth.len()
    );

    let api = payloads::lines(payloads::API_ENDPOINTS);
    assert!(
        api.len() >= 500,
        "Expected 500+ API endpoints, got {}",
        api.len()
    );

    println!("All 10 payload files loaded successfully:");
    println!("  SQL injection: {} payloads", sql.len());
    println!("  XSS: {} payloads", xss.len());
    println!("  SSRF: {} probe URLs", ssrf.len());
    println!("  XXE: {} payloads", xxe.len());
    println!("  Command injection: {} payloads", cmd.len());
    println!("  LFI: {} paths", lfi.len());
    println!("  NoSQL injection: {} payloads", nosql.len());
    println!("  SSTI: {} payloads", ssti.len());
    println!("  Auth bypass: {} headers", auth.len());
    println!("  API endpoints: {} paths", api.len());
}
