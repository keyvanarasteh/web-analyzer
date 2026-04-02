#[cfg(feature = "subdomain-takeover")]
#[tokio::test]
async fn test_subdomain_takeover() {
    use web_analyzer::subdomain_takeover::check_subdomain_takeover;

    // Test with empty subdomain list (basic smoke test)
    let result = check_subdomain_takeover("example.com", &[]).await;
    assert!(result.is_ok(), "Failed: {:?}", result.err());

    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    assert_eq!(info.statistics.subdomains_scanned, 0);
    assert!(info.vulnerable.is_empty());

    println!("subdomain_takeover smoke test passed");
}
