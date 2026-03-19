#[cfg(feature = "advanced-content-scanner")]
#[tokio::test]
async fn test_scan_content() {
    use web_analyzer::advanced_content_scanner::scan_content;
    
    let result = scan_content("example.com").await;
    assert!(result.is_ok(), "Failed to scan content: {:?}", result.err());
    
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    // Usually example.com has no AWS secrets!
    assert_eq!(info.secrets_found.len(), 0);
    assert_eq!(info.vulnerabilities_found.len(), 0);
    
    println!("Resolved advanced_content_scanner for example.com");
}
