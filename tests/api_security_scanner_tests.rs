#[cfg(feature = "api-security-scanner")]
#[tokio::test]
async fn test_api_security_scanner() {
    use web_analyzer::api_security_scanner::scan_api_endpoints;
    
    let result = scan_api_endpoints("example.com").await;
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    
    println!("api_security_scanner test passed, found {} endpoints", info.endpoints_found.len());
}
