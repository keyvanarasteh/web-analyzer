#[cfg(feature = "api-security-scanner")]
#[tokio::test]
async fn test_api_security_scanner() {
    use web_analyzer::api_security_scanner::scan_api_endpoints;
    
    let result = scan_api_endpoints("example.com").await;
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    assert!(info.total_paths_probed > 100, "Should probe 800+ API paths from payloads, got {}", info.total_paths_probed);
    
    println!("api_security_scanner test passed, probed {} paths, found {} endpoints",
        info.total_paths_probed, info.endpoints_found.len());
}
