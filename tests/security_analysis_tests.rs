#[cfg(feature = "security-analysis")]
#[tokio::test]
async fn test_analyze_security() {
    use web_analyzer::security_analysis::analyze_security;
    
    let result = analyze_security("example.com").await;
    assert!(result.is_ok(), "Failed to analyze security: {:?}", result.err());
    
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    assert!(info.https_available);
    
    println!("Resolved security_analysis for example.com");
}
