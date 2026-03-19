#[cfg(feature = "web-technologies")]
#[tokio::test]
async fn test_detect_web_technologies() {
    use web_analyzer::web_technologies::detect_web_technologies;
    
    let result = detect_web_technologies("example.com").await;
    assert!(result.is_ok(), "Failed to get web tech analysis: {:?}", result.err());
    
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    
    // Example.com server header usually says ECS or some standard string but we just assume it exists
    assert!(!info.web_server.is_empty(), "web_server field should be populated");
    
    println!("Resolved web_technologies for example.com -> {:?}", info);
}
