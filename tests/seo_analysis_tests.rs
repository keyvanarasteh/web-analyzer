#[cfg(feature = "seo-analysis")]
#[tokio::test]
async fn test_analyze_advanced_seo() {
    use web_analyzer::seo_analysis::analyze_advanced_seo;
    
    let result = analyze_advanced_seo("example.com").await;
    assert!(result.is_ok(), "Failed to get SEO analysis: {:?}", result.err());
    
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    
    // Example.com has a title
    assert!(info.title.contains("Example Domain"), "Title should be Example Domain");
    assert!(info.h1_count >= 1, "example.com should have an H1 tag");
    
    // It has very fast load time generally
    assert!(info.load_time_ms > 0);
    
    println!("Resolved seo_analysis for example.com -> {:?}", info);
}
