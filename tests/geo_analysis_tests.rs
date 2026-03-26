#[cfg(feature = "geo-analysis")]
#[tokio::test]
async fn test_geo_analysis() {
    use web_analyzer::geo_analysis::analyze_geo;

    let result = analyze_geo("example.com").await;
    assert!(result.is_ok(), "Failed: {:?}", result.err());

    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    assert!(!info.ai_crawler_directives.bots.is_empty());

    println!(
        "geo_analysis test passed, score: {}, grade: {}",
        info.geo_score, info.geo_grade
    );
}
