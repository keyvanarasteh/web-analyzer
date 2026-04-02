#[cfg(feature = "seo-analysis")]
#[tokio::test]
async fn test_analyze_advanced_seo() {
    use web_analyzer::seo_analysis::analyze_advanced_seo;

    let result = analyze_advanced_seo("example.com").await;
    assert!(
        result.is_ok(),
        "Failed to get SEO analysis: {:?}",
        result.err()
    );

    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");

    // Example.com has a title
    assert!(
        info.basic_seo.title.text.contains("Example Domain"),
        "Title should be Example Domain"
    );

    // SEO score should be calculated
    assert!(info.seo_score.score > 0);

    println!("Resolved seo_analysis for example.com -> {:?}", info);
}
