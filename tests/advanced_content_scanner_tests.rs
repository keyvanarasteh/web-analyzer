#[cfg(feature = "advanced-content-scanner")]
#[tokio::test]
async fn test_scan_content() {
    use web_analyzer::advanced_content_scanner::scan_content;

    let result = scan_content("example.com").await;
    assert!(result.is_ok(), "Failed: {:?}", result.err());

    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    assert!(
        info.summary.total_urls_crawled >= 1,
        "Should crawl at least 1 page"
    );

    println!("advanced_content_scanner test passed:");
    println!("  URLs crawled: {}", info.summary.total_urls_crawled);
    println!("  JS files: {}", info.summary.total_js_files);
    println!("  API endpoints: {}", info.summary.total_api_endpoints);
    println!("  Secrets: {}", info.summary.secrets_count);
    println!("  JS vulns: {}", info.summary.js_vulnerabilities_count);
    println!(
        "  SSRF findings: {}",
        info.summary.ssrf_vulnerabilities_count
    );
}

#[cfg(feature = "advanced-content-scanner")]
#[test]
fn test_shannon_entropy() {
    let high = "aB3xZ9kL2mN7pQ4s";
    let low = "aaaaaaaaaaaaaaaa";

    fn entropy(data: &str) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for b in data.bytes() {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    let h_high = entropy(high);
    let h_low = entropy(low);

    assert!(
        h_high > 3.5,
        "High entropy string should be > 3.5, got {}",
        h_high
    );
    assert!(
        h_low < 1.0,
        "Low entropy string should be < 1.0, got {}",
        h_low
    );

    println!("entropy test passed: high={:.2}, low={:.2}", h_high, h_low);
}
