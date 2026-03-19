#[cfg(feature = "cloudflare-bypass")]
#[tokio::test]
async fn test_cloudflare_bypass() {
    use web_analyzer::cloudflare_bypass::find_real_ip;
    
    let result = find_real_ip("example.com").await;
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    
    println!(
        "cloudflare_bypass test passed, protected={}, found {} IPs",
        info.cloudflare_protected,
        info.found_ips.len()
    );
}
