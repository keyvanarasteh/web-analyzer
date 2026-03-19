#[cfg(feature = "cloudflare-bypass")]
#[tokio::test]
async fn test_cloudflare_bypass() {
    use web_analyzer::cloudflare_bypass::find_real_ip;
    
    let result = find_real_ip("example.com").await;
    assert!(result.is_ok(), "Failed: {:?}", result.err());
    
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    // example.com is not behind Cloudflare
    assert!(!info.cloudflare_protected);
    
    println!("cloudflare_bypass test passed, found {} IPs", info.found_ips.len());
}
