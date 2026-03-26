#[cfg(feature = "domain-info")]
#[tokio::test]
async fn test_get_domain_info_basic() {
    use web_analyzer::domain_info::get_domain_info;

    let result = get_domain_info("example.com").await;
    assert!(
        result.is_ok(),
        "Failed to get domain info: {:?}",
        result.err()
    );

    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");

    // example.com should have A records (IPv4)
    assert!(info.ipv4.is_some(), "Should have resolved an IPv4 address");
    assert!(
        !info.all_ipv4.is_empty(),
        "Should have at least one IPv4 in all_ipv4"
    );

    // It should also have IPv6
    assert!(
        !info.ipv6.is_empty(),
        "Should have resolved an IPv6 address for example.com"
    );

    // It might or might not have MX or TXT, but we can check it doesn't crash.
    println!("Resolved example.com -> {:?}", info);
}
