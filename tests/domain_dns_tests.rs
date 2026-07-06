#[cfg(feature = "domain-dns")]
#[tokio::test]
async fn test_get_dns_records() {
    use web_analyzer::domain_dns::get_dns_records;

    let result = get_dns_records("example.com", None).await;
    assert!(
        result.is_ok(),
        "Failed to get DNS records: {:?}",
        result.err()
    );

    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");

    // Ensure A records exist for example.com
    assert!(!info.records.a.is_empty(), "Missing A records");
    // Ensure NS records exist
    assert!(!info.records.ns.is_empty(), "Missing NS records");

    println!("Resolved domain-dns for example.com -> {:?}", info);
}
