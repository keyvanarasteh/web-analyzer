#[cfg(feature = "contact-spy")]
#[tokio::test]
async fn test_contact_spy() {
    use web_analyzer::contact_spy::crawl_contacts;

    // We can use example.com, though it likely has no emails or social profiles
    let result = crawl_contacts("example.com", 1).await;
    assert!(
        result.is_ok(),
        "Failed to crawl contacts: {:?}",
        result.err()
    );

    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");
    assert_eq!(info.pages_scanned, 1);

    println!(
        "Resolved contact_spy for example.com -> {} emails found",
        info.emails.len()
    );
}
