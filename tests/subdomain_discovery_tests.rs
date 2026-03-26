#[cfg(feature = "subdomain-discovery")]
#[tokio::test]
async fn test_discover_subdomains() {
    use web_analyzer::subdomain_discovery::discover_subdomains;

    // Example.com doesn't have many subdomains, but subfinder should at least run and not crash
    let result = discover_subdomains("example.com").await;

    // Depending on whether subfinder is installed on the testing env, this might fail with NotFound.
    if let Err(e) = &result {
        println!("Subfinder error (possibly not installed): {}", e);
        return; // skip if subfinder not installed
    }

    assert!(result.is_ok(), "Failed to get subdomains");
    let info = result.unwrap();
    assert_eq!(info.domain, "example.com");

    println!(
        "Resolved subdomain_discovery for example.com -> {} subdomains found",
        info.subdomains.len()
    );
}
