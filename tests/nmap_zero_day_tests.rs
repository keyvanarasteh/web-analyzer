#[cfg(feature = "nmap-zero-day")]
#[tokio::test]
async fn test_nmap_scan() {
    use web_analyzer::nmap_zero_day::run_nmap_scan;

    // Check if nmap is installed
    let nmap_check = tokio::process::Command::new("which")
        .arg("nmap")
        .output()
        .await;

    if nmap_check.map(|o| o.status.success()).unwrap_or(false) {
        let result = run_nmap_scan("example.com", None).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());

        let info = result.unwrap();
        assert_eq!(info.domain, "example.com");
        println!(
            "nmap_zero_day test passed, found {} open ports",
            info.open_ports.len()
        );
    } else {
        println!("nmap not installed, skipping test");
    }
}
