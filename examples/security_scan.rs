//! Security posture assessment example.
//!
//! Run with:
//! ```bash
//! cargo run --example security_scan --all-features
//! ```

use web_analyzer::security_analysis::analyze_security;

#[tokio::main]
async fn main() {
    let domain = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());

    println!("🛡️  Security scan: {}\n", domain);

    match analyze_security(&domain).await {
        Ok(report) => {
            println!("━━━ WAF Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Detected:  {}", report.waf_detection.detected);
            if let Some(ref primary) = report.waf_detection.primary_waf {
                println!("  Provider:  {}", primary.provider);
            }

            println!();
            println!("━━━ SSL Analysis ━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Available: {}", report.ssl_analysis.ssl_available);
            println!("  Grade:     {}", report.ssl_analysis.overall_grade);
            println!(
                "  Protocol:  {}",
                report
                    .ssl_analysis
                    .protocol_version
                    .as_deref()
                    .unwrap_or("N/A")
            );

            println!();
            println!("━━━ Security Score ━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Score:     {}/100", report.security_score.overall_score);
            println!("  Grade:     {}", report.security_score.grade);

            let json = serde_json::to_string_pretty(&report).unwrap();
            println!("\n━━━ Full JSON ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("{}", json);
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
