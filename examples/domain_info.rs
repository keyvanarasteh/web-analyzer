//! Basic domain intelligence example.
//!
//! Run with:
//! ```bash
//! cargo run --example domain_info --all-features
//! ```

use web_analyzer::domain_info::get_domain_info;

#[tokio::main]
async fn main() {
    let domain = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());

    println!("🔍 Analyzing domain: {}\n", domain);

    match get_domain_info(&domain).await {
        Ok(info) => {
            println!("━━━ Domain Intelligence ━━━━━━━━━━━━━━━━━━━━");
            println!("  Domain:       {}", info.domain);
            println!("  IPv4:         {}", info.ipv4.as_deref().unwrap_or("N/A"));
            println!("  Web Server:   {}", info.web_server.as_deref().unwrap_or("N/A"));
            println!("  Open Ports:   {:?}", info.open_ports);
            println!();
            println!("━━━ WHOIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Registrar:    {}", info.whois.registrar);
            println!("  Created:      {}", info.whois.creation_date);
            println!("  Expires:      {}", info.whois.expiry_date);
            println!("  Privacy:      {}", info.whois.privacy_protection);
            println!();
            println!("━━━ SSL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  Status:       {}", info.ssl.status);
            println!("  Issued To:    {}", info.ssl.issued_to.as_deref().unwrap_or("N/A"));
            println!("  Issuer:       {}", info.ssl.issuer.as_deref().unwrap_or("N/A"));
            println!("  Protocol:     {}", info.ssl.protocol_version.as_deref().unwrap_or("N/A"));
            println!();
            println!("━━━ Security ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("  HTTPS:        {}", info.security.https_available);
            println!("  HTTPS Redir:  {}", info.security.https_redirect);
            println!("  Sec Headers:  {}/{}", info.security.headers_count, 5);
            println!("  Score:        {}/100", info.security_score);
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
