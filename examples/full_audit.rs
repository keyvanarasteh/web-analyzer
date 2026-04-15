//! Comprehensive multi-module audit example.
//!
//! Run with:
//! ```bash
//! cargo run --example full_audit --all-features
//! ```

use web_analyzer::domain_dns::get_dns_records;
use web_analyzer::domain_info::get_domain_info;
use web_analyzer::security_analysis::analyze_security;
use web_analyzer::seo_analysis::analyze_advanced_seo;
use web_analyzer::web_technologies::detect_web_technologies;

#[tokio::main]
async fn main() {
    let domain = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());

    println!("🔍 Full audit: {}\n", domain);

    // Run all analyses concurrently
    let (info, dns, security, seo, tech) = tokio::join!(
        get_domain_info(&domain, None),
        get_dns_records(&domain, None),
        analyze_security(&domain, None),
        analyze_advanced_seo(&domain, None),
        detect_web_technologies(&domain),
    );

    // Domain info
    if let Ok(ref info) = info {
        println!("━━━ Domain ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  IP:           {}", info.ipv4.as_deref().unwrap_or("N/A"));
        println!("  Registrar:    {}", info.whois.registrar);
        println!("  SSL Status:   {}", info.ssl.status);
        println!("  Score:        {}/100", info.security_score);
    } else {
        println!("⚠️  Domain info failed: {:?}", info.err());
    }

    println!();

    // DNS
    if let Ok(ref dns) = dns {
        println!("━━━ DNS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  A records:    {:?}", dns.records.a);
        println!("  MX records:   {:?}", dns.records.mx);
        println!("  NS records:   {:?}", dns.records.ns);
    }

    println!();

    // Security
    if let Ok(ref sec) = security {
        println!("━━━ Security ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(
            "  WAF:   {}",
            if sec.waf_detection.detected {
                sec.waf_detection
                    .primary_waf
                    .as_ref()
                    .map(|w| w.provider.as_str())
                    .unwrap_or("detected")
            } else {
                "none"
            }
        );
        println!("  SSL:   {}", sec.ssl_analysis.overall_grade);
        println!(
            "  Grade: {} ({}/100)",
            sec.security_score.grade, sec.security_score.overall_score
        );
    }

    println!();

    // SEO
    if let Ok(ref seo) = seo {
        println!("━━━ SEO ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(
            "  Title:      {} ({})",
            seo.basic_seo.title.text, seo.basic_seo.title.status
        );
        println!(
            "  Words:      {} ({})",
            seo.content_analysis.word_count, seo.content_analysis.word_count_status
        );
        println!(
            "  Score:      {}/{} ({})",
            seo.seo_score.score, seo.seo_score.max_score, seo.seo_score.grade
        );
    }

    println!();

    // Technologies
    if let Ok(ref tech) = tech {
        println!("━━━ Technologies ━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  Server:     {:?}", tech.web_server);
        println!("  Backend:    {:?}", tech.backend);
        println!("  Frontend:   {:?}", tech.frontend);
        println!("  CMS:        {:?}", tech.cms);
        println!("  CDN:        {:?}", tech.cdn);
        println!("  WordPress:  {}", tech.is_wordpress);
    }

    println!("\n✅ Audit complete");
}
