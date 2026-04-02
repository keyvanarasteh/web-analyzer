use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::process::Command;

// ── Structs ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecords {
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub soa: Vec<String>,
    pub txt: Vec<String>,
    pub cname: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDnsResult {
    pub timestamp: String,
    pub domain: String,
    pub records: DnsRecords,
    pub response_time_ms: u128,
}

// ── DNS resolution via dig ──────────────────────────────────────────────────

async fn resolve_record(domain: &str, record_type: &str) -> Vec<String> {
    if let Ok(output) = Command::new("dig")
        .arg("+short")
        .arg(record_type)
        .arg(domain)
        .output()
        .await
    {
        if let Ok(text) = String::from_utf8(output.stdout) {
            return text
                .lines()
                .filter_map(|s| {
                    let s = s.trim();
                    if !s.is_empty() && !s.starts_with(';') {
                        Some(s.to_string())
                    } else {
                        None
                    }
                })
                .collect();
        }
    }
    vec![]
}

// ── Main function ───────────────────────────────────────────────────────────

pub async fn get_dns_records(
    domain: &str,
) -> Result<DomainDnsResult, Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();

    // Run all 7 record types concurrently
    let (a, aaaa, mx, ns, soa, txt, cname) = tokio::join!(
        resolve_record(domain, "A"),
        resolve_record(domain, "AAAA"),
        resolve_record(domain, "MX"),
        resolve_record(domain, "NS"),
        resolve_record(domain, "SOA"),
        resolve_record(domain, "TXT"),
        resolve_record(domain, "CNAME"),
    );

    let duration = start_time.elapsed().as_millis();

    Ok(DomainDnsResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        domain: domain.to_string(),
        records: DnsRecords {
            a,
            aaaa,
            mx,
            ns,
            soa,
            txt,
            cname,
        },
        response_time_ms: duration,
    })
}
