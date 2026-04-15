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
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<DomainDnsResult, Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();

    if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain DNS".into(), percentage: 5.0, message: "Starting parallel DNS resolution...".into(), status: "Info".into() }).await; }

    // Run all 7 record types concurrently
    let (a, aaaa, mx, ns, soa, txt, cname) = tokio::join!(
        async {
            let res = resolve_record(domain, "A").await;
            if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain DNS".into(), percentage: 15.0, message: "Resolved A records".into(), status: "Success".into() }).await; }
            res
        },
        async {
            let res = resolve_record(domain, "AAAA").await;
            if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain DNS".into(), percentage: 30.0, message: "Resolved AAAA records".into(), status: "Success".into() }).await; }
            res
        },
        async {
            let res = resolve_record(domain, "MX").await;
            if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain DNS".into(), percentage: 45.0, message: "Resolved MX records".into(), status: "Success".into() }).await; }
            res
        },
        async {
            let res = resolve_record(domain, "NS").await;
            if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain DNS".into(), percentage: 60.0, message: "Resolved NS records".into(), status: "Success".into() }).await; }
            res
        },
        async {
            let res = resolve_record(domain, "SOA").await;
            if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain DNS".into(), percentage: 75.0, message: "Resolved SOA records".into(), status: "Success".into() }).await; }
            res
        },
        async {
            let res = resolve_record(domain, "TXT").await;
            if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain DNS".into(), percentage: 90.0, message: "Resolved TXT records".into(), status: "Success".into() }).await; }
            res
        },
        async {
            let res = resolve_record(domain, "CNAME").await;
            if let Some(t) = &progress_tx { let _ = t.send(crate::ScanProgress { module: "Domain DNS".into(), percentage: 100.0, message: "Resolved CNAME records".into(), status: "Success".into() }).await; }
            res
        },
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
