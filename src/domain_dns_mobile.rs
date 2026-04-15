use serde::{Deserialize, Serialize};

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

use chrono::Utc;
use hickory_resolver::config::*;
use hickory_resolver::AsyncResolver;
use std::time::Instant;

pub async fn get_dns_records(
    domain: &str,
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<DomainDnsResult, Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();

    if let Some(t) = &progress_tx {
        let _ = t
            .send(crate::ScanProgress {
                module: "DNS Records".into(),
                percentage: 10.0,
                message: "Initializing native DNS resolver".into(),
                status: "Info".into(),
            })
            .await;
    }

    // Using Google or Cloudflare as fallback
    let resolver = AsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

    let mut records_meta = DnsRecords {
        a: vec![],
        aaaa: vec![],
        mx: vec![],
        ns: vec![],
        soa: vec![],
        txt: vec![],
        cname: vec![],
    };

    if let Some(t) = &progress_tx {
        let _ = t
            .send(crate::ScanProgress {
                module: "DNS Records".into(),
                percentage: 30.0,
                message: "Looking up A and AAAA records".into(),
                status: "Info".into(),
            })
            .await;
    }

    if let Ok(response) = resolver.ipv4_lookup(domain).await {
        for ip in response.iter() {
            records_meta.a.push(ip.to_string());
        }
    }

    if let Ok(response) = resolver.ipv6_lookup(domain).await {
        for ip in response.iter() {
            records_meta.aaaa.push(ip.to_string());
        }
    }

    if let Some(t) = &progress_tx {
        let _ = t
            .send(crate::ScanProgress {
                module: "DNS Records".into(),
                percentage: 50.0,
                message: "Looking up MX and NS records".into(),
                status: "Info".into(),
            })
            .await;
    }

    if let Ok(response) = resolver.mx_lookup(domain).await {
        for mx in response.iter() {
            records_meta.mx.push(format!("{} {}", mx.preference(), mx.exchange()));
        }
    }

    if let Ok(response) = resolver.ns_lookup(domain).await {
        for ns in response.iter() {
            records_meta.ns.push(ns.to_string());
        }
    }

    if let Some(t) = &progress_tx {
        let _ = t
            .send(crate::ScanProgress {
                module: "DNS Records".into(),
                percentage: 70.0,
                message: "Looking up TXT records".into(),
                status: "Info".into(),
            })
            .await;
    }

    if let Ok(response) = resolver.txt_lookup(domain).await {
        for txt in response.iter() {
            records_meta.txt.push(txt.to_string());
        }
    }

    if let Some(t) = &progress_tx {
        let _ = t
            .send(crate::ScanProgress {
                module: "DNS Records".into(),
                percentage: 90.0,
                message: "Looking up CNAME and SOA records".into(),
                status: "Info".into(),
            })
            .await;
    }

    use hickory_resolver::proto::rr::RecordType;

    if let Ok(response) = resolver.lookup(domain, RecordType::CNAME).await {
        for record in response.iter() {
            if let Some(cname) = record.as_cname() {
                records_meta.cname.push(cname.to_string());
            }
        }
    }

    if let Ok(response) = resolver.lookup(domain, RecordType::SOA).await {
        for record in response.iter() {
            if let Some(soa) = record.as_soa() {
                records_meta.soa.push(format!("{} {}", soa.mname(), soa.rname()));
            }
        }
    }

    let response_time_ms = start_time.elapsed().as_millis();

    if let Some(t) = &progress_tx {
        let _ = t
            .send(crate::ScanProgress {
                module: "DNS Records".into(),
                percentage: 100.0,
                message: "DNS analysis completed successfully".into(),
                status: "Info".into(),
            })
            .await;
    }

    Ok(DomainDnsResult {
        timestamp: Utc::now().to_rfc3339(),
        domain: domain.to_string(),
        records: records_meta,
        response_time_ms,
    })
}
