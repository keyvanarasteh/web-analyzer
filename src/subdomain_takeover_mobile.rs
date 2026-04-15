use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCheckResult {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub has_valid_dns: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverVulnerability {
    pub subdomain: String,
    pub service: String,
    pub vulnerability_type: String,
    pub cname: Option<String>,
    pub confidence: String,
    pub description: String,
    pub exploitation_difficulty: String,
    pub mitigation: String,
    pub dns_info: DnsCheckResult,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub subdomains_scanned: usize,
    pub vulnerable_count: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub scan_time_secs: f64,
    pub services_checked: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverResult {
    pub domain: String,
    pub statistics: ScanStatistics,
    pub vulnerable: Vec<TakeoverVulnerability>,
}

use hickory_resolver::config::*;
use hickory_resolver::AsyncResolver;
use std::time::Instant;
use tokio::task::JoinSet;

pub async fn check_subdomain_takeover(
    domain: &str,
    subdomains: &[String],
    progress_tx: Option<tokio::sync::mpsc::Sender<crate::ScanProgress>>,
) -> Result<TakeoverResult, Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();
    let resolver = AsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

    if let Some(t) = &progress_tx {
        let _ = t.send(crate::ScanProgress {
            module: "Subdomain Takeover".into(),
            percentage: 10.0,
            message: format!("Checking {} subdomains for dangling CNAMEs natively", subdomains.len()),
            status: "Info".into(),
        }).await;
    }

    let mut vulnerable_list = Vec::new();
    let mut set = JoinSet::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(10));

    for d in subdomains {
        let subdomain = d.clone();
        let res = resolver.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        set.spawn(async move {
            use hickory_resolver::proto::rr::RecordType;
            let mut cname_records = vec![];
            let mut a_records = vec![];

            if let Ok(response) = res.lookup(subdomain.as_str(), RecordType::CNAME).await {
                for record in response.iter() {
                    if let Some(cname) = record.as_cname() {
                        cname_records.push(cname.to_string());
                    }
                }
            }
            
            if let Ok(response) = res.ipv4_lookup(subdomain.as_str()).await {
                for ip in response.iter() {
                    a_records.push(ip.to_string());
                }
            }

            let result = if !cname_records.is_empty() && a_records.is_empty() {
                Some(TakeoverVulnerability {
                    subdomain: subdomain.clone(),
                    service: "Unknown".into(),
                    vulnerability_type: "Dangling CNAME".into(),
                    cname: Some(cname_records[0].clone()),
                    confidence: "High".into(),
                    description: format!("CNAME points to {} which doesn't resolve to an IP.", cname_records[0]),
                    exploitation_difficulty: "Medium".into(),
                    mitigation: "Remove the DNS record or claim the external resource.".into(),
                    dns_info: DnsCheckResult {
                        a_records,
                        aaaa_records: vec![],
                        cname_records,
                        mx_records: vec![],
                        txt_records: vec![],
                        ns_records: vec![],
                        has_valid_dns: true,
                    },
                    http_status: None,
                })
            } else {
                None
            };
            drop(permit);
            result
        });
    }

    let mut scanned = 0;
    while let Some(vuln_opt) = set.join_next().await {
        scanned += 1;
        if let Ok(Some(v)) = vuln_opt {
            vulnerable_list.push(v);
        }
    }

    if let Some(t) = &progress_tx {
        let _ = t.send(crate::ScanProgress {
            module: "Subdomain Takeover".into(),
            percentage: 100.0,
            message: "Finished native CNAME checking".into(),
            status: "Info".into(),
        }).await;
    }

    Ok(TakeoverResult {
        domain: domain.to_string(),
        statistics: ScanStatistics {
            subdomains_scanned: scanned,
            vulnerable_count: vulnerable_list.len(),
            high_confidence: vulnerable_list.len(),
            medium_confidence: 0,
            low_confidence: 0,
            scan_time_secs: start_time.elapsed().as_secs_f64(),
            services_checked: 0,
        },
        vulnerable: vulnerable_list,
    })
}
