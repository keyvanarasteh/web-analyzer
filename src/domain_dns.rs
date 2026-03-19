use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecords {
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub soa: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDnsResult {
    pub timestamp: String,
    pub domain: String,
    pub records: DnsRecords,
    pub response_time_ms: u128,
}

pub async fn get_dns_records(domain: &str) -> Result<DomainDnsResult, Box<dyn std::error::Error + Send + Sync>> {
    // Initialize the resolver with default config
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    
    let start_time = Instant::now();
    let mut records = DnsRecords {
        a: vec![],
        aaaa: vec![],
        mx: vec![],
        ns: vec![],
        soa: vec![],
    };

    // Resolving all concurrently could be faster, but sequentially is robust and fast enough for initial port.
    if let Ok(response) = resolver.ipv4_lookup(domain).await {
        for ip in response.iter() {
            records.a.push(ip.to_string());
        }
    }
    
    if let Ok(response) = resolver.ipv6_lookup(domain).await {
        for ip in response.iter() {
            records.aaaa.push(ip.to_string());
        }
    }
    
    if let Ok(response) = resolver.mx_lookup(domain).await {
        for mx in response.iter() {
            records.mx.push(format!("{} {}", mx.preference(), mx.exchange()));
        }
    }
    
    if let Ok(response) = resolver.ns_lookup(domain).await {
        for ns in response.iter() {
            records.ns.push(ns.to_string());
        }
    }
    
    if let Ok(response) = resolver.soa_lookup(domain).await {
        for soa in response.iter() {
            records.soa.push(format!("{} {}", soa.mname(), soa.rname()));
        }
    }

    let duration = start_time.elapsed().as_millis();

    Ok(DomainDnsResult {
        timestamp: chrono::Utc::now().to_rfc3339(),
        domain: domain.to_string(),
        records,
        response_time_ms: duration,
    })
}
