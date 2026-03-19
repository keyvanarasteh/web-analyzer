use serde::{Deserialize, Serialize};
use tokio::process::Command;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapScanResult {
    pub domain: String,
    pub ip: String,
    pub open_ports: Vec<PortInfo>,
}

/// Runs nmap scan using the system nmap binary (must be installed).
pub async fn run_nmap_scan(domain: &str) -> Result<NmapScanResult, Box<dyn std::error::Error + Send + Sync>> {
    // Resolve IP
    let ip = tokio::net::lookup_host(format!("{}:80", domain))
        .await?
        .next()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| domain.to_string());

    // Run nmap with service version detection on top 1000 ports
    let output = Command::new("nmap")
        .args(["-sV", "-Pn", "-T4", "--top-ports", "1000", "-oG", "-", &ip])
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut open_ports = Vec::new();

    // Parse grepable output
    for line in stdout.lines() {
        if !line.contains("Ports:") {
            continue;
        }
        // Format: Host: x.x.x.x ()  Ports: 22/open/tcp//ssh//OpenSSH 8.9/, 80/open/tcp//http//nginx/
        if let Some(ports_section) = line.split("Ports: ").nth(1) {
            for port_entry in ports_section.split(',') {
                let parts: Vec<&str> = port_entry.trim().split('/').collect();
                if parts.len() >= 5 && parts[1].trim() == "open" {
                    let port: u16 = parts[0].trim().parse().unwrap_or(0);
                    let service = parts[4].trim().to_string();
                    let version = if parts.len() > 6 { parts[6].trim().to_string() } else { String::new() };
                    open_ports.push(PortInfo {
                        port,
                        state: "open".into(),
                        service,
                        version,
                    });
                }
            }
        }
    }

    Ok(NmapScanResult {
        domain: domain.to_string(),
        ip,
        open_ports,
    })
}
