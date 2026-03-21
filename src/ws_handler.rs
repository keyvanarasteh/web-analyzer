use async_trait::async_trait;
use qicro_data_core::ws_handler::WsMessageHandler;
use qicro_data_core::ws_server::WebSocketServer;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{debug, warn};

pub struct WebAnalyzerMessageHandler {
    fallback: Arc<dyn WsMessageHandler + Send + Sync>,
}

impl WebAnalyzerMessageHandler {
    pub fn new(fallback: Arc<dyn WsMessageHandler + Send + Sync>) -> Self {
        Self { fallback }
    }

    async fn dispatch(
        &self,
        event: &str,
        data: &Value,
    ) -> anyhow::Result<Value> {
        match event {
                // ── Intelligence Gathering ────────────────────────────────
                #[cfg(feature = "domain-info")]
                "domain_info" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::domain_info::get_domain_info(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "domain-dns")]
                "domain_dns" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::domain_dns::get_dns_records(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "seo-analysis")]
                "seo_analysis" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::seo_analysis::analyze_advanced_seo(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "web-technologies")]
                "web_technologies" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::web_technologies::detect_web_technologies(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "domain-validator")]
                "domain_validate" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::domain_validator::validate_domain(&domain).await;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "domain-validator")]
                "domain_validate_bulk" => {
                    let domains: Vec<String> = data.get("domains")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    if domains.is_empty() { return Err(anyhow::anyhow!("Missing 'domains' array parameter")); }
                    let res = crate::domain_validator::validate_domains_bulk(&domains, 10).await;
                    Ok(serde_json::to_value(res)?)
                }

                // ── Reconnaissance ────────────────────────────────────────
                #[cfg(feature = "subdomain-discovery")]
                "subdomain_discovery" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::subdomain_discovery::discover_subdomains(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "contact-spy")]
                "contact_spy" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let max_pages: usize = data.get("max_pages").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                    let res = crate::contact_spy::crawl_contacts(&domain, max_pages).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "advanced-content-scanner")]
                "content_scan" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::advanced_content_scanner::scan_content(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }

                // ── Security Assessment ───────────────────────────────────
                #[cfg(feature = "security-analysis")]
                "security_analysis" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::security_analysis::analyze_security(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "subdomain-takeover")]
                "subdomain_takeover" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let subdomains: Vec<String> = data.get("subdomains")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    if subdomains.is_empty() { return Err(anyhow::anyhow!("Missing 'subdomains' array parameter")); }
                    let res = crate::subdomain_takeover::check_subdomain_takeover(&domain, &subdomains).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "cloudflare-bypass")]
                "cloudflare_bypass" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::cloudflare_bypass::find_real_ip(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "nmap-zero-day")]
                "nmap_scan" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::nmap_zero_day::run_nmap_scan(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "api-security-scanner")]
                "api_security_scan" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::api_security_scanner::scan_api_endpoints(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "geo-analysis")]
                "geo_analysis" => {
                    let domain = s(data, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::geo_analysis::analyze_geo(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                _ => Err(anyhow::anyhow!("Unknown web-analyzer event or feature disabled: {}", event)),
            }
    }
}

#[async_trait]
impl WsMessageHandler for WebAnalyzerMessageHandler {
    async fn handle_text(
        &self,
        addr: SocketAddr,
        text: &str,
        server: &WebSocketServer,
        user_id: Option<u64>,
        browser_id: Option<String>,
    ) -> anyhow::Result<bool> {
        let msg: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => return self.fallback.handle_text(addr, text, server, user_id, browser_id).await,
        };

        let Some(channel) = msg.get("channel").and_then(|v| v.as_str()) else {
            return self.fallback.handle_text(addr, text, server, user_id, browser_id).await;
        };

        if channel != "web-analyzer" {
            return self.fallback.handle_text(addr, text, server, user_id, browser_id).await;
        }

        let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or("");
        let data = msg.get("data").cloned().unwrap_or(json!({}));
        let request_id = msg.get("request_id").and_then(|v| v.as_str()).map(String::from);

        debug!(addr = %addr, channel, event, "WebAnalyzer WS command");

        let result = self.dispatch(event, &data).await;

        let response = match result {
            Ok(resp_data) => {
                let mut r = json!({
                    "channel": channel,
                    "event": format!("{event}_result"),
                    "success": true,
                    "data": resp_data,
                });
                if let Some(ref rid) = request_id {
                    r.as_object_mut().unwrap().insert("request_id".to_string(), json!(rid));
                }
                r
            }
            Err(e) => {
                warn!(addr = %addr, channel, event, error = %e, "WebAnalyzer WS error");
                let mut r = json!({
                    "channel": channel,
                    "event": format!("{event}_result"),
                    "success": false,
                    "error": e.to_string(),
                });
                if let Some(ref rid) = request_id {
                    r.as_object_mut().unwrap().insert("request_id".to_string(), json!(rid));
                }
                r
            }
        };

        let _ = server.send_to(addr, Message::Text(response.to_string().into())).await;
        Ok(true)
    }

    async fn handle_binary(
        &self,
        addr: SocketAddr,
        data: &[u8],
        server: &WebSocketServer,
        user_id: Option<u64>,
        browser_id: Option<String>,
    ) -> anyhow::Result<bool> {
        self.fallback.handle_binary(addr, data, server, user_id, browser_id).await
    }

    fn on_disconnect(&self, addr: &SocketAddr) {
        self.fallback.on_disconnect(addr);
    }
}

// ── Helpers ───────────────────────────────────────────────────────
fn s(data: &Value, key: &str) -> String {
    data.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}
