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
        let event_copy = event.to_string();
        let data_copy = data.clone();

        // Spawn a background task for the actual analysis to avoid blocking the WS worker
        let handle = tokio::spawn(async move {
            match event_copy.as_str() {
                #[cfg(feature = "domain-info")]
                "domain_info" => {
                    let domain = s(&data_copy, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::domain_info::get_domain_info(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "domain-dns")]
                "domain_dns" => {
                    let domain = s(&data_copy, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::domain_dns::get_dns_records(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "security-analysis")]
                "security_analysis" => {
                    let domain = s(&data_copy, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::security_analysis::analyze_security(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "seo-analysis")]
                "seo_analysis" => {
                    let domain = s(&data_copy, "domain"); // or URL, usually SEO takes domain / url
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::seo_analysis::analyze_advanced_seo(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "subdomain-discovery")]
                "subdomain_discovery" => {
                    let domain = s(&data_copy, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::subdomain_discovery::discover_subdomains(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                #[cfg(feature = "api-security-scanner")]
                "api_security_scan" => {
                    let domain = s(&data_copy, "domain");
                    if domain.is_empty() { return Err(anyhow::anyhow!("Missing 'domain' parameter")); }
                    let res = crate::api_security_scanner::scan_api_endpoints(&domain).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    Ok(serde_json::to_value(res)?)
                }
                _ => Err(anyhow::anyhow!("Unknown web-analyzer event or feature disabled: {}", event_copy)),
            }
        });

        match handle.await {
            Ok(result) => result,
            Err(e) => Err(anyhow::anyhow!("Task panicked or cancelled: {}", e)),
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
