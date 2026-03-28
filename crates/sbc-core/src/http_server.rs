//! HTTP Server — REST API + Prometheus endpoint
//!
//! Implémente un vrai serveur HTTP via axum pour exposer :
//! - REST API de gestion (trunks, appels, stats)
//! - Endpoint Prometheus /metrics
//! - Health checks /health + /ready
//!
//! Le serveur écoute sur 127.0.0.1:8080 par défaut (pas exposé publiquement).

use crate::api::ApiRouter;
use crate::b2bua::B2buaManager;
use crate::metrics::SbcMetrics;
use crate::register::Registrar;
use crate::routing::TrunkManager;
use crate::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// Configuration du serveur HTTP
#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    pub bind_address: SocketAddr,
    pub auth_token: Option<String>,
    pub cors_enabled: bool,
}

impl HttpServerConfig {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            bind_address: addr,
            auth_token: None,
            cors_enabled: false,
        }
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.auth_token = Some(token);
        self
    }
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self::new("127.0.0.1:8080".parse().unwrap())
    }
}

/// Serveur HTTP gérant l'API REST et Prometheus
pub struct HttpServer {
    config: HttpServerConfig,
    router: Arc<ApiRouter>,
}

impl HttpServer {
    pub fn new(
        config: HttpServerConfig,
        metrics: Arc<SbcMetrics>,
        b2bua: Arc<B2buaManager>,
        trunks: Arc<TrunkManager>,
    ) -> Self {
        let router = Arc::new(ApiRouter::new(metrics, b2bua, trunks));
        Self { config, router }
    }

    pub fn with_registrar(mut self, registrar: Arc<dyn Registrar>) -> Self {
        // Re-create router with registrar — Arc::get_mut only works if we're the sole owner
        if let Some(router) = Arc::get_mut(&mut self.router) {
            router.registrar = Some(registrar);
        }
        self
    }

    /// Démarrer le serveur HTTP en arrière-plan
    pub async fn start(self) -> Result<()> {
        let addr = self.config.bind_address;
        let router = self.router.clone();
        let token = self.config.auth_token.clone();

        let listener = TcpListener::bind(addr).await.map_err(|e| {
            Error::Transport(format!("Failed to bind HTTP server on {}: {}", addr, e))
        })?;

        info!("HTTP API server listening on http://{}", addr);

        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        error!("HTTP accept error: {}", e);
                        continue;
                    }
                };

                let router = router.clone();
                let token = token.clone();

                tokio::spawn(async move {
                    if let Err(e) =
                        handle_http_connection(stream, peer_addr, router, token).await
                    {
                        warn!("HTTP connection error from {}: {}", peer_addr, e);
                    }
                });
            }
        });

        Ok(())
    }
}

/// Parse et traite une connexion HTTP/1.1 simple
async fn handle_http_connection(
    mut stream: tokio::net::TcpStream,
    _peer_addr: SocketAddr,
    router: Arc<ApiRouter>,
    auth_token: Option<String>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 8192];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| Error::Transport(format!("HTTP read error: {}", e)))?;

    if n == 0 {
        return Ok(());
    }

    let raw = String::from_utf8_lossy(&buf[..n]);
    let lines: Vec<&str> = raw.lines().collect();

    if lines.is_empty() {
        return Ok(());
    }

    // Parse la première ligne : "GET /path HTTP/1.1"
    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() < 2 {
        let resp = http_response(400, "Bad Request", "text/plain", "Bad Request");
        stream.write_all(resp.as_bytes()).await.ok();
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // Vérification du token d'authentification (si configuré)
    if let Some(ref expected_token) = auth_token {
        let has_auth = lines.iter().any(|line| {
            let lower = line.to_lowercase();
            lower.starts_with("authorization:") && line.contains(expected_token.as_str())
                || lower.starts_with("x-api-token:") && line.contains(expected_token.as_str())
        });
        if !has_auth {
            let resp = http_response(401, "Unauthorized", "application/json", r#"{"error":"unauthorized"}"#);
            stream.write_all(resp.as_bytes()).await.ok();
            return Ok(());
        }
    }

    // Extraire le body (pour POST)
    let body = extract_body(&raw);

    // Router la requête via ApiRouter
    let api_response = router.handle(method, path, &body).await;

    // Construire la réponse HTTP
    let content_type = if path == "/metrics" {
        "text/plain; version=0.0.4; charset=utf-8"
    } else {
        "application/json"
    };

    let http_resp = http_response(
        api_response.status,
        status_text(api_response.status),
        content_type,
        &api_response.body,
    );

    stream
        .write_all(http_resp.as_bytes())
        .await
        .map_err(|e| Error::Transport(format!("HTTP write error: {}", e)))?;

    Ok(())
}

/// Extraire le body d'une requête HTTP brute
fn extract_body(raw: &str) -> String {
    if let Some(pos) = raw.find("\r\n\r\n") {
        raw[pos + 4..].trim().to_string()
    } else if let Some(pos) = raw.find("\n\n") {
        raw[pos + 2..].trim().to_string()
    } else {
        String::new()
    }
}

/// Construire une réponse HTTP/1.1
fn http_response(status: u16, reason: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nX-Powered-By: SBC-NIXI/0.1\r\n\r\n{}",
        status,
        reason,
        content_type,
        body.len(),
        body
    )
}

/// Texte du status HTTP
fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_response_format() {
        let resp = http_response(200, "OK", "application/json", r#"{"status":"ok"}"#);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
        assert!(resp.contains(r#"{"status":"ok"}"#));
    }

    #[test]
    fn test_http_response_content_length() {
        let body = r#"{"hello":"world"}"#;
        let resp = http_response(200, "OK", "application/json", body);
        let expected = format!("Content-Length: {}", body.len());
        assert!(resp.contains(&expected));
    }

    #[test]
    fn test_extract_body_crlf() {
        let raw = "POST /api/v1/trunks HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}";
        let body = extract_body(raw);
        assert_eq!(body, r#"{"name":"test"}"#);
    }

    #[test]
    fn test_extract_body_lf() {
        let raw = "POST /api/v1/trunks HTTP/1.1\nContent-Type: application/json\n\n{\"name\":\"test\"}";
        let body = extract_body(raw);
        assert_eq!(body, r#"{"name":"test"}"#);
    }

    #[test]
    fn test_extract_body_empty() {
        let raw = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let body = extract_body(raw);
        assert!(body.is_empty());
    }

    #[test]
    fn test_status_text_codes() {
        assert_eq!(status_text(200), "OK");
        assert_eq!(status_text(201), "Created");
        assert_eq!(status_text(400), "Bad Request");
        assert_eq!(status_text(401), "Unauthorized");
        assert_eq!(status_text(404), "Not Found");
        assert_eq!(status_text(500), "Internal Server Error");
    }

    #[test]
    fn test_http_server_config_default() {
        let config = HttpServerConfig::default();
        assert_eq!(config.bind_address.port(), 8080);
        assert!(config.auth_token.is_none());
    }

    #[test]
    fn test_http_server_config_with_token() {
        let config = HttpServerConfig::new("127.0.0.1:9000".parse().unwrap())
            .with_token("secret-token".to_string());
        assert_eq!(config.auth_token, Some("secret-token".to_string()));
        assert_eq!(config.bind_address.port(), 9000);
    }

    #[tokio::test]
    async fn test_http_server_binds() {
        use crate::media::MediaManager;
        use std::collections::HashMap;

        let metrics = Arc::new(SbcMetrics::new());
        let media = Arc::new(MediaManager::with_port_range(30000..31000, None));
        let b2bua = Arc::new(B2buaManager::new(media));
        let trunks = Arc::new(TrunkManager::new());

        let config = HttpServerConfig::new("127.0.0.1:0".parse().unwrap());

        // Binding to port 0 should succeed (OS assigns port)
        // We test it doesn't panic
        let server = HttpServer::new(config, metrics, b2bua, trunks);
        let result = server.start().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_http_server_with_auth_config() {
        use crate::media::MediaManager;

        let metrics = Arc::new(SbcMetrics::new());
        let media = Arc::new(MediaManager::with_port_range(31000..32000, None));
        let b2bua = Arc::new(B2buaManager::new(media));
        let trunks = Arc::new(TrunkManager::new());

        let config = HttpServerConfig::new("127.0.0.1:0".parse().unwrap())
            .with_token("test-token-123".to_string());

        let server = HttpServer::new(config.clone(), metrics, b2bua, trunks);
        assert!(config.auth_token.is_some());
        // Server creation should not fail
        let result = server.start().await;
        assert!(result.is_ok());
    }
}
