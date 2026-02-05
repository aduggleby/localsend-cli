use crate::protocol::DeviceInfo;
use crate::send::{SendData, SendItem};
use crate::util::TlsIdentity;
use anyhow::Context;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{routing::get, Router};
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
 
use tokio_util::io::ReaderStream;

#[derive(Clone)]
struct WebShareState {
    items: Arc<HashMap<String, SendItem>>,
    pin: Option<String>,
}

#[derive(Deserialize)]
struct PinQuery {
    pin: Option<String>,
}

#[derive(Serialize)]
struct QrOutput {
    preferred_url: String,
    urls: Vec<String>,
    qr: String,
    pin: Option<String>,
}

pub async fn run_web_share(
    items: Vec<SendItem>,
    device_info: DeviceInfo,
    tls: Option<TlsIdentity>,
    bind: IpAddr,
    port: u16,
    pin: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let items_map: HashMap<String, SendItem> = items
        .into_iter()
        .map(|item| (item.id.clone(), item))
        .collect();

    let state = WebShareState {
        items: Arc::new(items_map),
        pin: pin.clone(),
    };

    let urls = build_urls(&device_info.protocol, port, &pin)?;
    let preferred = choose_preferred_url(&urls).unwrap_or_else(|| urls[0].clone());
    let qr = render_qr(&preferred)?;

    if json {
        let output = QrOutput {
            preferred_url: preferred.clone(),
            urls: urls.clone(),
            qr,
            pin: pin.clone(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("QR send ready. Open this URL on the receiver:");
        println!("{}", preferred);
        println!();
        println!("{}", qr);
        if urls.len() > 1 {
            println!("Other URLs:");
            for url in &urls {
                println!("{}", url);
            }
        }
        if let Some(pin) = &pin {
            println!("PIN: {}", pin);
        }
        println!("Press Ctrl+C to stop.");
        let _ = std::io::stdout().flush();
    }

    let app = Router::new()
        .route("/", get(index))
        .route("/files/:id", get(download))
        .with_state(Arc::new(state));

    let addr = SocketAddr::new(bind, port);
    let server = if let Some(tls) = tls {
        let config = axum_server::tls_rustls::RustlsConfig::from_pem(
            tls.cert_pem.into_bytes(),
            tls.key_pem.into_bytes(),
        )
        .await
        .context("failed to build tls config")?;
        tokio::spawn(async move {
            let _ = axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await;
        })
    } else {
        tokio::spawn(async move {
            let _ = axum::serve(
                tokio::net::TcpListener::bind(addr).await.expect("bind"),
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        })
    };

    tokio::signal::ctrl_c().await?;
    server.abort();
    Ok(())
}

async fn index(State(state): State<Arc<WebShareState>>) -> impl IntoResponse {
    let mut rows = String::new();
    let mut entries: Vec<_> = state.items.values().collect();
    entries.sort_by(|a, b| a.file_name.cmp(&b.file_name));

    let pin_query = state
        .pin
        .as_ref()
        .map(|pin| format!("?pin={}", urlencoding::encode(pin)))
        .unwrap_or_default();

    for item in entries {
        let link = format!("/files/{}{}", item.id, pin_query);
        rows.push_str(&format!(
            "<li><a href=\"{}\">{} ({})</a></li>",
            link,
            html_escape(&item.file_name),
            item.size
        ));
    }

    let pin_note = if state.pin.is_some() {
        "<p>PIN required. Use the QR URL that already contains the PIN.</p>"
    } else {
        ""
    };

    Html(format!(
        "<html><head><meta charset=\"utf-8\"/><title>LocalSend Web Share</title></head><body><h1>LocalSend Web Share</h1>{pin_note}<ul>{rows}</ul></body></html>"
    ))
}

async fn download(
    Path(id): Path<String>,
    Query(query): Query<PinQuery>,
    State(state): State<Arc<WebShareState>>,
) -> Response {
    if let Some(required) = &state.pin {
        if query.pin.as_deref() != Some(required.as_str()) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let item = match state.items.get(&id) {
        Some(item) => item,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let mut response = Response::builder().status(StatusCode::OK);
    response = response.header(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&item.file_type).unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    response = response.header(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"{}\"",
            item.file_name
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );

    match &item.data {
        SendData::Bytes(bytes) => {
            response = response.header(header::CONTENT_LENGTH, bytes.len());
            response.body(axum::body::Body::from(bytes.clone())).unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        SendData::Path(path) => {
            let file = match tokio::fs::File::open(path).await {
                Ok(file) => file,
                Err(_) => return StatusCode::NOT_FOUND.into_response(),
            };
            let len = tokio::fs::metadata(path).await.map(|m| m.len()).unwrap_or(0);
            response = response.header(header::CONTENT_LENGTH, len);
            let stream = ReaderStream::new(file);
            response
                .body(axum::body::Body::from_stream(stream))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

fn build_urls(protocol: &str, port: u16, pin: &Option<String>) -> anyhow::Result<Vec<String>> {
    let mut urls = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        let ip = match iface.addr {
            if_addrs::IfAddr::V4(v4) => v4.ip,
            _ => continue,
        };
        if ip.is_loopback() || ip.is_link_local() {
            continue;
        }
        let base = format!("{}://{}:{}", protocol, ip, port);
        let url = match pin {
            Some(pin) => format!("{}?pin={}", base, urlencoding::encode(pin)),
            None => base,
        };
        urls.push(url);
    }

    if urls.is_empty() {
        return Err(anyhow::anyhow!("no usable network interfaces found"));
    }

    Ok(urls)
}

fn choose_preferred_url(urls: &[String]) -> Option<String> {
    let mut tailscale = None;
    let mut first = None;
    for url in urls {
        if first.is_none() {
            first = Some(url.clone());
        }
        if let Some(ip) = extract_ip(url) {
            if ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000) == 0b0100_0000 {
                tailscale = Some(url.clone());
                break;
            }
        }
    }
    tailscale.or(first)
}

fn extract_ip(url: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = url.split("//").collect();
    let host_part = parts.get(1)?;
    let host = host_part.split(':').next()?;
    host.parse().ok()
}

fn render_qr(data: &str) -> anyhow::Result<String> {
    let code = QrCode::new(data.as_bytes()).context("failed to build qr")?;
    Ok(code.render::<unicode::Dense1x2>().build())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
