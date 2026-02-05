use crate::protocol::{Announcement, DeviceInfo, DeviceType, API_BASE};
use crate::util::TlsIdentity;
use anyhow::Context;
use axum::extract::{ConnectInfo, State};
use axum::response::IntoResponse;
use axum::{routing::get, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use futures_util::stream::{FuturesUnordered, StreamExt};

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 167);
const MULTICAST_PORT: u16 = 53317;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub id: String,
    #[serde(flatten)]
    pub info: DeviceInfo,
    pub addr: IpAddr,
}

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub timeout_secs: u64,
    pub scan: bool,
}

#[derive(Debug, Clone)]
pub struct TargetSelector {
    pub to: String,
    pub direct: Option<String>,
}

impl TargetSelector {
    pub fn new(to: String, direct: Option<String>) -> Self {
        Self { to, direct }
    }
}

pub fn match_selector(selector: &str, device: &DiscoveredDevice) -> bool {
    let needle = selector.to_lowercase();
    if device.id.to_lowercase() == needle {
        return true;
    }
    if device.info.alias.to_lowercase() == needle {
        return true;
    }
    if device.addr.to_string() == selector {
        return true;
    }
    false
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeerInfo {
    alias: String,
    version: String,
    device_model: String,
    device_type: DeviceType,
    fingerprint: String,
    port: Option<u16>,
    protocol: Option<String>,
    download: Option<bool>,
}

impl PeerInfo {
    fn into_device_info(self, fallback_port: u16, fallback_protocol: &str) -> DeviceInfo {
        DeviceInfo {
            alias: self.alias,
            version: self.version,
            device_model: self.device_model,
            device_type: self.device_type,
            fingerprint: self.fingerprint,
            port: self.port.unwrap_or(fallback_port),
            protocol: self
                .protocol
                .unwrap_or_else(|| fallback_protocol.to_string()),
            download: self.download.unwrap_or(false),
        }
    }
}

pub async fn search_tailscale_peer(
    selector: &str,
    device_info: &DeviceInfo,
    timeout_secs: u64,
) -> anyhow::Result<Option<DiscoveredDevice>> {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output();
    let Ok(output) = output else { return Ok(None) };
    if !output.status.success() {
        return Ok(None);
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return Ok(None);
    };
    let Some(peers) = json.get("Peer") else { return Ok(None) };
    let Some(peer_map) = peers.as_object() else { return Ok(None) };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(800))
        .build()?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    for peer in peer_map.values() {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        if !tailscale_peer_matches(peer, selector) {
            continue;
        }
        let Some(ips) = peer.get("TailscaleIPs").and_then(|v| v.as_array()) else { continue };
        for ip_val in ips {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Some(ip_str) = ip_val.as_str() else { continue };
            let Ok(ip) = ip_str.parse::<IpAddr>() else { continue };
            if !matches!(ip, IpAddr::V4(_)) {
                continue;
            }
            let probe = probe_peer(client.clone(), device_info, ip, device_info.port);
            let result = tokio::time::timeout(remaining, probe).await;
            if let Ok(Some(device)) = result {
                let id = device_id(&device, ip);
                return Ok(Some(DiscoveredDevice {
                    id,
                    info: device,
                    addr: ip,
                }));
            }
        }
    }

    Ok(None)
}

pub async fn probe_device(
    ip: IpAddr,
    port: u16,
    device_info: &DeviceInfo,
    timeout_secs: u64,
) -> anyhow::Result<Option<DeviceInfo>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;

    let probe = probe_peer(client, device_info, ip, port);
    let result = tokio::time::timeout(Duration::from_secs(timeout_secs), probe).await;
    Ok(result.ok().flatten())
}

#[derive(Clone)]
struct DiscoveryState {
    device_info: DeviceInfo,
    devices: Arc<Mutex<HashMap<String, DiscoveredDevice>>>,
}

pub async fn discover_devices(
    device_info: DeviceInfo,
    tls: Option<TlsIdentity>,
    bind: IpAddr,
    port: u16,
    options: DiscoveryOptions,
) -> anyhow::Result<Vec<DiscoveredDevice>> {
    let devices: Arc<Mutex<HashMap<String, DiscoveredDevice>>> = Arc::new(Mutex::new(HashMap::new()));
    let state = DiscoveryState {
        device_info: device_info.clone(),
        devices: devices.clone(),
    };

    let server_handle = start_register_server(state.clone(), tls, bind, port).await?;
    let announcer = announce_multicast(device_info.clone());
    let listener = listen_multicast(device_info.clone(), devices.clone(), options.timeout_secs);

    if options.scan {
        let scan = scan_subnets(device_info.clone(), devices.clone(), options.timeout_secs);
        let _ = tokio::join!(announcer, listener, scan);
    } else {
        let _ = tokio::join!(announcer, listener);
    }
    server_handle.abort();

    let devices = devices.lock().expect("devices lock");
    Ok(devices.values().cloned().collect())
}

async fn start_register_server(
    state: DiscoveryState,
    tls: Option<TlsIdentity>,
    bind: IpAddr,
    port: u16,
) -> anyhow::Result<JoinHandle<()>> {
    let shared_state = Arc::new(state);
    let app = Router::new()
        .route(&format!("{API_BASE}/register"), post(register))
        .route(&format!("{API_BASE}/info"), get(info))
        .with_state(shared_state.clone());

    let addr = SocketAddr::new(bind, port);
    let handle = if let Some(tls) = tls {
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

    Ok(handle)
}

async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<DiscoveryState>>,
    Json(info): Json<DeviceInfo>,
) -> impl IntoResponse {
    let id = device_id(&info, addr.ip());
    let mut devices = state.devices.lock().expect("devices lock");
    devices.insert(
        id.clone(),
        DiscoveredDevice {
            id,
            info,
            addr: addr.ip(),
        },
    );

    Json(state.device_info.clone())
}

async fn info(State(state): State<Arc<DiscoveryState>>) -> impl IntoResponse {
    Json(state.device_info.clone())
}

async fn announce_multicast(device_info: DeviceInfo) -> anyhow::Result<()> {
    let announcement = Announcement {
        info: device_info,
        announce: true,
    };
    let payload = serde_json::to_vec(&announcement).context("serialize announce")?;
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(true)?;
    let addr = SocketAddr::new(IpAddr::V4(MULTICAST_ADDR), MULTICAST_PORT);
    socket.send_to(&payload, &addr.into())?;
    Ok(())
}

async fn listen_multicast(
    device_info: DeviceInfo,
    devices: Arc<Mutex<HashMap<String, DiscoveredDevice>>>,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT).into())?;
    socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;

    let socket = tokio::net::UdpSocket::from_std(socket.into())?;
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }

        let timeout = deadline - now;
        let recv = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;
        let Ok(Ok((len, addr))) = recv else { break };
        let Ok(info) = serde_json::from_slice::<DeviceInfo>(&buf[..len]) else { continue };
        if info.fingerprint == device_info.fingerprint {
            continue;
        }
        let id = device_id(&info, addr.ip());
        let mut devices_lock = devices.lock().expect("devices lock");
        devices_lock.insert(
            id.clone(),
            DiscoveredDevice {
                id,
                info,
                addr: addr.ip(),
            },
        );
    }

    Ok(())
}

async fn scan_subnets(
    device_info: DeviceInfo,
    devices: Arc<Mutex<HashMap<String, DiscoveredDevice>>>,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(400))
        .build()?
        .clone();

    let mut futures = FuturesUnordered::new();
    let start = tokio::time::Instant::now();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        let (ip, netmask) = match iface.addr {
            if_addrs::IfAddr::V4(v4) => (v4.ip, v4.netmask),
            _ => continue,
        };
        let Some(net) = ipnet::Ipv4Net::with_netmask(ip, netmask).ok() else { continue };
        for host in net.hosts() {
            if start.elapsed() >= Duration::from_secs(timeout_secs) {
                break;
            }
            if host == ip {
                continue;
            }
            let target = SocketAddr::new(IpAddr::V4(host), device_info.port);
            let devices = devices.clone();
            let info = device_info.clone();
            let client = client.clone();
            futures.push(async move {
                let url = format!(
                    "{}://{}:{}/api/localsend/v2/register",
                    info.protocol, host, info.port
                );
                let response = client.post(url).json(&info).send().await.ok()?;
                let device: DeviceInfo = response.json().await.ok()?;
                let id = device_id(&device, target.ip());
                let mut devices_lock = devices.lock().expect("devices lock");
                devices_lock.insert(
                    id.clone(),
                    DiscoveredDevice {
                        id,
                        info: device,
                        addr: target.ip(),
                    },
                );
                Some(())
            });
        }
    }

    let deadline = start + Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let next = tokio::time::timeout(remaining, futures.next()).await;
        if next.is_err() {
            break;
        }
        if next.ok().flatten().is_none() {
            break;
        }
    }

    scan_tailscale_peers(device_info.clone(), devices.clone(), timeout_secs).await?;

    Ok(())
}

pub(crate) fn device_id(info: &DeviceInfo, addr: IpAddr) -> String {
    if !info.fingerprint.is_empty() {
        return info.fingerprint.clone();
    }
    let mut hasher = Sha256::new();
    hasher.update(info.alias.as_bytes());
    hasher.update(addr.to_string().as_bytes());
    hasher.update(info.port.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

async fn scan_tailscale_peers(
    device_info: DeviceInfo,
    devices: Arc<Mutex<HashMap<String, DiscoveredDevice>>>,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output();
    let Ok(output) = output else { return Ok(()) };
    if !output.status.success() {
        return Ok(());
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return Ok(());
    };
    let Some(peers) = json.get("Peer") else { return Ok(()) };
    let Some(peer_map) = peers.as_object() else { return Ok(()) };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(800))
        .build()?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    for peer in peer_map.values() {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        let Some(ips) = peer.get("TailscaleIPs").and_then(|v| v.as_array()) else { continue };
        for ip_val in ips {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Some(ip_str) = ip_val.as_str() else { continue };
            let Ok(ip) = ip_str.parse::<IpAddr>() else { continue };
            if !matches!(ip, IpAddr::V4(_)) {
                continue;
            }
            let probe = probe_peer(client.clone(), &device_info, ip, device_info.port);
            let result = tokio::time::timeout(remaining, probe).await;
            if let Ok(Some(device)) = result {
                let id = device_id(&device, ip);
                let mut devices_lock = devices.lock().expect("devices lock");
                devices_lock.insert(
                    id.clone(),
                    DiscoveredDevice {
                        id,
                        info: device,
                        addr: ip,
                    },
                );
            }
        }
    }

    Ok(())
}

fn tailscale_peer_matches(peer: &serde_json::Value, selector: &str) -> bool {
    let needle = selector.to_lowercase();
    let mut candidates = Vec::new();
    if let Some(name) = peer.get("Name").and_then(|v| v.as_str()) {
        candidates.push(name.to_string());
    }
    if let Some(name) = peer.get("HostName").and_then(|v| v.as_str()) {
        candidates.push(name.to_string());
    }
    if let Some(name) = peer.get("DNSName").and_then(|v| v.as_str()) {
        let trimmed = name.trim_end_matches('.');
        candidates.push(trimmed.to_string());
        if let Some(short) = trimmed.split('.').next() {
            candidates.push(short.to_string());
        }
    }

    candidates
        .into_iter()
        .any(|candidate| candidate.to_lowercase() == needle)
}

async fn probe_peer(
    client: reqwest::Client,
    device_info: &DeviceInfo,
    ip: IpAddr,
    port: u16,
) -> Option<DeviceInfo> {
    let mut protocols = vec![device_info.protocol.clone()];
    if device_info.protocol != "https" {
        protocols.push("https".to_string());
    }
    if device_info.protocol != "http" {
        protocols.push("http".to_string());
    }

    for proto in protocols {
        let info_url = format!(
            "{}://{}:{}/api/localsend/v2/info",
            proto, ip, port
        );
        if let Ok(response) = client.get(info_url).send().await {
            if response.status().is_success() {
                if let Ok(peer) = response.json::<PeerInfo>().await {
                    return Some(peer.into_device_info(port, &proto));
                }
            }
        }

        let register_url = format!(
            "{}://{}:{}/api/localsend/v2/register",
            proto, ip, port
        );
        if let Ok(response) = client.post(register_url).json(device_info).send().await {
            if response.status().is_success() {
                if let Ok(peer) = response.json::<PeerInfo>().await {
                    return Some(peer.into_device_info(port, &proto));
                }
            }
        }
    }

    None
}
