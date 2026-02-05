use crate::protocol::{Announcement, DeviceInfo, API_BASE};
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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;

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
        let scan = scan_subnets(device_info.clone(), devices.clone());
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
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(400))
        .build()?
        .clone();

    let mut handles = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        let ip = match iface.ip() {
            IpAddr::V4(ip) => ip,
            _ => continue,
        };
        let netmask = match iface.netmask() {
            IpAddr::V4(mask) => mask,
            _ => continue,
        };
        let Some(net) = ipnet::Ipv4Net::with_netmask(ip, netmask).ok() else { continue };
        for host in net.hosts() {
            if host == ip {
                continue;
            }
            let target = SocketAddr::new(IpAddr::V4(host), device_info.port);
            let devices = devices.clone();
            let info = device_info.clone();
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                let url = format!("{}://{}:{}/api/localsend/v2/register", info.protocol, host, info.port);
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
            }));
        }
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

fn device_id(info: &DeviceInfo, addr: IpAddr) -> String {
    if !info.fingerprint.is_empty() {
        return info.fingerprint.clone();
    }
    let mut hasher = Sha256::new();
    hasher.update(info.alias.as_bytes());
    hasher.update(addr.to_string().as_bytes());
    hasher.update(info.port.to_string().as_bytes());
    hex::encode(hasher.finalize())
}
