use crate::protocol::{new_session_id, new_token, DeviceInfo, FileMetadata, PrepareUploadRequest, PrepareUploadResponse, API_BASE};
use crate::util::{self, TlsIdentity};
use anyhow::Context;
use axum::body::Body;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{routing::get, routing::post, Json, Router};
use futures_util::TryStreamExt;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[derive(Clone)]
struct ReceiverState {
    device_info: DeviceInfo,
    output_dir: PathBuf,
    pin: Option<String>,
    sessions: Arc<Mutex<HashMap<String, UploadSession>>>,
    json: bool,
}

#[derive(Debug, Clone)]
struct UploadSession {
    files: HashMap<String, UploadFile>,
}

#[derive(Debug, Clone)]
struct UploadFile {
    token: String,
    file_name: String,
    metadata: Option<FileMetadata>,
}

#[derive(Deserialize)]
struct PinQuery {
    pin: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadQuery {
    session_id: String,
    file_id: String,
    token: String,
}

pub async fn run_receiver(
    device_info: DeviceInfo,
    tls: Option<TlsIdentity>,
    bind: IpAddr,
    port: u16,
    output_dir: PathBuf,
    pin: Option<String>,
    announce: bool,
    json: bool,
) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(&output_dir).await?;

    let state = ReceiverState {
        device_info: device_info.clone(),
        output_dir,
        pin,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        json,
    };

    if announce {
        announce_multicast(device_info.clone()).await?;
    }

    tokio::spawn(respond_to_announces(device_info.clone()));

    let app = Router::new()
        .route(&format!("{API_BASE}/register"), post(register))
        .route(&format!("{API_BASE}/info"), get(info))
        .route(&format!("{API_BASE}/prepare-upload"), post(prepare_upload))
        .route(&format!("{API_BASE}/upload"), post(upload))
        .with_state(Arc::new(state));

    let addr = SocketAddr::new(bind, port);
    if let Some(tls) = tls {
        let config = axum_server::tls_rustls::RustlsConfig::from_pem(
            tls.cert_pem.into_bytes(),
            tls.key_pem.into_bytes(),
        )
        .await
        .context("failed to build tls config")?;
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        axum::serve(
            tokio::net::TcpListener::bind(addr).await?,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}

async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<ReceiverState>>,
    Json(info): Json<DeviceInfo>,
) -> impl IntoResponse {
    if state.json {
        println!(
            "{}",
            serde_json::json!({
                "event": "register",
                "from": addr.ip().to_string(),
                "alias": info.alias,
                "id": info.fingerprint,
            })
        );
    } else {
        println!("Register from {} ({})", info.alias, addr.ip());
    }

    Json(state.device_info.clone())
}

async fn info(State(state): State<Arc<ReceiverState>>) -> impl IntoResponse {
    Json(state.device_info.clone())
}

async fn prepare_upload(
    Query(query): Query<PinQuery>,
    State(state): State<Arc<ReceiverState>>,
    Json(request): Json<PrepareUploadRequest>,
) -> impl IntoResponse {
    if let Some(required) = &state.pin {
        if query.pin.as_deref() != Some(required.as_str()) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let mut session = UploadSession {
        files: HashMap::new(),
    };

    let mut prepared: HashMap<String, String> = HashMap::new();
    for (id, file) in request.files {
        let token = new_token();
        session.files.insert(
            id.clone(),
            UploadFile {
                token: token.clone(),
                file_name: file.file_name.clone(),
                metadata: file.metadata.clone(),
            },
        );
        prepared.insert(id, token);
    }

    let session_id = new_session_id();
    state
        .sessions
        .lock()
        .expect("sessions lock")
        .insert(session_id.clone(), session);

    Json(PrepareUploadResponse {
        session_id,
        files: prepared,
    })
    .into_response()
}

async fn upload(
    Query(query): Query<UploadQuery>,
    State(state): State<Arc<ReceiverState>>,
    body: Body,
) -> impl IntoResponse {
    let file = {
        let sessions = state.sessions.lock().expect("sessions lock");
        let session = match sessions.get(&query.session_id) {
            Some(session) => session,
            None => return StatusCode::NOT_FOUND.into_response(),
        };
        let file = match session.files.get(&query.file_id) {
            Some(file) => file,
            None => return StatusCode::NOT_FOUND.into_response(),
        };
        if file.token != query.token {
            return StatusCode::FORBIDDEN.into_response();
        }
        file.clone()
    };

    let safe_name = util::safe_file_name(&file.file_name);
    let target = util::unique_path(&state.output_dir.join(&safe_name));

    let mut out = match tokio::fs::File::create(&target).await {
        Ok(file) => file,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mut stream = body.into_data_stream().map_err(|err| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{err}"))
    });
    while let Ok(Some(chunk)) = stream.try_next().await {
        if out.write_all(&chunk).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    if let Some(meta) = file.metadata {
        let mtime = meta
            .modified
            .map(|dt| filetime::FileTime::from_unix_time(dt.timestamp(), 0));
        let atime = meta
            .accessed
            .map(|dt| filetime::FileTime::from_unix_time(dt.timestamp(), 0));
        if mtime.is_some() || atime.is_some() {
            let _ = filetime::set_file_times(
                &target,
                atime.unwrap_or_else(filetime::FileTime::now),
                mtime.unwrap_or_else(filetime::FileTime::now),
            );
        }
    }

    if state.json {
        println!(
            "{}",
            serde_json::json!({
                "event": "received",
                "path": target.to_string_lossy(),
            })
        );
    } else {
        println!("Received {}", target.display());
    }

    StatusCode::OK.into_response()
}

async fn announce_multicast(device_info: DeviceInfo) -> anyhow::Result<()> {
    let announcement = crate::protocol::Announcement {
        info: device_info,
        announce: true,
    };
    let payload = serde_json::to_vec(&announcement).context("serialize announce")?;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(true)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 167)), 53317);
    socket.send_to(&payload, &addr.into())?;
    Ok(())
}

async fn respond_to_announces(device_info: DeviceInfo) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(2))
        .build()?;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_multicast_loop_v4(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53317).into())?;
    socket.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 167), &Ipv4Addr::UNSPECIFIED)?;

    let socket = tokio::net::UdpSocket::from_std(socket.into())?;
    let mut buf = vec![0u8; 65536];
    loop {
        let Ok((len, addr)) = socket.recv_from(&mut buf).await else { continue };
        let Ok(announcement) = serde_json::from_slice::<crate::protocol::Announcement>(&buf[..len]) else { continue };
        if !announcement.announce || announcement.info.fingerprint == device_info.fingerprint {
            continue;
        }
        let url = format!(
            "{}://{}:{}/api/localsend/v2/register",
            announcement.info.protocol, addr.ip(), announcement.info.port
        );
        let _ = client.post(url).json(&device_info).send().await;
    }
}
