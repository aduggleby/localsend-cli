use crate::discovery::{self, match_selector, DiscoveryOptions, DiscoveredDevice, TargetSelector};
use crate::protocol::{new_file_id, DeviceInfo, FileInfo, FileMetadata, PrepareUploadRequest, PrepareUploadResponse, API_BASE};
use crate::util::{self, TlsIdentity};
use anyhow::{anyhow, Context};
use glob::glob;
use mime_guess::MimeGuess;
use reqwest::StatusCode;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio_util::io::ReaderStream;

#[derive(Debug, Clone)]
pub(crate) struct SendItem {
    pub(crate) id: String,
    pub(crate) file_name: String,
    pub(crate) size: u64,
    pub(crate) file_type: String,
    pub(crate) metadata: Option<FileMetadata>,
    pub(crate) data: SendData,
}

#[derive(Debug, Clone)]
pub(crate) enum SendData {
    Path(PathBuf),
    Bytes(Vec<u8>),
}

#[derive(Serialize)]
struct SendResult {
    id: String,
    name: String,
    size: u64,
}

#[allow(dead_code)]
pub async fn send_items(
    selector: TargetSelector,
    device_info: DeviceInfo,
    tls: Option<TlsIdentity>,
    bind: IpAddr,
    port: u16,
    timeout: u64,
    pin: Option<String>,
    text: Option<String>,
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    globs: Vec<String>,
    json: bool,
) -> anyhow::Result<()> {
    let mut temp_files = Vec::new();
    let items = build_items(text, files, dirs, globs, &mut temp_files).await?;
    let target = resolve_target(selector, device_info.clone(), tls, bind, port, timeout).await?;

    send_prepared_items(target, items, device_info, timeout, pin, json).await
}

pub(crate) async fn send_prepared_items(
    target: DiscoveredDevice,
    items: Vec<SendItem>,
    device_info: DeviceInfo,
    timeout: u64,
    pin: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    if items.is_empty() {
        return Err(anyhow!("no files, directories, or text specified"));
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(timeout))
        .build()?;

    let url = format!(
        "{}://{}:{}{}/prepare-upload",
        target.info.protocol,
        target.addr,
        target.info.port,
        API_BASE
    );

    let mut files = HashMap::new();
    for item in &items {
        files.insert(
            item.id.clone(),
            FileInfo {
                id: item.id.clone(),
                file_name: item.file_name.clone(),
                size: item.size,
                file_type: item.file_type.clone(),
                sha256: None,
                preview: None,
                metadata: item.metadata.clone(),
            },
        );
    }

    let prepare_request = PrepareUploadRequest {
        info: device_info,
        files,
    };

    let mut request = client.post(url).json(&prepare_request);
    if let Some(pin) = pin.as_ref() {
        request = request.query(&["pin", pin]);
    }

    let response = request.send().await?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(anyhow!("receiver rejected the pin"));
    }
    if !response.status().is_success() {
        return Err(anyhow!("prepare-upload failed: {}", response.status()));
    }

    let prepared: PrepareUploadResponse = response.json().await?;
    let token_map: HashMap<String, String> = prepared.files;

    let mut results = Vec::new();

    for item in items {
        let token = token_map
            .get(&item.id)
            .ok_or_else(|| anyhow!("missing token for {}", item.file_name))?;
        let upload_url = format!(
            "{}://{}:{}{}/upload",
            target.info.protocol,
            target.addr,
            target.info.port,
            API_BASE
        );

        let mut upload_req = client.post(upload_url);
        upload_req = upload_req.query(&[
            ("sessionId", prepared.session_id.as_str()),
            ("fileId", item.id.as_str()),
            ("token", token.as_str()),
        ]);

        let body = match &item.data {
            SendData::Path(path) => {
                let file = tokio::fs::File::open(path).await?;
                let stream = ReaderStream::new(file);
                reqwest::Body::wrap_stream(stream)
            }
            SendData::Bytes(bytes) => reqwest::Body::from(bytes.clone()),
        };

        let response = upload_req.body(body).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "upload failed for {}: {}",
                item.file_name,
                response.status()
            ));
        }

        results.push(SendResult {
            id: item.id,
            name: item.file_name,
            size: item.size,
        });
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for result in results {
            println!("Sent {} ({} bytes)", result.name, result.size);
        }
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) struct NoMatchingDevice;

impl std::fmt::Display for NoMatchingDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no matching device found")
    }
}

impl std::error::Error for NoMatchingDevice {}

pub(crate) async fn resolve_target(
    selector: TargetSelector,
    device_info: DeviceInfo,
    tls: Option<TlsIdentity>,
    bind: IpAddr,
    port: u16,
    timeout: u64,
) -> anyhow::Result<DiscoveredDevice> {
    if let Some(direct) = selector.direct.as_deref() {
        if let Some((ip, port)) = util::parse_socket_target(direct) {
            return Ok(DiscoveredDevice {
                id: format!("{}:{}", ip, port),
                info: DeviceInfo {
                    port,
                    protocol: device_info.protocol.clone(),
                    ..device_info
                },
                addr: ip,
            });
        }
    }

    if let Ok(ip) = selector.to.parse::<IpAddr>() {
        return Ok(DiscoveredDevice {
            id: ip.to_string(),
            info: DeviceInfo {
                port,
                protocol: device_info.protocol.clone(),
                ..device_info
            },
            addr: ip,
        });
    }

    let devices = discovery::discover_devices(
        device_info,
        tls,
        bind,
        port,
        DiscoveryOptions {
            timeout_secs: timeout,
            scan: true,
        },
    )
    .await?;

    let target = devices
        .into_iter()
        .find(|device| match_selector(&selector.to, device))
        .ok_or_else(|| anyhow::Error::new(NoMatchingDevice))?;

    Ok(target)
}

pub(crate) async fn build_items(
    text: Option<String>,
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    globs: Vec<String>,
    temp_files: &mut Vec<NamedTempFile>,
) -> anyhow::Result<Vec<SendItem>> {
    let mut items = Vec::new();

    if let Some(text) = text {
        let bytes = text.into_bytes();
        items.push(SendItem {
            id: new_file_id(),
            file_name: "message.txt".to_string(),
            size: bytes.len() as u64,
            file_type: "text/plain; charset=utf-8".to_string(),
            metadata: None,
            data: SendData::Bytes(bytes),
        });
    }

    for file in files {
        items.push(item_from_path(file).await?);
    }

    for pattern in globs {
        for entry in glob(&pattern).context("invalid glob")? {
            if let Ok(path) = entry {
                items.push(item_from_path(path).await?);
            }
        }
    }

    for dir in dirs {
        let zipped = zip_directory(&dir, temp_files).await?;
        items.push(item_from_path(zipped).await?);
    }

    Ok(items)
}

async fn item_from_path(path: PathBuf) -> anyhow::Result<SendItem> {
    let metadata = tokio::fs::metadata(&path).await?;
    if !metadata.is_file() {
        return Err(anyhow!("{} is not a file", path.display()));
    }
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let file_type = MimeGuess::from_path(&path)
        .first_or_octet_stream()
        .to_string();
    let modified = metadata.modified().ok().and_then(util::format_time);
    let accessed = metadata.accessed().ok().and_then(util::format_time);
    let meta = if modified.is_some() || accessed.is_some() {
        Some(FileMetadata { modified, accessed })
    } else {
        None
    };

    Ok(SendItem {
        id: new_file_id(),
        file_name,
        size: metadata.len(),
        file_type,
        metadata: meta,
        data: SendData::Path(path),
    })
}

async fn zip_directory(dir: &Path, temp_files: &mut Vec<NamedTempFile>) -> anyhow::Result<PathBuf> {
    let dir = dir
        .canonicalize()
        .with_context(|| format!("invalid directory {}", dir.display()))?;
    let name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("archive");

    let temp = NamedTempFile::new()?;
    let path = temp.path().to_path_buf();
    let path_for_zip = path.clone();

    let dir_clone = dir.clone();
    let name = name.to_string();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let file = std::fs::File::create(&path_for_zip)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for entry in walkdir::WalkDir::new(&dir_clone) {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let relative = path.strip_prefix(&dir_clone)?;
            let mut name_path = PathBuf::from(&name);
            name_path.push(relative);
            let zip_name = name_path.to_string_lossy();
            zip.start_file(zip_name, options)?;
            let mut file = std::fs::File::open(path)?;
            std::io::copy(&mut file, &mut zip)?;
        }
        zip.finish()?;
        Ok(())
    })
    .await??;

    temp_files.push(temp);
    Ok(path)
}
