use crate::discovery::DiscoveredDevice;
use crate::protocol::Protocol;
use anyhow::Context;
use chrono::{DateTime, Utc};
use rand::RngCore;
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone)]
pub struct TlsIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
}

#[derive(Clone)]
pub struct Identity {
    pub fingerprint: String,
    pub tls: Option<TlsIdentity>,
}

pub fn build_identity(protocol: Protocol) -> anyhow::Result<Identity> {
    match protocol {
        Protocol::Https => {
            let cert = generate_simple_self_signed(vec!["localsend-cli".to_string()])
                .context("failed to generate self-signed cert")?;
            let der = cert.cert.der();
            let mut hasher = Sha256::new();
            hasher.update(der.as_ref());
            let fingerprint = hex::encode(hasher.finalize());
            let cert_pem = cert.cert.pem();
            let key_pem = cert.key_pair.serialize_pem();
            Ok(Identity {
                fingerprint: fingerprint.clone(),
                tls: Some(TlsIdentity { cert_pem, key_pem, fingerprint }),
            })
        }
        Protocol::Http => {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            Ok(Identity {
                fingerprint: hex::encode(bytes),
                tls: None,
            })
        }
    }
}

pub fn default_alias() -> Option<String> {
    hostname::get().ok().map(|name| name.to_string_lossy().to_string())
}

pub fn format_time(time: SystemTime) -> Option<DateTime<Utc>> {
    Some(DateTime::<Utc>::from(time))
}

pub fn safe_file_name(name: &str) -> String {
    let path = Path::new(name);
    let file_name = path.file_name().unwrap_or_else(|| OsStr::new("file"));
    file_name.to_string_lossy().to_string()
}

pub fn unique_path(base: &Path) -> PathBuf {
    if !base.exists() {
        return base.to_path_buf();
    }

    let stem = base
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = base.extension().and_then(|e| e.to_str()).unwrap_or("");

    for idx in 1..1000 {
        let candidate = if ext.is_empty() {
            base.with_file_name(format!("{} ({})", stem, idx))
        } else {
            base.with_file_name(format!("{} ({}).{}", stem, idx, ext))
        };
        if !candidate.exists() {
            return candidate;
        }
    }

    base.to_path_buf()
}

pub fn print_devices(devices: &[DiscoveredDevice], json: bool) {
    if json {
        let _ = serde_json::to_writer_pretty(io::stdout(), devices);
        let _ = io::stdout().flush();
        return;
    }

    if devices.is_empty() {
        println!("No devices found.");
        return;
    }

    for device in devices {
        println!(
            "{} ({}) {}:{} [{}] id={}",
            device.info.alias,
            device.info.device_model,
            device.addr,
            device.info.port,
            device.info.protocol,
            device.id
        );
    }
}

pub fn parse_socket_target(target: &str) -> Option<(IpAddr, u16)> {
    let mut parts = target.split(':');
    let host = parts.next()?;
    let port = parts.next()?.parse().ok()?;
    let ip: IpAddr = host.parse().ok()?;
    Some((ip, port))
}
