use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

pub const API_BASE: &str = "/api/localsend/v2";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
        }
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "http" => Ok(Protocol::Http),
            "https" => Ok(Protocol::Https),
            other => Err(format!("unsupported protocol: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Mobile,
    Desktop,
    Web,
    Headless,
    Server,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub alias: String,
    pub version: String,
    pub device_model: String,
    pub device_type: DeviceType,
    pub fingerprint: String,
    pub port: u16,
    pub protocol: String,
    pub download: bool,
}

impl DeviceInfo {
    pub fn new(
        alias: String,
        device_type: DeviceType,
        protocol: Protocol,
        port: u16,
        fingerprint: String,
    ) -> Self {
        let device_model = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

        DeviceInfo {
            alias,
            version: "2.1".to_string(),
            device_model,
            device_type,
            fingerprint,
            port,
            protocol: protocol.as_str().to_string(),
            download: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Announcement {
    #[serde(flatten)]
    pub info: DeviceInfo,
    pub announce: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    pub file_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUploadRequest {
    pub info: DeviceInfo,
    pub files: Vec<FileInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUploadResponse {
    pub session_id: String,
    pub files: Vec<PreparedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedFile {
    pub id: String,
    pub token: String,
}

pub fn new_session_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn new_token() -> String {
    Uuid::new_v4().to_string()
}

pub fn new_file_id() -> String {
    Uuid::new_v4().to_string()
}
