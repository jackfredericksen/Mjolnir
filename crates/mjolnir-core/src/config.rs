use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MjolnirConfig {
    pub scan: ScanConfig,
    pub quarantine: QuarantineConfig,
    pub realtime: RealtimeConfig,
    pub update: UpdateConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub max_file_size_mb: u64,
    pub thread_count: usize,
    pub engines: Vec<String>,
    pub excluded_paths: Vec<PathBuf>,
    pub excluded_extensions: Vec<String>,
    pub quick: QuickScanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickScanConfig {
    pub targets: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub vault_path: PathBuf,
    pub max_vault_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeConfig {
    pub enabled: bool,
    pub watch_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub auto_update: bool,
    pub check_interval_hours: u64,
    pub server_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: PathBuf,
}

impl Default for MjolnirConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                max_file_size_mb: 512,
                thread_count: 0,
                engines: vec![
                    "signature".into(),
                    "heuristic".into(),
                    "ml".into(),
                    "static".into(),
                ],
                excluded_paths: vec![],
                excluded_extensions: vec![".iso".into(), ".vmdk".into(), ".vhd".into()],
                quick: QuickScanConfig {
                    targets: vec![],
                },
            },
            quarantine: QuarantineConfig {
                vault_path: PathBuf::from("~/.mjolnir/quarantine"),
                max_vault_size_mb: 2048,
            },
            realtime: RealtimeConfig {
                enabled: true,
                watch_paths: vec![],
                excluded_paths: vec![],
            },
            update: UpdateConfig {
                auto_update: true,
                check_interval_hours: 6,
                server_url: "https://updates.mjolnir.local/api/v1".into(),
            },
            logging: LoggingConfig {
                level: "info".into(),
                file: PathBuf::from("~/.mjolnir/mjolnir.log"),
            },
        }
    }
}

impl MjolnirConfig {
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| crate::error::MjolnirError::Config(e.to_string()))
    }
}
