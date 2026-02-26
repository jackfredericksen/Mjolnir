use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::threat::Detection;

/// Type of scan to perform
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    /// Scan common locations (Downloads, Desktop, temp)
    Quick,
    /// Full system scan (entire home directory)
    Full,
    /// Scan known threat persistence locations (LaunchAgents, cron, startup, temp)
    Threat,
    /// Scan specific targets
    Custom,
}

/// Which engines to enable for a scan
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineFlag {
    Signature,
    Heuristic,
    MachineLearning,
    StaticAnalysis,
}

/// A request to start a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub targets: Vec<PathBuf>,
    pub scan_type: ScanType,
    pub engines: Vec<EngineFlag>,
}

/// Thread-safe scan progress tracker
pub struct ScanProgress {
    pub files_scanned: AtomicU64,
    pub files_total: AtomicU64,
    pub threats_found: AtomicU64,
    pub current_file: Mutex<PathBuf>,
    pub start_time: std::time::Instant,
}

impl ScanProgress {
    pub fn new() -> Self {
        Self {
            files_scanned: AtomicU64::new(0),
            files_total: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            current_file: Mutex::new(PathBuf::new()),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn set_total(&self, total: u64) {
        self.files_total.store(total, Ordering::Relaxed);
    }

    pub fn increment(&self) {
        self.files_scanned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_threat(&self) {
        self.threats_found.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_current(&self, path: PathBuf) {
        if let Ok(mut current) = self.current_file.lock() {
            *current = path;
        }
    }

    pub fn snapshot(&self) -> ScanProgressSnapshot {
        ScanProgressSnapshot {
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            files_total: self.files_total.load(Ordering::Relaxed),
            threats_found: self.threats_found.load(Ordering::Relaxed),
            current_file: self
                .current_file
                .lock()
                .map(|f| f.clone())
                .unwrap_or_default(),
            elapsed: self.start_time.elapsed(),
        }
    }
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable snapshot of scan progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgressSnapshot {
    pub files_scanned: u64,
    pub files_total: u64,
    pub threats_found: u64,
    pub current_file: PathBuf,
    #[serde(with = "duration_serde")]
    pub elapsed: Duration,
}

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(dur: &Duration, s: S) -> Result<S::Ok, S::Error> {
        dur.as_millis().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let millis = u64::deserialize(d)?;
        Ok(Duration::from_millis(millis))
    }
}

/// Result of a file scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanResult {
    pub file_path: PathBuf,
    pub file_hash: String,
    pub file_size: u64,
    pub detections: Vec<Detection>,
    pub scan_duration_ms: u64,
}

impl FileScanResult {
    pub fn is_clean(&self) -> bool {
        self.detections.is_empty()
    }

    pub fn max_severity(&self) -> Option<crate::threat::ThreatSeverity> {
        self.detections.iter().map(|d| d.severity).max()
    }
}

/// Complete scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_type: ScanType,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub files_scanned: u64,
    pub files_infected: u64,
    pub total_detections: u64,
    pub detections: Vec<Detection>,
    pub duration_ms: u64,
}
