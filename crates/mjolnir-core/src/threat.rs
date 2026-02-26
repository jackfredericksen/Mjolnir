use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::error::Result;

/// Severity levels for detected threats
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Which engine produced the detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionSource {
    Signature,
    Heuristic,
    MachineLearning,
    StaticAnalysis,
}

impl std::fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signature => write!(f, "Signature"),
            Self::Heuristic => write!(f, "Heuristic"),
            Self::MachineLearning => write!(f, "ML"),
            Self::StaticAnalysis => write!(f, "Static"),
        }
    }
}

/// A unified detection result from any engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: Uuid,
    pub file_path: PathBuf,
    pub file_hash: String,
    pub threat_name: String,
    pub severity: ThreatSeverity,
    pub source: DetectionSource,
    pub confidence: f64,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

impl Detection {
    pub fn new(
        file_path: PathBuf,
        file_hash: String,
        threat_name: String,
        severity: ThreatSeverity,
        source: DetectionSource,
        confidence: f64,
        details: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            file_path,
            file_hash,
            threat_name,
            severity,
            source,
            confidence,
            details,
            timestamp: Utc::now(),
        }
    }
}

/// Trait that every detection engine must implement
#[async_trait::async_trait]
pub trait DetectionEngine: Send + Sync {
    /// Scan file data and return any detections
    fn scan_file(&self, path: &Path, data: &[u8]) -> Result<Vec<Detection>>;

    /// Human-readable engine name
    fn engine_name(&self) -> &str;
}
