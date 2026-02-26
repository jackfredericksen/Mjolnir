use std::path::Path;

use mjolnir_core::error::Result;
use mjolnir_core::threat::{Detection, DetectionEngine, DetectionSource, ThreatSeverity};
use mjolnir_static::StaticAnalyzer;

use crate::rules;

/// Heuristic-based detection engine that analyzes file characteristics
/// without relying on known signatures
pub struct HeuristicEngine {
    /// Minimum total score to trigger a detection (0.0 - 1.0)
    pub threshold: f64,
}

impl HeuristicEngine {
    pub fn new() -> Self {
        Self { threshold: 0.45 }
    }

    pub fn with_threshold(threshold: f64) -> Self {
        Self { threshold }
    }
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionEngine for HeuristicEngine {
    fn scan_file(&self, path: &Path, data: &[u8]) -> Result<Vec<Detection>> {
        // Parse the binary for analysis
        let analysis = match StaticAnalyzer::analyze(data) {
            Ok(a) => a,
            Err(_) => return Ok(vec![]), // Can't analyze non-binary files
        };

        let file_hash = mjolnir_crypto::FileHasher::hash_bytes(data);

        // Run all heuristic checks
        let (import_score, import_details) = rules::score_imports(&analysis);
        let (string_score, string_details) = rules::score_strings(&analysis);
        let (packing_score, packing_details) = rules::score_packing(&analysis);
        let (anomaly_score, anomaly_details) = rules::score_anomalies(&analysis);

        // Weighted combination
        let total_score = import_score * 0.35
            + string_score * 0.25
            + packing_score * 0.25
            + anomaly_score * 0.15;

        if total_score < self.threshold {
            return Ok(vec![]);
        }

        // Build detailed report
        let mut all_details = Vec::new();
        if !import_details.is_empty() {
            all_details.push(format!(
                "Suspicious imports ({:.0}%): {}",
                import_score * 100.0,
                import_details.join(", ")
            ));
        }
        if !string_details.is_empty() {
            all_details.push(format!(
                "Suspicious strings ({:.0}%): {}",
                string_score * 100.0,
                string_details.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        if !packing_details.is_empty() {
            all_details.push(format!(
                "Packing indicators ({:.0}%): {}",
                packing_score * 100.0,
                packing_details.join(", ")
            ));
        }
        if !anomaly_details.is_empty() {
            all_details.push(format!(
                "Anomalies ({:.0}%): {}",
                anomaly_score * 100.0,
                anomaly_details.join(", ")
            ));
        }

        let severity = if total_score > 0.8 {
            ThreatSeverity::Critical
        } else if total_score > 0.6 {
            ThreatSeverity::High
        } else if total_score > 0.45 {
            ThreatSeverity::Medium
        } else {
            ThreatSeverity::Low
        };

        let threat_name = if import_score > 0.5 {
            "Heuristic.Suspicious.Imports"
        } else if packing_score > 0.5 {
            "Heuristic.Packed.Generic"
        } else {
            "Heuristic.Suspicious.Generic"
        };

        Ok(vec![Detection::new(
            path.to_path_buf(),
            file_hash,
            threat_name.to_string(),
            severity,
            DetectionSource::Heuristic,
            total_score,
            all_details.join("; "),
        )])
    }

    fn engine_name(&self) -> &str {
        "Heuristic Analysis Engine"
    }
}
