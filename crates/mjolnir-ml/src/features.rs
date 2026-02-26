use mjolnir_static::StaticAnalysisResult;
use ndarray::Array1;
use serde::{Deserialize, Serialize};

/// Total number of features extracted per file
pub const FEATURE_COUNT: usize = 296;

/// A feature vector extracted from a file for ML classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub raw: Vec<f64>,
}

impl FeatureVector {
    pub fn as_array(&self) -> Array1<f64> {
        Array1::from_vec(self.raw.clone())
    }
}

pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Extract features from raw file bytes and static analysis results.
    ///
    /// Feature layout (296 total):
    ///   [0..256]   - Byte histogram (frequency of each byte value)
    ///   [256..272] - Windowed entropy (16 windows across the file)
    ///   [272..282] - Structural features (section count, import count, etc.)
    ///   [282..292] - String statistics
    ///   [292..296] - File metadata
    pub fn extract(data: &[u8], static_info: &StaticAnalysisResult) -> FeatureVector {
        let mut features = Vec::with_capacity(FEATURE_COUNT);

        // 1. Byte histogram (256 features) — normalized frequency of each byte value
        let mut byte_counts = [0u64; 256];
        for &b in data {
            byte_counts[b as usize] += 1;
        }
        let len = data.len().max(1) as f64;
        for count in &byte_counts {
            features.push(*count as f64 / len);
        }

        // 2. Windowed entropy (16 features)
        let entropy_windows = mjolnir_static::entropy::windowed_entropy(
            data,
            data.len() / 16.max(1).max(256),
            data.len() / 16.max(1).max(256),
        );
        for i in 0..16 {
            features.push(entropy_windows.get(i).copied().unwrap_or(0.0));
        }

        // 3. Structural features (10 features)
        features.push(static_info.sections.len() as f64);
        features.push(static_info.imports.len() as f64);
        features.push(static_info.exports.len() as f64);
        features.push(static_info.entry_point as f64 / len);
        features.push(if static_info.is_signed { 1.0 } else { 0.0 });
        features.push(static_info.overlay_size as f64 / len);
        features.push(static_info.overall_entropy);

        // Section entropy stats
        let section_entropies: Vec<f64> = static_info
            .sections
            .iter()
            .map(|s| s.entropy)
            .collect();
        let max_entropy = section_entropies
            .iter()
            .copied()
            .fold(0.0f64, f64::max);
        let min_entropy = section_entropies
            .iter()
            .copied()
            .fold(8.0f64, f64::min);
        let avg_entropy = if section_entropies.is_empty() {
            0.0
        } else {
            section_entropies.iter().sum::<f64>() / section_entropies.len() as f64
        };
        features.push(max_entropy);
        features.push(min_entropy);
        features.push(avg_entropy);

        // 4. String statistics (10 features)
        let total_strings = static_info.strings.len() as f64;
        let avg_string_len = if static_info.strings.is_empty() {
            0.0
        } else {
            static_info
                .strings
                .iter()
                .map(|s| s.value.len() as f64)
                .sum::<f64>()
                / total_strings
        };
        let max_string_len = static_info
            .strings
            .iter()
            .map(|s| s.value.len())
            .max()
            .unwrap_or(0) as f64;

        // Count URLs, IPs, paths in strings
        let url_count = static_info
            .strings
            .iter()
            .filter(|s| s.value.starts_with("http://") || s.value.starts_with("https://"))
            .count() as f64;
        let path_count = static_info
            .strings
            .iter()
            .filter(|s| s.value.contains(":\\") || s.value.starts_with("/"))
            .count() as f64;

        // Printable ratio
        let printable_count = data.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count() as f64;
        let printable_ratio = printable_count / len;

        // Null byte ratio
        let null_ratio = byte_counts[0] as f64 / len;

        features.push(total_strings);
        features.push(avg_string_len);
        features.push(max_string_len);
        features.push(url_count);
        features.push(path_count);
        features.push(printable_ratio);
        features.push(null_ratio);
        features.push(0.0); // reserved
        features.push(0.0); // reserved
        features.push(0.0); // reserved

        // 5. File metadata (4 features)
        features.push((data.len() as f64).ln()); // log file size
        features.push(match static_info.format {
            mjolnir_static::BinaryFormat::PE => 1.0,
            mjolnir_static::BinaryFormat::ELF => 2.0,
            mjolnir_static::BinaryFormat::MachO => 3.0,
            mjolnir_static::BinaryFormat::Unknown => 0.0,
        });
        features.push(0.0); // reserved
        features.push(0.0); // reserved

        // Ensure exact feature count
        features.resize(FEATURE_COUNT, 0.0);

        FeatureVector { raw: features }
    }
}
