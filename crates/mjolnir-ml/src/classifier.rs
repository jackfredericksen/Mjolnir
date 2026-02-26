use serde::{Deserialize, Serialize};
use std::path::Path;

use mjolnir_core::error::{MjolnirError, Result};
use mjolnir_core::threat::{Detection, DetectionEngine, DetectionSource, ThreatSeverity};
use mjolnir_static::StaticAnalyzer;

use crate::features::{FeatureExtractor, FeatureVector, FEATURE_COUNT};

/// A decision stump — the simplest weak learner for boosting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionStump {
    pub feature_idx: usize,
    pub threshold: f64,
    pub polarity: f64,
    pub weight: f64,
}

impl DecisionStump {
    /// Predict: returns +1.0 (malware) or -1.0 (benign)
    fn predict(&self, features: &[f64]) -> f64 {
        let value = features.get(self.feature_idx).copied().unwrap_or(0.0);
        if self.polarity * value < self.polarity * self.threshold {
            -1.0
        } else {
            1.0
        }
    }
}

/// Quantum Annealing-Inspired Optimized (QAIO) Classifier.
///
/// Uses SQA for feature selection and AdaBoost ensemble of decision stumps
/// for classification. The model is trained offline and shipped as a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QAIOClassifier {
    /// Feature indices selected by SQA (subset of 0..FEATURE_COUNT)
    pub selected_features: Vec<usize>,
    /// AdaBoost ensemble of weak learners
    pub stumps: Vec<DecisionStump>,
    /// Classification threshold (above = malware)
    pub threshold: f64,
}

impl QAIOClassifier {
    /// Create a default classifier with pre-tuned parameters.
    /// In production, this would be loaded from a trained model file.
    pub fn default_model() -> Self {
        // Pre-configured stumps based on known malware characteristics.
        // These are hand-tuned defaults; a trained model would replace them.
        Self {
            selected_features: (0..FEATURE_COUNT).collect(), // Use all features initially
            stumps: vec![
                // High overall entropy suggests encryption/packing
                DecisionStump {
                    feature_idx: 278, // overall_entropy feature
                    threshold: 7.0,
                    polarity: 1.0,
                    weight: 0.3,
                },
                // Many imports can indicate complex behavior
                DecisionStump {
                    feature_idx: 273, // import_count feature
                    threshold: 50.0,
                    polarity: 1.0,
                    weight: 0.15,
                },
                // Low printable ratio suggests binary/encrypted content
                DecisionStump {
                    feature_idx: 287, // printable_ratio feature
                    threshold: 0.3,
                    polarity: -1.0,
                    weight: 0.2,
                },
                // Unsigned binary
                DecisionStump {
                    feature_idx: 276, // is_signed feature
                    threshold: 0.5,
                    polarity: -1.0,
                    weight: 0.1,
                },
                // High max section entropy
                DecisionStump {
                    feature_idx: 279, // max_section_entropy
                    threshold: 7.2,
                    polarity: 1.0,
                    weight: 0.25,
                },
            ],
            threshold: 0.3,
        }
    }

    /// Load a trained model from a binary file
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        bincode::deserialize(&data).map_err(|e| MjolnirError::MachineLearning(e.to_string()))
    }

    /// Save the model to a binary file
    pub fn save(&self, path: &Path) -> Result<()> {
        let data =
            bincode::serialize(self).map_err(|e| MjolnirError::MachineLearning(e.to_string()))?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Classify a feature vector. Returns score in [-1.0, 1.0].
    /// Positive = more likely malware, negative = more likely benign.
    pub fn predict(&self, features: &FeatureVector) -> f64 {
        let mut score = 0.0;
        let mut total_weight = 0.0;

        for stump in &self.stumps {
            let prediction = stump.predict(&features.raw);
            score += stump.weight * prediction;
            total_weight += stump.weight;
        }

        if total_weight > 0.0 {
            score / total_weight
        } else {
            0.0
        }
    }

    /// Train the classifier using AdaBoost on labeled samples.
    /// `samples` are feature vectors, `labels` are true for malware.
    pub fn train(
        samples: &[FeatureVector],
        labels: &[bool],
        num_stumps: usize,
        selected_features: &[usize],
    ) -> Self {
        let n = samples.len();
        if n == 0 {
            return Self::default_model();
        }

        // Convert labels to +1/-1
        let y: Vec<f64> = labels.iter().map(|&l| if l { 1.0 } else { -1.0 }).collect();

        // Initialize uniform weights
        let mut weights = vec![1.0 / n as f64; n];
        let mut stumps = Vec::new();

        for _ in 0..num_stumps {
            // Find best stump
            let mut best_stump = DecisionStump {
                feature_idx: 0,
                threshold: 0.0,
                polarity: 1.0,
                weight: 0.0,
            };
            let mut best_error = f64::MAX;

            for &feat_idx in selected_features {
                // Try both polarities
                for &polarity in &[1.0, -1.0] {
                    // Collect feature values to determine thresholds
                    let mut values: Vec<f64> = samples
                        .iter()
                        .map(|s| s.raw.get(feat_idx).copied().unwrap_or(0.0))
                        .collect();
                    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    values.dedup();

                    // Try midpoints as thresholds
                    for window in values.windows(2) {
                        let threshold = (window[0] + window[1]) / 2.0;

                        let stump = DecisionStump {
                            feature_idx: feat_idx,
                            threshold,
                            polarity,
                            weight: 0.0,
                        };

                        // Weighted error
                        let error: f64 = samples
                            .iter()
                            .zip(y.iter())
                            .zip(weights.iter())
                            .map(|((s, &yi), &w)| {
                                let pred = stump.predict(&s.raw);
                                if pred != yi {
                                    w
                                } else {
                                    0.0
                                }
                            })
                            .sum();

                        if error < best_error {
                            best_error = error;
                            best_stump = stump;
                        }
                    }
                }
            }

            // Compute stump weight (AdaBoost alpha)
            let epsilon = best_error.max(1e-10).min(1.0 - 1e-10);
            let alpha = 0.5 * ((1.0 - epsilon) / epsilon).ln();
            best_stump.weight = alpha;

            // Update sample weights
            for i in 0..n {
                let pred = best_stump.predict(&samples[i].raw);
                weights[i] *= (-alpha * y[i] * pred).exp();
            }

            // Normalize weights
            let weight_sum: f64 = weights.iter().sum();
            for w in &mut weights {
                *w /= weight_sum;
            }

            stumps.push(best_stump);
        }

        Self {
            selected_features: selected_features.to_vec(),
            stumps,
            threshold: 0.0, // Balanced threshold
        }
    }
}

/// ML Detection Engine wrapper
pub struct MLEngine {
    classifier: QAIOClassifier,
    detection_threshold: f64,
}

impl MLEngine {
    pub fn new() -> Self {
        Self {
            classifier: QAIOClassifier::default_model(),
            detection_threshold: 0.3,
        }
    }

    pub fn with_model(model_path: &Path) -> Result<Self> {
        let classifier = QAIOClassifier::load(model_path)?;
        Ok(Self {
            classifier,
            detection_threshold: 0.3,
        })
    }
}

impl Default for MLEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionEngine for MLEngine {
    fn scan_file(&self, path: &Path, data: &[u8]) -> Result<Vec<Detection>> {
        // Get static analysis for feature extraction
        let static_info = match StaticAnalyzer::quick_parse(data) {
            Ok(info) => info,
            Err(_) => return Ok(vec![]), // Can't analyze, skip
        };

        let features = FeatureExtractor::extract(data, &static_info);
        let score = self.classifier.predict(&features);

        if score <= self.detection_threshold {
            return Ok(vec![]);
        }

        let file_hash = mjolnir_crypto::FileHasher::hash_bytes(data);
        let confidence = ((score + 1.0) / 2.0).clamp(0.0, 1.0); // Map [-1,1] to [0,1]

        let severity = if confidence > 0.9 {
            ThreatSeverity::Critical
        } else if confidence > 0.7 {
            ThreatSeverity::High
        } else if confidence > 0.5 {
            ThreatSeverity::Medium
        } else {
            ThreatSeverity::Low
        };

        Ok(vec![Detection::new(
            path.to_path_buf(),
            file_hash,
            "ML.Suspicious.QAIO".to_string(),
            severity,
            DetectionSource::MachineLearning,
            confidence,
            format!(
                "Quantum-inspired ML classifier score: {:.3} (threshold: {:.3})",
                score, self.detection_threshold
            ),
        )])
    }

    fn engine_name(&self) -> &str {
        "Quantum-Inspired ML Engine (QAIO)"
    }
}
