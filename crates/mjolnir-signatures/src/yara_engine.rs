use std::path::Path;

use mjolnir_core::error::{MjolnirError, Result};
use mjolnir_core::threat::{Detection, DetectionEngine, DetectionSource, ThreatSeverity};

use crate::database::SignatureDatabase;

/// YARA-based signature scanning engine
pub struct YaraEngine {
    rules: Option<yara_x::Rules>,
    pub database: SignatureDatabase,
}

impl YaraEngine {
    /// Create a new YARA engine with compiled rules
    pub fn new(rules_dir: &Path) -> Result<Self> {
        let rules = Self::compile_rules(rules_dir)?;
        let database = SignatureDatabase::load_defaults();

        Ok(Self {
            rules: Some(rules),
            database,
        })
    }

    /// Create with just the hash database (no YARA rules)
    pub fn with_database(database: SignatureDatabase) -> Self {
        Self {
            rules: None,
            database,
        }
    }

    /// Compile all .yar files from a directory
    fn compile_rules(rules_dir: &Path) -> Result<yara_x::Rules> {
        let mut compiler = yara_x::Compiler::new();

        if rules_dir.exists() {
            Self::load_rules_recursive(rules_dir, &mut compiler)?;
        }

        let rules = compiler
            .build();

        Ok(rules)
    }

    fn load_rules_recursive(dir: &Path, compiler: &mut yara_x::Compiler) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                Self::load_rules_recursive(&path, compiler)?;
            } else if path.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false) {
                let content = std::fs::read_to_string(&path)?;
                compiler
                    .add_source(content.as_str())
                    .map_err(|e| MjolnirError::Yara(format!("{}: {}", path.display(), e)))?;
            }
        }

        Ok(())
    }

    /// Reload rules from disk without restarting
    pub fn reload_rules(&mut self, rules_dir: &Path) -> Result<()> {
        self.rules = Some(Self::compile_rules(rules_dir)?);
        Ok(())
    }

    /// Scan file data with YARA rules
    fn yara_scan(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let rules = match &self.rules {
            Some(r) => r,
            None => return Ok(vec![]),
        };

        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner
            .scan(data)
            .map_err(|e| MjolnirError::Yara(e.to_string()))?;

        let matches: Vec<YaraMatch> = results
            .matching_rules()
            .map(|rule| YaraMatch {
                rule_name: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags: rule
                    .tags()
                    .map(|t| t.identifier().to_string())
                    .collect(),
            })
            .collect();

        Ok(matches)
    }
}

struct YaraMatch {
    rule_name: String,
    namespace: String,
    tags: Vec<String>,
}

impl DetectionEngine for YaraEngine {
    fn scan_file(&self, path: &Path, data: &[u8]) -> Result<Vec<Detection>> {
        let mut detections = Vec::new();
        let file_hash = mjolnir_crypto::FileHasher::hash_bytes(data);

        // 1. Quick hash lookup
        if let Some(threat) = self.database.check_hash(&file_hash) {
            detections.push(Detection::new(
                path.to_path_buf(),
                file_hash.clone(),
                threat.name.clone(),
                threat.severity,
                DetectionSource::Signature,
                1.0,
                format!("Known threat: {} ({})", threat.family, threat.description),
            ));
        }

        // 2. YARA rule matching
        match self.yara_scan(data) {
            Ok(matches) => {
                for m in matches {
                    let severity = if m.tags.contains(&"critical".to_string()) {
                        ThreatSeverity::Critical
                    } else if m.tags.contains(&"high".to_string()) {
                        ThreatSeverity::High
                    } else if m.tags.contains(&"medium".to_string()) {
                        ThreatSeverity::Medium
                    } else {
                        ThreatSeverity::Low
                    };

                    detections.push(Detection::new(
                        path.to_path_buf(),
                        file_hash.clone(),
                        m.rule_name.clone(),
                        severity,
                        DetectionSource::Signature,
                        0.95,
                        format!(
                            "YARA rule match: {} (namespace: {})",
                            m.rule_name, m.namespace
                        ),
                    ));
                }
            }
            Err(e) => {
                tracing::warn!("YARA scan error for {}: {}", path.display(), e);
            }
        }

        Ok(detections)
    }

    fn engine_name(&self) -> &str {
        "Signature Engine (YARA + Hash DB)"
    }
}
