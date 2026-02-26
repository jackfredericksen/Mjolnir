use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::Path;

use mjolnir_core::error::{MjolnirError, Result};
use mjolnir_core::threat::ThreatSeverity;

/// Information about a known threat (from hash database)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub name: String,
    pub severity: ThreatSeverity,
    pub family: String,
    pub description: String,
}

/// Signature database containing known-bad hashes and metadata
pub struct SignatureDatabase {
    /// BLAKE3 hash -> threat info for instant lookups
    hash_db: DashMap<String, ThreatInfo>,
    /// Database version for update tracking
    pub version: u64,
}

impl SignatureDatabase {
    /// Create a new empty signature database
    pub fn new() -> Self {
        Self {
            hash_db: DashMap::new(),
            version: 0,
        }
    }

    /// Load from a JSON file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let entries: Vec<HashEntry> =
            serde_json::from_str(&content).map_err(|e| MjolnirError::SignatureDb(e.to_string()))?;

        let db = Self::new();
        for entry in entries {
            db.hash_db.insert(entry.hash, entry.info);
        }

        Ok(db)
    }

    /// Load built-in default database with common test signatures
    pub fn load_defaults() -> Self {
        let mut db = Self::new();

        // EICAR test file hash (standard AV test pattern)
        db.hash_db.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            ThreatInfo {
                name: "EICAR-Test-File".to_string(),
                severity: ThreatSeverity::Low,
                family: "Test".to_string(),
                description: "EICAR antivirus test file".to_string(),
            },
        );

        db.version = 1;
        db
    }

    /// Quick hash lookup
    pub fn check_hash(&self, hash: &str) -> Option<ThreatInfo> {
        self.hash_db.get(hash).map(|entry| entry.value().clone())
    }

    /// Add a hash entry
    pub fn insert(&self, hash: String, info: ThreatInfo) {
        self.hash_db.insert(hash, info);
    }

    /// Number of entries
    pub fn len(&self) -> usize {
        self.hash_db.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hash_db.is_empty()
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct HashEntry {
    hash: String,
    info: ThreatInfo,
}
