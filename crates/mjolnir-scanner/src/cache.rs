use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Cached scan result for a file (keyed by BLAKE3 hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub file_hash: String,
    pub last_scanned: DateTime<Utc>,
    pub db_version: u64,
    pub is_clean: bool,
}

/// Thread-safe scan cache to skip files that haven't changed
pub struct ScanCache {
    entries: DashMap<String, CacheEntry>,
}

impl ScanCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Check if a file hash is cached and the DB version matches
    pub fn is_cached(&self, hash: &str, current_db_version: u64) -> Option<bool> {
        self.entries.get(hash).and_then(|entry| {
            if entry.db_version == current_db_version {
                Some(entry.is_clean)
            } else {
                None // DB updated, need to rescan
            }
        })
    }

    /// Insert or update a cache entry
    pub fn insert(&self, hash: String, db_version: u64, is_clean: bool) {
        self.entries.insert(
            hash.clone(),
            CacheEntry {
                file_hash: hash,
                last_scanned: Utc::now(),
                db_version,
                is_clean,
            },
        );
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Number of cached entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ScanCache {
    fn default() -> Self {
        Self::new()
    }
}
