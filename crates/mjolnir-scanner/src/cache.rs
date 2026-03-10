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

/// Maximum number of entries before the cache is cleared.
/// At ~150 bytes per entry this caps cache RAM at ≈ 7.5 MB.
const CACHE_MAX_ENTRIES: usize = 50_000;

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

    /// Insert or update a cache entry.
    /// If the cache is at capacity it is cleared before inserting so that
    /// a single long-running Full scan cannot grow the map without bound.
    pub fn insert(&self, hash: String, db_version: u64, is_clean: bool) {
        if self.entries.len() >= CACHE_MAX_ENTRIES {
            self.entries.clear();
        }
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
