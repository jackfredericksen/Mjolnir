use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

use mjolnir_core::error::{MjolnirError, Result};
use mjolnir_core::threat::Detection;
use mjolnir_crypto::AesGcmCipher;

/// A quarantined file entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: Uuid,
    pub original_path: PathBuf,
    pub threat_name: String,
    pub quarantine_time: DateTime<Utc>,
    pub file_hash: String,
    pub file_size: u64,
    pub nonce: [u8; 12],
}

/// Manifest of all quarantined files
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    entries: Vec<QuarantineEntry>,
}

/// Encrypted quarantine vault for isolating detected threats
pub struct QuarantineVault {
    vault_dir: PathBuf,
    cipher: AesGcmCipher,
}

impl QuarantineVault {
    /// Create or open a quarantine vault
    pub fn new(vault_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(vault_dir)?;

        // Load or generate vault key; zeroize raw bytes as soon as the cipher is built
        let key_path = vault_dir.join(".vault_key");
        let mut key = if key_path.exists() {
            let mut key_bytes = std::fs::read(&key_path)?;
            if key_bytes.len() != 32 {
                // Wipe before returning the error
                for b in key_bytes.iter_mut() { *b = 0; }
                return Err(MjolnirError::Quarantine("Invalid vault key length".into()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            // Wipe the heap copy
            for b in key_bytes.iter_mut() { *b = 0; }
            key
        } else {
            let key = AesGcmCipher::generate_key();
            std::fs::write(&key_path, key)?;
            // Set restrictive permissions on the key file
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            key
        };

        let cipher = AesGcmCipher::new(&key);
        // Wipe the stack copy now that the cipher has expanded the key internally
        for b in key.iter_mut() { *b = 0; }

        Ok(Self {
            vault_dir: vault_dir.to_path_buf(),
            cipher,
        })
    }

    /// Quarantine a file: encrypt and move to vault
    pub fn quarantine(&self, path: &Path, detection: &Detection) -> Result<QuarantineEntry> {
        let data = std::fs::read(path)?;
        let file_size = data.len() as u64;

        let id = Uuid::new_v4();
        let nonce = AesGcmCipher::generate_nonce();

        // Encrypt the file
        let encrypted = self
            .cipher
            .encrypt(&nonce, &data)
            .map_err(|e| MjolnirError::Quarantine(e.to_string()))?;

        // Write encrypted blob to vault
        let vault_path = self.vault_dir.join(format!("{}.mjq", id));
        std::fs::write(&vault_path, &encrypted)?;

        // Delete original file
        std::fs::remove_file(path)?;

        let entry = QuarantineEntry {
            id,
            original_path: path.to_path_buf(),
            threat_name: detection.threat_name.clone(),
            quarantine_time: Utc::now(),
            file_hash: detection.file_hash.clone(),
            file_size,
            nonce,
        };

        // Update manifest
        self.add_to_manifest(&entry)?;

        tracing::info!(
            "Quarantined {} -> {}.mjq ({})",
            path.display(),
            id,
            detection.threat_name
        );

        Ok(entry)
    }

    /// Validate that a restore path is safe (no traversal, no system directories).
    fn validate_restore_path(path: &Path) -> Result<()> {
        // Reject any path containing ".." components
        if path.components().any(|c| c == Component::ParentDir) {
            return Err(MjolnirError::Quarantine(
                "Restore path contains path traversal components".into(),
            ));
        }

        // Reject restores into sensitive system directories
        let s = path.to_string_lossy();
        let blocked = [
            "/etc/", "/bin/", "/sbin/", "/lib/", "/lib64/",
            "/boot/", "/sys/", "/proc/", "/dev/",
            "/usr/bin/", "/usr/sbin/", "/usr/lib/",
        ];
        for prefix in &blocked {
            if s.starts_with(prefix) {
                return Err(MjolnirError::Quarantine(format!(
                    "Restoring to system directory '{}' is not permitted",
                    prefix
                )));
            }
        }

        Ok(())
    }

    /// Restore a quarantined file to its original location
    pub fn restore(&self, id: &Uuid) -> Result<PathBuf> {
        let entry = self
            .find_entry(id)?
            .ok_or_else(|| MjolnirError::Quarantine(format!("Entry {} not found", id)))?;

        // Guard against a tampered manifest pointing at system paths
        Self::validate_restore_path(&entry.original_path)?;

        let vault_path = self.vault_dir.join(format!("{}.mjq", id));
        let encrypted = std::fs::read(&vault_path)?;

        // Decrypt
        let decrypted = self
            .cipher
            .decrypt(&entry.nonce, &encrypted)
            .map_err(|e| MjolnirError::Quarantine(e.to_string()))?;

        // Write to original location
        if let Some(parent) = entry.original_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&entry.original_path, &decrypted)?;

        // Remove from vault and manifest
        std::fs::remove_file(&vault_path)?;
        self.remove_from_manifest(id)?;

        tracing::info!(
            "Restored {} from quarantine to {}",
            id,
            entry.original_path.display()
        );

        Ok(entry.original_path)
    }

    /// Permanently delete a quarantined file
    pub fn delete(&self, id: &Uuid) -> Result<()> {
        let vault_path = self.vault_dir.join(format!("{}.mjq", id));
        if vault_path.exists() {
            std::fs::remove_file(&vault_path)?;
        }
        self.remove_from_manifest(id)?;

        tracing::info!("Permanently deleted quarantined file {}", id);
        Ok(())
    }

    /// List all quarantined files
    pub fn list(&self) -> Result<Vec<QuarantineEntry>> {
        Ok(self.load_manifest()?.entries)
    }

    fn manifest_path(&self) -> PathBuf {
        self.vault_dir.join("manifest.json")
    }

    fn load_manifest(&self) -> Result<Manifest> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(Manifest {
                entries: Vec::new(),
            });
        }
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str(&content).map_err(|e| MjolnirError::Quarantine(e.to_string()))
    }

    fn save_manifest(&self, manifest: &Manifest) -> Result<()> {
        let content = serde_json::to_string_pretty(manifest)
            .map_err(|e| MjolnirError::Quarantine(e.to_string()))?;
        std::fs::write(self.manifest_path(), content)?;
        Ok(())
    }

    fn add_to_manifest(&self, entry: &QuarantineEntry) -> Result<()> {
        let mut manifest = self.load_manifest()?;
        manifest.entries.push(entry.clone());
        self.save_manifest(&manifest)
    }

    fn remove_from_manifest(&self, id: &Uuid) -> Result<()> {
        let mut manifest = self.load_manifest()?;
        manifest.entries.retain(|e| e.id != *id);
        self.save_manifest(&manifest)
    }

    fn find_entry(&self, id: &Uuid) -> Result<Option<QuarantineEntry>> {
        let manifest = self.load_manifest()?;
        Ok(manifest.entries.into_iter().find(|e| e.id == *id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mjolnir_core::threat::{DetectionSource, ThreatSeverity};
    use tempfile::TempDir;

    #[test]
    fn test_quarantine_and_restore() {
        let temp = TempDir::new().unwrap();
        let vault_dir = temp.path().join("vault");
        let vault = QuarantineVault::new(&vault_dir).unwrap();

        // Create a test file
        let test_file = temp.path().join("malware.exe");
        std::fs::write(&test_file, b"definitely malicious content").unwrap();

        let detection = Detection::new(
            test_file.clone(),
            "testhash".into(),
            "Test.Malware".into(),
            ThreatSeverity::High,
            DetectionSource::Signature,
            1.0,
            "Test detection".into(),
        );

        // Quarantine
        let entry = vault.quarantine(&test_file, &detection).unwrap();
        assert!(!test_file.exists()); // Original should be deleted
        assert!(vault_dir.join(format!("{}.mjq", entry.id)).exists());

        // List
        let entries = vault.list().unwrap();
        assert_eq!(entries.len(), 1);

        // Restore
        let restored_path = vault.restore(&entry.id).unwrap();
        assert!(restored_path.exists());
        assert_eq!(
            std::fs::read(&restored_path).unwrap(),
            b"definitely malicious content"
        );
    }

    #[test]
    fn test_permanent_delete() {
        let temp = TempDir::new().unwrap();
        let vault_dir = temp.path().join("vault");
        let vault = QuarantineVault::new(&vault_dir).unwrap();

        let test_file = temp.path().join("malware2.exe");
        std::fs::write(&test_file, b"bad stuff").unwrap();

        let detection = Detection::new(
            test_file.clone(),
            "hash2".into(),
            "Test.Malware2".into(),
            ThreatSeverity::Critical,
            DetectionSource::Heuristic,
            0.9,
            "Test".into(),
        );

        let entry = vault.quarantine(&test_file, &detection).unwrap();
        vault.delete(&entry.id).unwrap();

        assert!(vault.list().unwrap().is_empty());
    }
}
