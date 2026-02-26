use std::io::Read;
use std::path::Path;

/// BLAKE3-based file hashing
pub struct FileHasher;

impl FileHasher {
    /// Hash raw bytes
    pub fn hash_bytes(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    /// Hash a file from disk (streaming for large files)
    pub fn hash_file(path: &Path) -> std::io::Result<String> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 65536];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Hash used internally for signing (returns raw bytes)
    pub fn hash_raw(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes() {
        let hash = FileHasher::hash_bytes(b"hello world");
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = FileHasher::hash_bytes(b"test data");
        let h2 = FileHasher::hash_bytes(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let h1 = FileHasher::hash_bytes(b"data1");
        let h2 = FileHasher::hash_bytes(b"data2");
        assert_ne!(h1, h2);
    }
}
