use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use crate::hybrid::CryptoError;

/// AES-256-GCM authenticated encryption for quarantine and transport encryption
pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    /// Create a new cipher from a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("valid 32-byte key");
        Self { cipher }
    }

    /// Generate a random 32-byte key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    /// Generate a random 12-byte nonce
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt plaintext with the given nonce. Returns ciphertext with auth tag.
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from(*nonce);
        self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptoError::Encryption(e.to_string()))
    }

    /// Decrypt ciphertext with the given nonce.
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from(*nonce);
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }

    /// Encrypt with a fresh random nonce. Returns (nonce, ciphertext).
    pub fn encrypt_with_random_nonce(
        &self,
        plaintext: &[u8],
    ) -> Result<([u8; 12], Vec<u8>), CryptoError> {
        let nonce = Self::generate_nonce();
        let ciphertext = self.encrypt(&nonce, plaintext)?;
        Ok((nonce, ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key);
        let plaintext = b"Sensitive quarantined malware data";

        let (nonce, ciphertext) = cipher.encrypt_with_random_nonce(plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = AesGcmCipher::generate_key();
        let key2 = AesGcmCipher::generate_key();
        let cipher1 = AesGcmCipher::new(&key1);
        let cipher2 = AesGcmCipher::new(&key2);

        let (nonce, ciphertext) = cipher1.encrypt_with_random_nonce(b"test").unwrap();
        assert!(cipher2.decrypt(&nonce, &ciphertext).is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key);

        let (_, ciphertext) = cipher.encrypt_with_random_nonce(b"test").unwrap();
        let wrong_nonce = AesGcmCipher::generate_nonce();
        assert!(cipher.decrypt(&wrong_nonce, &ciphertext).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key);

        let (nonce, mut ciphertext) = cipher.encrypt_with_random_nonce(b"test").unwrap();
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(cipher.decrypt(&nonce, &ciphertext).is_err());
    }
}
