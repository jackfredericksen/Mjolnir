use ed25519_dalek::{
    Signature as Ed25519Sig, Signer, SigningKey as Ed25519SigningKey, Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use pqcrypto_dilithium::dilithium3::{
    self, DetachedSignature as DilithiumSig, PublicKey as DilithiumPubKey,
    SecretKey as DilithiumSecKey,
};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::FileHasher;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
}

/// Hybrid public key combining Ed25519 and Dilithium3 for quantum resistance
#[derive(Clone)]
pub struct HybridPublicKey {
    pub classical: Ed25519VerifyingKey,
    pub post_quantum: DilithiumPubKey,
}

impl std::fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridPublicKey")
            .field("classical", &hex::encode(self.classical.as_bytes()))
            .field(
                "post_quantum",
                &format!("[{} bytes]", self.post_quantum.as_bytes().len()),
            )
            .finish()
    }
}

impl HybridPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + dilithium3::public_key_bytes());
        bytes.extend_from_slice(self.classical.as_bytes());
        bytes.extend_from_slice(self.post_quantum.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let ed_size = 32;
        let dil_size = dilithium3::public_key_bytes();

        if bytes.len() != ed_size + dil_size {
            return Err(CryptoError::InvalidPublicKey);
        }

        let ed_bytes: &[u8; 32] = bytes[..ed_size]
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let classical = Ed25519VerifyingKey::from_bytes(ed_bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        let post_quantum = DilithiumPubKey::from_bytes(&bytes[ed_size..])
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(Self {
            classical,
            post_quantum,
        })
    }
}

impl Serialize for HybridPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for HybridPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        HybridPublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Hybrid keypair combining Ed25519 and Dilithium3
pub struct HybridKeypair {
    classical_secret: Ed25519SigningKey,
    classical_public: Ed25519VerifyingKey,
    post_quantum_secret: DilithiumSecKey,
    post_quantum_public: DilithiumPubKey,
}

impl HybridKeypair {
    /// Generate a new random hybrid keypair
    pub fn generate() -> Self {
        let classical_secret = Ed25519SigningKey::generate(&mut OsRng);
        let classical_public = classical_secret.verifying_key();
        let (post_quantum_public, post_quantum_secret) = dilithium3::keypair();

        Self {
            classical_secret,
            classical_public,
            post_quantum_secret,
            post_quantum_public,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            classical: self.classical_public,
            post_quantum: self.post_quantum_public.clone(),
        }
    }

    /// Sign a message with both signature schemes
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let hash_bytes = FileHasher::hash_raw(message);

        let classical = self.classical_secret.sign(&hash_bytes);
        let post_quantum =
            dilithium3::detached_sign(&hash_bytes, &self.post_quantum_secret);

        HybridSignature {
            classical,
            post_quantum,
        }
    }

    /// Serialize the keypair to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.classical_secret.as_bytes());
        bytes.extend_from_slice(self.post_quantum_secret.as_bytes());
        bytes.extend_from_slice(self.post_quantum_public.as_bytes());
        bytes
    }

    /// Deserialize a keypair from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let ed_secret_size = 32;
        let dil_secret_size = dilithium3::secret_key_bytes();
        let dil_public_size = dilithium3::public_key_bytes();

        if bytes.len() != ed_secret_size + dil_secret_size + dil_public_size {
            return Err(CryptoError::InvalidSecretKey);
        }

        let ed_secret_bytes: &[u8; 32] = bytes[..ed_secret_size]
            .try_into()
            .map_err(|_| CryptoError::InvalidSecretKey)?;
        let classical_secret = Ed25519SigningKey::from_bytes(ed_secret_bytes);
        let classical_public = classical_secret.verifying_key();

        let dil_secret_start = ed_secret_size;
        let dil_public_start = ed_secret_size + dil_secret_size;

        let post_quantum_secret =
            DilithiumSecKey::from_bytes(&bytes[dil_secret_start..dil_public_start])
                .map_err(|_| CryptoError::InvalidSecretKey)?;
        let post_quantum_public = DilithiumPubKey::from_bytes(&bytes[dil_public_start..])
            .map_err(|_| CryptoError::InvalidSecretKey)?;

        Ok(Self {
            classical_secret,
            classical_public,
            post_quantum_secret,
            post_quantum_public,
        })
    }
}

/// Hybrid signature combining Ed25519 and Dilithium3.
/// Both signatures must verify for the overall signature to be valid.
#[derive(Clone)]
pub struct HybridSignature {
    pub classical: Ed25519Sig,
    pub post_quantum: DilithiumSig,
}

impl std::fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSignature")
            .field(
                "classical",
                &hex::encode(&self.classical.to_bytes()[..8]),
            )
            .field(
                "post_quantum",
                &format!("[{} bytes]", self.post_quantum.as_bytes().len()),
            )
            .finish()
    }
}

impl HybridSignature {
    /// Verify the signature against a public key and message.
    /// Both Ed25519 and Dilithium signatures must verify.
    pub fn verify(
        &self,
        public_key: &HybridPublicKey,
        message: &[u8],
    ) -> Result<(), CryptoError> {
        let hash_bytes = FileHasher::hash_raw(message);

        // Verify Ed25519
        public_key
            .classical
            .verify(&hash_bytes, &self.classical)
            .map_err(|_| CryptoError::InvalidSignature)?;

        // Verify Dilithium
        dilithium3::verify_detached_signature(
            &self.post_quantum,
            &hash_bytes,
            &public_key.post_quantum,
        )
        .map_err(|_| CryptoError::InvalidSignature)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + dilithium3::signature_bytes());
        bytes.extend_from_slice(&self.classical.to_bytes());
        bytes.extend_from_slice(self.post_quantum.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let ed_size = 64;
        let dil_size = dilithium3::signature_bytes();

        if bytes.len() != ed_size + dil_size {
            return Err(CryptoError::InvalidSignature);
        }

        let ed_sig_bytes: &[u8; 64] = bytes[..ed_size]
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let classical = Ed25519Sig::from_bytes(ed_sig_bytes);

        let post_quantum = DilithiumSig::from_bytes(&bytes[ed_size..])
            .map_err(|_| CryptoError::InvalidSignature)?;

        Ok(Self {
            classical,
            post_quantum,
        })
    }
}

impl Serialize for HybridSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for HybridSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        HybridSignature::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = HybridKeypair::generate();
        let pk = kp.public_key();
        assert_eq!(pk.to_bytes().len(), 32 + dilithium3::public_key_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = HybridKeypair::generate();
        let message = b"Hello, Mjolnir!";
        let signature = kp.sign(message);
        let pk = kp.public_key();
        assert!(signature.verify(&pk, message).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let kp = HybridKeypair::generate();
        let message = b"Hello, Mjolnir!";
        let signature = kp.sign(message);
        let pk = kp.public_key();
        assert!(signature.verify(&pk, b"Wrong message").is_err());
    }

    #[test]
    fn test_wrong_key() {
        let kp1 = HybridKeypair::generate();
        let kp2 = HybridKeypair::generate();
        let message = b"Hello, Mjolnir!";
        let signature = kp1.sign(message);
        assert!(signature.verify(&kp2.public_key(), message).is_err());
    }

    #[test]
    fn test_keypair_serialization() {
        let kp = HybridKeypair::generate();
        let bytes = kp.to_bytes();
        let recovered = HybridKeypair::from_bytes(&bytes).unwrap();
        let message = b"Test roundtrip";
        let sig = recovered.sign(message);
        assert!(sig.verify(&kp.public_key(), message).is_ok());
    }

    #[test]
    fn test_signature_serialization() {
        let kp = HybridKeypair::generate();
        let message = b"Test message";
        let signature = kp.sign(message);
        let bytes = signature.to_bytes();
        let recovered = HybridSignature::from_bytes(&bytes).unwrap();
        assert!(recovered.verify(&kp.public_key(), message).is_ok());
    }
}
