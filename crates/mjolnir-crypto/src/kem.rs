use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey, SharedSecret};

use crate::hybrid::CryptoError;

/// CRYSTALS-Kyber Key Encapsulation Mechanism for quantum-resistant key exchange.
/// Used to establish shared secrets for the secure update channel.
pub struct KyberKEM;

/// A Kyber keypair for key encapsulation
pub struct KyberKeypair {
    pub public_key: kyber1024::PublicKey,
    pub secret_key: kyber1024::SecretKey,
}

/// Result of key encapsulation: shared secret + ciphertext to send to receiver
pub struct EncapsulatedKey {
    pub shared_secret: Vec<u8>,
    pub ciphertext: kyber1024::Ciphertext,
}

impl KyberKEM {
    /// Generate a new Kyber1024 keypair
    pub fn keypair() -> KyberKeypair {
        let (pk, sk) = kyber1024::keypair();
        KyberKeypair {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Encapsulate: generate a shared secret and ciphertext for the given public key.
    /// The sender calls this with the receiver's public key.
    pub fn encapsulate(pk: &kyber1024::PublicKey) -> EncapsulatedKey {
        let (ss, ct) = kyber1024::encapsulate(pk);
        EncapsulatedKey {
            shared_secret: ss.as_bytes().to_vec(),
            ciphertext: ct,
        }
    }

    /// Decapsulate: recover the shared secret from a ciphertext using the secret key.
    /// The receiver calls this with their secret key.
    pub fn decapsulate(
        ct: &kyber1024::Ciphertext,
        sk: &kyber1024::SecretKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let ss = kyber1024::decapsulate(ct, sk);
        Ok(ss.as_bytes().to_vec())
    }
}

impl KyberKeypair {
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<kyber1024::PublicKey, CryptoError> {
        kyber1024::PublicKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip() {
        let receiver = KyberKEM::keypair();

        // Sender encapsulates with receiver's public key
        let encap = KyberKEM::encapsulate(&receiver.public_key);

        // Receiver decapsulates with their secret key
        let decap_secret =
            KyberKEM::decapsulate(&encap.ciphertext, &receiver.secret_key).unwrap();

        // Both sides should have the same shared secret
        assert_eq!(encap.shared_secret, decap_secret);
        assert!(!encap.shared_secret.is_empty());
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let receiver = KyberKEM::keypair();
        let encap1 = KyberKEM::encapsulate(&receiver.public_key);
        let encap2 = KyberKEM::encapsulate(&receiver.public_key);

        // Each encapsulation should produce a different shared secret
        assert_ne!(encap1.shared_secret, encap2.shared_secret);
    }
}
