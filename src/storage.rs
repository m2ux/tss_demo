use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Encryption error")]
    Encryption,

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

pub struct KeyStorage {
    storage_path: PathBuf,
    cipher: Aes256Gcm,
}

impl KeyStorage {
    pub fn new(storage_path: impl AsRef<Path>, encryption_key: &str) -> Result<Self, StorageError> {
        // Hash the encryption key to get a fixed 32-byte key
        let mut hasher = Sha256::new();
        hasher.update(encryption_key.as_bytes());
        let key = hasher.finalize();

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| StorageError::Encryption)?;

        Ok(Self {
            storage_path: storage_path.as_ref().to_owned(),
            cipher,
        })
    }

    pub fn save<T: Serialize>(&self, key_id: &str, data: &T) -> Result<(), StorageError> {
        let serialized = bincode::serialize(data)?;
        let nonce = Nonce::from_slice(b"unique nonce"); // In production, generate a unique nonce

        let encrypted = self.cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|_| StorageError::Encryption)?;

        let path = self.storage_path.join(format!("{}.key", key_id));
        std::fs::write(path, encrypted)?;

        Ok(())
    }

    pub fn load<T: for<'de> Deserialize<'de>>(&self, key_id: &str) -> Result<T, StorageError> {
        let path = self.storage_path.join(format!("{}.key", key_id));
        let encrypted = std::fs::read(path)?;

        let nonce = Nonce::from_slice(b"unique nonce"); // Must match the nonce used for encryption
        let decrypted = self.cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| StorageError::Encryption)?;

        Ok(bincode::deserialize(&decrypted)?)
    }
}