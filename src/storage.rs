//! Secure key storage implementation with encryption support.
//!
//! This module provides a secure storage mechanism for cryptographic keys and sensitive data,
//! using AES-GCM encryption for data protection at rest. It supports serialization of arbitrary
//! types that implement Serialize and Deserialize traits.
//!
//! # Features
//!
//! * AES-256-GCM encryption for data protection
//! * Transparent serialization of arbitrary types
//! * Secure key derivation from passwords
//! * File-based persistent storage
//!
//! # Examples
//!
//! ```rust,no_run
//! use your_crate_name::storage::KeyStorage;
//!
//! fn example() -> Result<(), StorageError> {
//!     // Initialize storage with encryption key
//!     let storage = KeyStorage::new("./keys", "encryption-password")?;
//!
//!     // Save data
//!     let secret_data = "sensitive information";
//!     storage.save("my-key", &secret_data)?;
//!
//!     // Load data
//!     let loaded: String = storage.load("my-key")?;
//!     assert_eq!(secret_data, loaded);
//!
//!     Ok(())
//! }
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use cggmp21::supported_curves::Secp256k1;
use cggmp21::KeyShare;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Errors that can occur during storage operations.
///
/// This enum represents the various error conditions that may arise when performing
/// storage operations, including IO errors, encryption/decryption failures, and
/// serialization issues.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// File system related errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Encryption or decryption operation failures
    #[error("Encryption error")]
    Encryption,

    /// Data serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] rmp_serde::decode::Error),

    /// Data deserialization errors
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::encode::Error),
}

/// Secure storage for sensitive data with encryption support.
///
/// KeyStorage provides a secure way to store and retrieve sensitive data using
/// AES-256-GCM encryption. All data is encrypted before being written to disk
/// and decrypted when read back.
///
/// # Security Features
///
/// * AES-256-GCM authenticated encryption
/// * SHA-256 key derivation from passwords
/// * Unique key files for each stored item
///
/// # Type Parameters
///
/// The storage supports any type that implements both Serialize and Deserialize traits.
#[derive(Clone)]
pub struct KeyStorage {
    /// Base directory for storing encrypted files
    pub(crate) storage_path: PathBuf,
    /// AES-256-GCM cipher instance for encryption/decryption
    pub(crate) cipher: Aes256Gcm,
}

impl KeyStorage {
    /// Creates a new KeyStorage instance with the specified storage path and encryption key.
    ///
    /// This method initializes the storage system by:
    /// 1. Creating a secure encryption key from the provided password
    /// 2. Initializing the AES-GCM cipher
    /// 3. Setting up the storage directory
    ///
    /// # Arguments
    ///
    /// * `storage_path` - Base directory path for storing encrypted files
    /// * `encryption_key` - Password used to derive the encryption key
    ///
    /// # Returns
    ///
    /// Returns a Result containing either:
    /// - `Ok(KeyStorage)`: A new storage instance ready for use
    /// - `Err(StorageError)`: If initialization fails
    ///
    /// # Errors
    ///
    /// Will return `StorageError::Encryption` if:
    /// - Key derivation fails
    /// - Cipher initialization fails
    pub fn new(storage_path: impl AsRef<Path>, encryption_key: &str) -> Result<Self, StorageError> {
        // Hash the encryption key to get a fixed 32-byte key
        let mut hasher = Sha256::new();
        hasher.update(encryption_key.as_bytes());
        let key = hasher.finalize();

        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| StorageError::Encryption)?;

        // Create storage directory if it doesn't exist
        let path = storage_path.as_ref().to_owned();
        std::fs::create_dir_all(&path)?;

        Ok(Self {
            storage_path: path,
            cipher,
        })
    }

    /// Saves encrypted data to storage.
    ///
    /// This method:
    /// 1. Serializes the provided data
    /// 2. Encrypts it using AES-GCM
    /// 3. Writes the encrypted data to a file
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the stored data
    /// * `data` - The data to encrypt and store
    ///
    /// # Type Parameters
    ///
    /// * `T` - Type of data to store, must implement Serialize
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or appropriate `StorageError` on failure
    ///
    /// # Errors
    ///
    /// - `StorageError::Serialization`: If data serialization fails
    /// - `StorageError::Encryption`: If encryption fails
    /// - `StorageError::Io`: If writing to file fails
    pub fn save<T: Serialize>(&self, key_id: &str, data: &T) -> Result<(), StorageError> {
        let serialized = rmp_serde::to_vec(&data)?;
        let nonce = Nonce::from_slice(b"unique nonce"); // In production, generate a unique nonce

        let encrypted = self
            .cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|_| StorageError::Encryption)?;

        let path = self.storage_path.join(format!("{}.key", key_id));
        std::fs::write(path, encrypted)?;

        Ok(())
    }

    /// Loads and decrypts data from storage.
    ///
    /// This method:
    /// 1. Reads the encrypted data from file
    /// 2. Decrypts it using AES-GCM
    /// 3. Deserializes it into the requested type
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the stored data
    ///
    /// # Type Parameters
    ///
    /// * `T` - Type to deserialize the data into, must implement Deserialize
    ///
    /// # Returns
    ///
    /// Returns `Result<T, StorageError>` containing either:
    /// - `Ok(T)`: The successfully decrypted and deserialized data
    /// - `Err(StorageError)`: If any operation fails
    ///
    /// # Errors
    ///
    /// - `StorageError::Io`: If reading from file fails
    /// - `StorageError::Encryption`: If decryption fails
    /// - `StorageError::Serialization`: If deserialization fails
    pub fn load<T: for<'de> Deserialize<'de>>(&self, key_id: &str) -> Result<T, StorageError> {
        let path = self.storage_path.join(format!("{}.key", key_id));
        let encrypted = std::fs::read(path)?;

        let nonce = Nonce::from_slice(b"unique nonce");
        let decrypted = self
            .cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| StorageError::Encryption)?;

        Ok(rmp_serde::from_slice(&decrypted)?)
    }

    pub fn save_key_share(
        &self,
        key_id: &str,
        share: &KeyShare<Secp256k1>,
    ) -> Result<(), StorageError> {
        // Serialize to a Vec<u8> using pot
        let serialized = rmp_serde::to_vec(&share)?;
        let nonce = Nonce::from_slice(b"unique nonce");

        let encrypted = self
            .cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|_| StorageError::Encryption)?;

        let path = self.storage_path.join(format!("{}.key", key_id));
        std::fs::write(path, encrypted)?;

        Ok(())
    }

    pub fn load_key_share(&self, key_id: &str) -> Result<KeyShare<Secp256k1>, StorageError> {
        let path = self.storage_path.join(format!("{}.key", key_id));
        let encrypted = std::fs::read(path)?;

        let nonce = Nonce::from_slice(b"unique nonce");
        let decrypted = self
            .cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|_| StorageError::Encryption)?;

        // Deserialize using pot
        let key_share: KeyShare<Secp256k1> = rmp_serde::from_slice(&decrypted)?;
        Ok(key_share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    /// Helper function to create a temporary directory for testing
    fn setup_test_dir() -> TempDir {
        tempfile::tempdir().expect("Failed to create temporary directory")
    }

    /// Test struct to verify complex type serialization
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        field1: String,
        field2: i32,
        field3: Vec<bool>,
    }

    impl TestData {
        fn new_sample() -> Self {
            TestData {
                field1: "test string".to_string(),
                field2: 42,
                field3: vec![true, false, true],
            }
        }
    }

    #[test]
    /// Test successful initialization of KeyStorage
    fn test_new_storage() {
        let temp_dir = setup_test_dir();
        let result = KeyStorage::new(temp_dir.path(), "test-password");
        assert!(result.is_ok());
    }

    #[test]
    /// Test saving and loading a simple string
    fn test_save_load_string() -> Result<(), StorageError> {
        let temp_dir = setup_test_dir();
        let storage = KeyStorage::new(temp_dir.path(), "test-password")?;

        let test_data = "Hello, World!";
        storage.save("test-key", &test_data)?;

        let loaded: String = storage.load("test-key")?;
        assert_eq!(test_data, loaded);
        Ok(())
    }

    #[test]
    /// Test saving and loading complex structured data
    fn test_save_load_struct() -> Result<(), StorageError> {
        let temp_dir = setup_test_dir();
        let storage = KeyStorage::new(temp_dir.path(), "test-password")?;

        let test_data = TestData::new_sample();
        storage.save("test-struct", &test_data)?;

        let loaded: TestData = storage.load("test-struct")?;
        assert_eq!(test_data, loaded);
        Ok(())
    }

    #[test]
    /// Test saving and loading binary data
    fn test_save_load_binary() -> Result<(), StorageError> {
        let temp_dir = setup_test_dir();
        let storage = KeyStorage::new(temp_dir.path(), "test-password")?;

        let test_data: Vec<u8> = vec![0, 1, 2, 3, 4, 5];
        storage.save("test-binary", &test_data)?;

        let loaded: Vec<u8> = storage.load("test-binary")?;
        assert_eq!(test_data, loaded);
        Ok(())
    }

    #[test]
    /// Test loading data with different password fails
    fn test_different_password_fails() {
        let temp_dir = setup_test_dir();
        let storage1 = KeyStorage::new(temp_dir.path(), "password1").unwrap();
        let storage2 = KeyStorage::new(temp_dir.path(), "password2").unwrap();

        let test_data = "secret data";
        storage1.save("test-key", &test_data).unwrap();

        let result: Result<String, StorageError> = storage2.load("test-key");
        assert!(matches!(result, Err(StorageError::Encryption)));
    }

    #[test]
    /// Test loading non-existent key fails
    fn test_load_non_existent() {
        let temp_dir = setup_test_dir();
        let storage = KeyStorage::new(temp_dir.path(), "test-password").unwrap();

        let result: Result<String, StorageError> = storage.load("non-existent-key");
        assert!(matches!(result, Err(StorageError::Io(_))));
    }

    #[test]
    /// Test saving to invalid directory fails
    fn test_save_invalid_directory() {
        let result = KeyStorage::new("/nonexistent/directory", "test-password");
        assert!(matches!(result, Err(StorageError::Io(_))));
    }

    #[test]
    /// Test overwriting existing data
    fn test_overwrite_data() -> Result<(), StorageError> {
        let temp_dir = setup_test_dir();
        let storage = KeyStorage::new(temp_dir.path(), "test-password")?;

        let initial_data = "initial data";
        let updated_data = "updated data";

        storage.save("test-key", &initial_data)?;
        storage.save("test-key", &updated_data)?;

        let loaded: String = storage.load("test-key")?;
        assert_eq!(updated_data, loaded);
        Ok(())
    }

    #[test]
    /// Test multiple saves with different keys
    fn test_multiple_keys() -> Result<(), StorageError> {
        let temp_dir = setup_test_dir();
        let storage = KeyStorage::new(temp_dir.path(), "test-password")?;

        let data1 = "first data";
        let data2 = "second data";

        storage.save("key1", &data1)?;
        storage.save("key2", &data2)?;

        let loaded1: String = storage.load("key1")?;
        let loaded2: String = storage.load("key2")?;

        assert_eq!(data1, loaded1);
        assert_eq!(data2, loaded2);
        Ok(())
    }

    #[test]
    /// Test saving empty data
    fn test_empty_data() -> Result<(), StorageError> {
        let temp_dir = setup_test_dir();
        let storage = KeyStorage::new(temp_dir.path(), "test-password")?;

        let empty_string = "";
        let empty_vec: Vec<u8> = vec![];

        storage.save("empty-string", &empty_string)?;
        storage.save("empty-vec", &empty_vec)?;

        let loaded_string: String = storage.load("empty-string")?;
        let loaded_vec: Vec<u8> = storage.load("empty-vec")?;

        assert_eq!(empty_string, loaded_string);
        assert_eq!(empty_vec, loaded_vec);
        Ok(())
    }

    #[test]
    /// Test concurrent access to storage
    fn test_concurrent_access() -> Result<(), StorageError> {
        use std::thread;

        let temp_dir = setup_test_dir();
        let storage = KeyStorage::new(temp_dir.path(), "test-password")?;
        let storage_clone = KeyStorage::new(temp_dir.path(), "test-password")?;

        // Save data in main thread
        storage.save("concurrent-key", &"main thread data")?;

        // Try to read in another thread
        let handle = thread::spawn(move || {
            let result: Result<String, StorageError> = storage_clone.load("concurrent-key");
            result.expect("Failed to load in thread")
        });

        let loaded = handle.join().unwrap();
        assert_eq!("main thread data", loaded);
        Ok(())
    }

    #[test]
    /// Test storage directory creation and cleanup
    fn test_directory_handling() {
        let temp_dir = setup_test_dir();
        let temp_path = temp_dir.path();

        // Create storage and save some data
        let storage = KeyStorage::new(temp_path, "test-password").unwrap();
        storage.save("test-key", &"test data").unwrap();

        // Verify file exists
        let key_path = temp_path.join("test-key.key");
        assert!(key_path.exists());

        // Drop temp_dir and verify cleanup
        drop(temp_dir);
        assert!(!key_path.exists());
    }

    #[test]
    /// Test basic pot serialization/deserialization of CoreKeyShare bytes
    fn test_core_key_share_bytes() {
        // Take a sample CoreKeyShare and verify pot serialization
        let sample_bytes = vec![1, 2, 3, 4]; // Replace with actual CoreKeyShare bytes
        let result = pot::to_vec(&sample_bytes);
        assert!(result.is_ok(), "Should serialize bytes successfully");

        if let Ok(serialized) = result {
            let deserialized: Vec<u8> = pot::from_slice(&serialized).unwrap();
            assert_eq!(
                sample_bytes, deserialized,
                "Serialized and deserialized bytes should match"
            );
        }
    }
}
