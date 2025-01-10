use crate::network;
use crate::storage;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Protocol error: {0}")]
    Protocol(#[from] cggmp21::KeygenError),

    #[error("Network error: {0}")]
    Network(#[from] network::NetworkError),

    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),

    #[error("Invalid configuration: {0}")]
    Config(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}
