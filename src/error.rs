//! Error types for the CGGMP21 protocol implementation.
//!
//! This module provides a centralized error handling system that encompasses
//! all possible error conditions that may occur during protocol execution,
//! including protocol-specific errors, network communication failures,
//! storage issues, and configuration problems.
//!
//! # Error Handling
//!
//! The module uses the `thiserror` crate to provide detailed error information
//! and proper error propagation throughout the application. Each error variant
//! includes specific context about what went wrong.
//!
//! # Examples
//!
//! ```rust,no_run
//! use crate::Error;
//!
//! fn example_operation() -> Result<(), Error> {
//!     // Handle various error types
//!     match some_operation() {
//!         Ok(result) => Ok(()),
//!         Err(e) => Err(Error::Protocol(e)),
//!     }
//! }
//! ```

use crate::{network, protocol};
use crate::ws_server::ServerError;
use crate::storage;

/// Comprehensive error type encompassing all possible failure modes.
///
/// This enum provides a unified error type that covers all potential error
/// conditions in the application, including:
/// - Protocol-specific errors from the CGGMP21 implementation
/// - Network communication failures
/// - Storage and persistence errors
/// - Configuration and setup issues
/// - Serialization/deserialization errors
///
/// # Error Propagation
///
/// The error type implements `std::error::Error` through the `thiserror` derive macro,
/// enabling proper error context and chaining. Each variant can wrap its underlying
/// error type while providing additional context.
///
/// # Examples
///
/// ```rust,no_run
/// use crate::Error;
///
/// async fn handle_protocol_operation() -> Result<(), Error> {
///     match protocol_operation().await {
///         Ok(_) => Ok(()),
///         Err(e) => Err(Error::Protocol(e)),
///     }
/// }
///
/// fn handle_config() -> Result<(), Error> {
///     if invalid_config {
///         return Err(Error::Config("Invalid parameter".to_string()));
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Errors that occur during the execution of the TSS protocol.
    /// These are protocol-specific errors such as invalid shares, failed verification, etc.
    #[error("Protocol error: {0}")]
    Protocol(#[from] protocol::ProtocolError),

    /// Network communication errors, including connection failures,
    /// message delivery issues, and WebSocket-related problems.
    #[error("Network error: {0}")]
    Network(#[from] network::NetworkError),

    /// Network communication errors, including connection failures,
    /// message delivery issues, and WebSocket-related problems.
    #[error("Network error: {0}")]
    Delivery(#[from] network::DeliveryError),

    /// Storage-related errors, including file I/O issues,
    /// encryption/decryption failures, and data persistence problems.
    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),

    /// Configuration errors, typically occurring during setup or
    /// when invalid parameters are provided.
    #[error("Invalid configuration: {0}")]
    Config(String),

    /// Data serialization or deserialization errors,
    /// typically when processing messages or storing data.
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Server error: {0}")]
    Server(#[from] ServerError),
}
