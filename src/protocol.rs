//! Error types for the CGGMP21 protocol implementation.
//!
//! This module provides a centralized error handling system that encompasses
//! all possible error conditions that may occur during protocol execution,
//! including protocol-specific errors, network communication failures,
//! storage issues, and configuration problems.


/// Represents specific errors that can occur during protocol execution.
///
/// This enum covers all protocol-specific error cases that may arise during
/// the CGGMP21 protocol execution, providing type-safe error handling and
/// detailed context about what went wrong.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Error when a share is invalid or cannot be verified
    #[error("Invalid share: {0}")]
    InvalidShare(String),

    /// Error when auxiliary info generation fails
    #[error("Aux info generation failed: {0}")]
    AuxGenFailed(String),

    /// Error when key generation fails
    #[error("Aux info generation failed: {0}")]
    KeyGenFailed(String),

    /// Error when verification of any protocol component fails
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Error when an invalid participant is referenced or detected
    #[error("Invalid participant: {0}")]
    InvalidParticipant(String),

    /// Error when an operation is attempted in an invalid protocol round
    #[error("Invalid round: {0}")]
    InvalidRound(String),

    /// Error when a received message is malformed or unexpected
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Error when signature operations fail
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Catch-all for other protocol-related errors
    #[error("Protocol error: {0}")]
    Other(String),
}