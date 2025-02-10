//! Message types and handling for network communication.
//!
//! This module defines the core message types and related utilities used for
//! network communication in the protocol. It provides:
//! - Wire format message definitions
//! - Message ID generation and ordering
//! - Message state tracking
//! - Session management types
//!
//! # Message Flow
//!
//! ```text
//! ┌─────────────┐    ┌────────────────┐    ┌────────────────┐
//! │ Application │ -> │ NetworkMessage │ -> │   WireMessage  │
//! │  Message    │    │    Wrapper     │    │ (Transmission) │
//! └─────────────┘    └────────────────┘    └────────────────┘
//! ```
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use crate::message::{WireMessage, MessageIdGenerator};
//!
//! let msg_gen = MessageIdGenerator::new();
//! let wire_msg = WireMessage::new_broadcast(&msg_gen, 1, "Hello")?;
//! `
use crate::network::NetworkError;
use round_based::{MessageDestination, Outgoing};
use serde::{Deserialize, Serialize};
use std::num::Wrapping;
use std::sync::atomic::{AtomicU64, Ordering};

/// Internal message format for wire transmission.
///
/// Encapsulates all necessary metadata for message delivery and ordering.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct WireMessage {
    /// Monotonically increasing message identifier
    pub id: u64,
    /// ID of the sending party
    pub sender: u16,
    /// Optional recipient ID for P2P messages
    pub receiver: Option<u16>,
    /// Serialized message payload
    pub payload: Vec<u8>,
}

impl WireMessage {
    /// Creates a new broadcast message.
    ///
    /// # Arguments
    /// * `msg_id_gen` - Message ID generator for sequence tracking
    /// * `sender` - ID of the sending party
    /// * `msg` - Message content to serialize
    ///
    /// # Returns
    /// Result containing the new WireMessage or a network error
    ///
    /// # Example
    /// ```rust,no_run
    /// let msg = WireMessage::new_broadcast(&msg_gen, 1, "Broadcast message")?;
    /// ```
    pub fn new_broadcast<M: Serialize>(
        msg_id_gen: &MessageIdGenerator,
        sender: u16,
        msg: M,
    ) -> Result<Self, NetworkError> {
        Ok(WireMessage {
            id: msg_id_gen.next_id(),
            sender,
            receiver: None,
            payload: bincode::serialize(&msg)
                .map_err(|_| NetworkError::Connection("Payload serialization failed".into()))?,
        })
    }

    /// Creates a new point-to-point message.
    ///
    /// # Arguments
    /// * `msg_id_gen` - Message ID generator for sequence tracking
    /// * `sender` - ID of the sending party
    /// * `receiver` - ID of the receiving party
    /// * `msg` - Message content to serialize
    ///
    /// # Returns
    /// Result containing the new WireMessage or a network error
    ///
    /// # Example
    /// ```rust,no_run
    /// let msg = WireMessage::new_p2p(&msg_gen, 1, 2, "Direct message")?;
    /// ```
    pub fn new_p2p<M: Serialize>(
        msg_id_gen: &MessageIdGenerator,
        sender: u16,
        receiver: u16,
        msg: M,
    ) -> Result<Self, NetworkError> {
        Ok(WireMessage {
            id: msg_id_gen.next_id(),
            sender,
            receiver: Some(receiver),
            payload: bincode::serialize(&msg)
                .map_err(|_| NetworkError::Connection("Payload serialization failed".into()))?,
        })
    }
}

/// Trait for converting between wire format and round-based messages.
///
/// This trait provides the conversion functionality between wire format messages
/// and the round-based protocol message types.
pub trait RoundBasedWireMessage<M>: Sized {
    /// Converts wire format receiver to MessageDestination.
    fn to_message_destination(&self) -> Option<MessageDestination>;
    /// Converts MessageDestination to wire format receiver.
    fn from_message_destination(dest: Option<MessageDestination>) -> Option<u16>;
    /// Creates a new broadcast message from a round-based protocol message
    fn new_broadcast(
        msg_id_gen: &MessageIdGenerator,
        sender: u16,
        item: Outgoing<M>,
    ) -> Result<Self, NetworkError>;
    /// Creates a new P2P message from a round-based protocol message.
    fn new_p2p(
        msg_id_gen: &MessageIdGenerator,
        sender: u16,
        item: Outgoing<M>,
    ) -> Result<Self, NetworkError>;
}


/// Implements conversion between round-based protocol messages and wire format messages.
///
/// This implementation provides bidirectional conversion between the round-based protocol's
/// message types and the wire format used for network transmission. It handles both
/// broadcast and point-to-point (P2P) message patterns.
///
/// # Type Parameters
///
/// * `M` - The message type that implements Serialize, representing the protocol-level message
///
impl<M: Serialize> RoundBasedWireMessage<M> for WireMessage {
    /// Converts wire format receiver to MessageDestination.
    ///
    /// Maps the optional receiver field to the appropriate MessageDestination:
    /// - Some(party_id) -> MessageDestination::OneParty(party_id)
    /// - None -> None (broadcast)
    ///
    /// # Returns
    /// * `Some(MessageDestination::OneParty(id))` for P2P messages
    /// * `None` for broadcast messages
    fn to_message_destination(&self) -> Option<MessageDestination> {
        self.receiver.map(MessageDestination::OneParty)
    }

    /// Converts MessageDestination to wire format receiver.
    ///
    /// Maps the MessageDestination to an optional receiver ID:
    /// - MessageDestination::OneParty(id) -> Some(id)
    /// - MessageDestination::AllParties -> None
    ///
    /// # Arguments
    /// * `dest` - Optional MessageDestination to convert
    ///
    /// # Returns
    /// * `Some(party_id)` for P2P destinations
    /// * `None` for broadcast destinations
    fn from_message_destination(dest: Option<MessageDestination>) -> Option<u16> {
        dest.and_then(|d| match d {
            MessageDestination::OneParty(id) => Some(id),
            MessageDestination::AllParties => None,
        })
    }


    /// Creates a new broadcast message from a round-based protocol message.
    ///
    /// Serializes the message content and creates a wire message without a specific
    /// receiver, suitable for broadcast delivery.
    ///
    /// # Arguments
    /// * `msg_id_gen` - Generator for message sequence IDs
    /// * `sender` - ID of the sending party
    /// * `item` - Outgoing message from the round-based protocol
    ///
    /// # Returns
    /// * `Ok(WireMessage)` - Successfully created wire message
    /// * `Err(NetworkError)` - If serialization fails
    fn new_broadcast(
        msg_id_gen: &MessageIdGenerator,
        sender: u16,
        item: Outgoing<M>,
    ) -> Result<Self, NetworkError> {
        Ok(WireMessage {
            id: msg_id_gen.next_id(),
            sender,
            receiver: None,
            payload: bincode::serialize(&item.msg)
                .map_err(|_| NetworkError::Connection("Payload serialization failed".into()))?,
        })
    }

    /// Creates a new P2P message from a round-based protocol message.
    ///
    /// Serializes the message content and creates a wire message with a specific
    /// receiver, suitable for point-to-point delivery.
    ///
    /// # Arguments
    /// * `msg_id_gen` - Generator for message sequence IDs
    /// * `sender` - ID of the sending party
    /// * `item` - Outgoing message from the round-based protocol
    ///
    /// # Returns
    /// * `Ok(WireMessage)` - Successfully created wire message
    /// * `Err(NetworkError)` - If serialization fails or destination is invalid
    fn new_p2p(
        msg_id_gen: &MessageIdGenerator,
        sender: u16,
        item: Outgoing<M>,
    ) -> Result<Self, NetworkError> {
        Ok(WireMessage {
            id: msg_id_gen.next_id(),
            sender,
            receiver: <WireMessage as RoundBasedWireMessage<M>>::from_message_destination(Some(
                item.recipient,
            )),
            payload: bincode::serialize(&item.msg)
                .map_err(|_| NetworkError::Connection("Payload serialization failed".into()))?,
        })
    }
}

/// Thread-safe message ID generator with overflow handling.
///
/// Generates monotonically increasing message IDs with proper handling of integer overflow
/// using wrapping arithmetic. Thread-safe through the use of atomic operations.
pub struct MessageIdGenerator {
    counter: AtomicU64,
}

impl MessageIdGenerator {
    /// Creates a new MessageIdGenerator starting from 0.
    pub const fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Generates the next message ID in a thread-safe manner.
    ///
    /// Uses wrapping arithmetic to handle overflow gracefully, ensuring
    /// the counter continues from 0 after reaching u64::MAX.
    pub fn next_id(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn reset(&self) {
        self.counter.store(0, Ordering::SeqCst);
    }
}

/// Tracks message ordering state to ensure proper message sequencing.
///
/// The MessageState struct is responsible for maintaining and validating the order
/// of messages in the network communication protocol. It uses wrapping arithmetic
/// to handle message ID overflow gracefully when reaching u64::MAX.
#[derive(Debug)]
pub struct MessageState {
    /// The last successfully validated message ID, wrapped to handle overflow
    last_id: Wrapping<u64>,
}

impl MessageState {
    /// Creates a new MessageState starting from ID 0.
    ///
    /// # Returns
    ///
    /// Returns a new MessageState instance initialized with a message ID of 0.
    pub fn new() -> Self {
        Self {
            last_id: Wrapping(0),
        }
    }

    /// Validates that a message ID maintains monotonic ordering.
    ///
    /// This function ensures messages are processed in order by validating that each
    /// new message ID is greater than the last seen ID. It handles wraparound at
    /// u64::MAX by using wrapping arithmetic.
    ///
    /// # Arguments
    ///
    /// * `id` - The message ID to validate
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the message ID is valid and in sequence.
    /// Returns Err(NetworkError::InvalidMessageId) if the message is out of sequence.
    pub fn validate_and_update_id(&mut self, id: u64) -> Result<(), NetworkError> {
        let new_id = Wrapping(id);
        let diff = new_id - self.last_id;

        // We expect IDs to increment by small values.
        if diff.0 > u64::MAX / 2 {
            return Err(NetworkError::InvalidMessageId {
                expected: self.last_id.0,
                actual: id,
            });
        }

        self.last_id = new_id;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PartySession {
    pub party_id: u16,
    pub session_id: u16,
}

/// Message type for session coordination
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum SessionMessage {
    Register { session: PartySession },
    Unregister { session: PartySession },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    SessionMessage(SessionMessage),
    WireMessage(WireMessage),
}
