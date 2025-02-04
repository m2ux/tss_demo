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

pub trait RoundBasedWireMessage<M>: Sized {
    fn to_message_destination(&self) -> Option<MessageDestination>;
    fn from_message_destination(dest: Option<MessageDestination>) -> Option<u16>;
    fn new_broadcast(
        msg_id_gen: &MessageIdGenerator,
        sender: u16,
        item: Outgoing<M>,
    ) -> Result<Self, NetworkError>;
    fn new_p2p(
        msg_id_gen: &MessageIdGenerator,
        sender: u16,
        item: Outgoing<M>,
    ) -> Result<Self, NetworkError>;
}

impl<M: Serialize> RoundBasedWireMessage<M> for WireMessage {
    /// Converts wire format receiver to MessageDestination.
    fn to_message_destination(&self) -> Option<MessageDestination> {
        self.receiver.map(MessageDestination::OneParty)
    }

    /// Converts MessageDestination to wire format receiver.
    fn from_message_destination(dest: Option<MessageDestination>) -> Option<u16> {
        dest.and_then(|d| match d {
            MessageDestination::OneParty(id) => Some(id),
            MessageDestination::AllParties => None,
        })
    }
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
