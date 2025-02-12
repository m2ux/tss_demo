//! Protocol-specific topic handling for libp2p gossipsub
//!
//! This module provides the [`ProtocolTopic`] struct which wraps libp2p's [`IdentTopic`]
//! to implement protocol-specific topic formatting and parsing. It supports two types of topics:
//!
//! - Broadcast topics: Used for messages intended for all parties in a session
//!   - Format: `{protocol}/broadcast/{session_id}`
//!
//! - P2P topics: Used for messages intended for a specific party in a session
//!   - Format: `{protocol}/p2p/{session_id}/{party_id}`
//!
//! The module provides methods to:
//! - Create broadcast and P2P topics
//! - Parse session IDs and party IDs from topic strings
//! - Determine topic types (broadcast vs P2P)
//! - Access underlying libp2p topic functionality
use libp2p_gossipsub::{IdentTopic, TopicHash};

/// Represents a gossipsub topic with protocol-specific formatting
#[derive(Clone, Debug)]
pub struct ProtocolTopic {
    /// The underlying libp2p IdentTopic
    inner: IdentTopic,
    /// Protocol identifier (e.g., "cggmp")
    protocol: String,
}

impl ProtocolTopic {
    /// Creates a new broadcast topic
    /// Format: "{protocol}/broadcast/{session_id}"
    pub fn new_broadcast(protocol: impl Into<String>, session_id: u16) -> Self {
        let protocol = protocol.into();
        let topic_str = format!("{}/broadcast/{}", protocol, session_id);
        Self {
            inner: IdentTopic::new(topic_str),
            protocol,
        }
    }

    /// Creates a new P2P topic
    /// Format: "{protocol}/p2p/{session_id}/{party_id}"
    pub fn new_p2p(protocol: impl Into<String>, session_id: u16, party_id: u16) -> Self {
        let protocol = protocol.into();
        let topic_str = format!("{}/p2p/{}/{}", protocol, session_id, party_id);
        Self {
            inner: IdentTopic::new(topic_str),
            protocol,
        }
    }

    /// Creates a Topic from an existing IdentTopic
    /// Note: This assumes the topic string follows the expected format
    pub fn from_ident_topic(topic: IdentTopic, protocol: impl Into<String>) -> Self {
        Self {
            inner: topic,
            protocol: protocol.into(),
        }
    }

    /// Checks if this is a broadcast topic
    /// Expected format: "{protocol}/broadcast/{session_id}"
    pub fn is_broadcast(&self) -> bool {
        let topic_str = self.inner.to_string();
        let parts: Vec<&str> = topic_str.split('/').collect();
        parts.len() == 3 && parts[1] == "broadcast"
    }

    /// Checks if this is a P2P topic
    /// Expected format: "{protocol}/p2p/{session_id}/{party_id}"
    pub fn is_p2p(&self) -> bool {
        let topic_str = self.inner.to_string();
        let parts: Vec<&str> = topic_str.split('/').collect();
        parts.len() == 4 && parts[1] == "p2p"
    }

    /// Extracts the session ID from a topic string if present
    pub fn session_id(&self) -> Option<u16> {
        let topic_str = self.inner.to_string();
        let parts: Vec<&str> = topic_str.split('/').collect();
        match parts.as_slice() {
            // Broadcast format: protocol/broadcast/session_id
            [_, "broadcast", session_id] => session_id.parse().ok(),
            // P2P format: protocol/p2p/session_id/party_id
            [_, "p2p", session_id, _] => session_id.parse().ok(),
            _ => None,
        }
    }

    /// Extracts the party ID from a P2P topic string if present
    pub fn party_id(&self) -> Option<u16> {
        let topic_str = self.inner.to_string();
        let parts: Vec<&str> = topic_str.split('/').collect();
        match parts.as_slice() {
            // P2P format: protocol/p2p/session_id/party_id
            [_, "p2p", _, party_id] => party_id.parse().ok(),
            _ => None,
        }
    }

    /// Gets the topic hash for storage/lookup
    pub fn hash(&self) -> TopicHash {
        self.inner.hash()
    }

    /// Gets a reference to the underlying IdentTopic
    pub fn as_ident_topic(&self) -> &IdentTopic {
        &self.inner
    }

    /// Creates a new ProtocolTopic from a TopicHash and protocol string
    ///
    /// # Arguments
    /// * `topic_hash` - The hash of the topic
    /// * `protocol` - The protocol identifier
    pub fn from_protocol(topic_hash: TopicHash, protocol: impl Into<String>) -> Self {
        Self {
            inner: IdentTopic::new(topic_hash.to_string()),
            protocol: protocol.into(),
        }
    }
}
