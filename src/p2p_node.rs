//! P2P-based delivery layer for distributed protocol communication.
//!
//! This module provides a P2P alternative to the network delivery system,
//! using libp2p and gossipsub for peer-to-peer message routing while
//! maintaining API compatibility with the existing delivery interface.

use crate::network::WireMessage;
use libp2p::{Multiaddr, Swarm};
use libp2p_gossipsub as gossipsub;
use libp2p_gossipsub::{Behaviour, IdentTopic};
use libp2p_identity::{self, Keypair};
use round_based::Incoming;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::UnboundedSender, Mutex, RwLock};

/// Configuration for P2P network setup
#[derive(Clone, Debug)]
pub struct P2PConfig {
    pub bootstrap_peers: Vec<Multiaddr>,
    pub listen_addresses: Vec<Multiaddr>,
}

/// Errors specific to P2P operations
#[derive(Debug, thiserror::Error)]
pub enum P2PError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Swarm error: {0}")]
    Swarm(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Session error: {0}")]
    Session(String),
}

/// Information about an active delivery session
pub struct SessionInfo<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Clone + Send + 'static,
{
    pub party_id: u16,
    pub session_id: u16,
    pub sender: UnboundedSender<Incoming<M>>,
}

impl<M> Clone for SessionInfo<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Clone + Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            session_id: self.session_id,
            sender: self.sender.clone(),
        }
    }
}

pub trait SessionInfoTrait: Send + Sync {
    fn party_id(&self) -> u16;
    fn session_id(&self) -> u16;
    fn forward_message(&self, wire_msg: WireMessage, msg_type: round_based::MessageType);
}

// Implement the trait for SessionInfo
impl<M> SessionInfoTrait for SessionInfo<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static + Clone,
{
    fn party_id(&self) -> u16 {
        self.party_id
    }

    fn session_id(&self) -> u16 {
        self.session_id
    }

    fn forward_message(&self, wire_msg: WireMessage, msg_type: round_based::MessageType) {
        if let Ok(msg) = bincode::deserialize(&wire_msg.payload) {
            let incoming = Incoming {
                id: wire_msg.id,
                sender: wire_msg.sender,
                msg,
                msg_type,
            };

            if let Err(e) = self.sender.send(incoming) {
                println!("Failed to forward message: {}", e);
            }
        }
    }
}

pub struct P2PNode {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    keypair: Keypair,
    sessions: Arc<RwLock<HashMap<gossipsub::TopicHash, Box<dyn SessionInfoTrait>>>>,
    running: Arc<RwLock<bool>>,
}

// p2p_node.rs
impl P2PNode {
    /// Creates a broadcast topic for a session
    pub fn get_broadcast_topic(session_id: u16) -> IdentTopic {
        IdentTopic::new(format!("cggmp21/broadcast/{}", session_id))
    }

    /// Creates a P2P topic for a specific party in a session
    pub fn get_p2p_topic(party_id: u16, session_id: u16) -> IdentTopic {
        IdentTopic::new(format!("cggmp21/p2p/{}/{}", session_id, party_id))
    }

    /// Subscribes to relevant topics for a party
    pub(crate) async fn subscribe_to_session<M>(
        &self,
        party_id: u16,
        session_id: u16,
        sender: UnboundedSender<Incoming<M>>,
    ) -> Result<(), P2PError>
    where
        M: Serialize + for<'de> Deserialize<'de> + Send + 'static + Clone,
    {
        let broadcast_topic = Self::get_broadcast_topic(session_id);
        let p2p_topic = Self::get_p2p_topic(party_id, session_id);

        let session_info = SessionInfo {
            party_id,
            session_id,
            sender,
        };

        if let Ok(mut swarm) = self.swarm.try_lock() {
            // Subscribe to broadcast topic
            swarm
                .behaviour_mut()
                .subscribe(&broadcast_topic)
                .map_err(|e| P2PError::Protocol(e.to_string()))?;

            // Subscribe to P2P topic
            swarm
                .behaviour_mut()
                .subscribe(&p2p_topic)
                .map_err(|e| P2PError::Protocol(e.to_string()))?;
        } else {
            return Err(P2PError::Protocol("Failed to acquire swarm lock".into()));
        }

        // Register session for both topics
        let mut sessions = self.sessions.write().await;
        sessions.insert(broadcast_topic.hash(), Box::new(session_info.clone()));
        sessions.insert(p2p_topic.hash(), Box::new(session_info));

        Ok(())
    }

    fn get_swarm_mut(&self) -> Result<tokio::sync::MutexGuard<'_, Swarm<Behaviour>>, P2PError> {
        self.swarm
            .try_lock()
            .map_err(|e| P2PError::Protocol(format!("Failed to acquire swarm lock: {}", e)))
    }

    /// Publishes a message to the appropriate topic
    pub(crate) fn publish_message<M>(
        &self,
        msg: &M,
        recipient: Option<u16>,
        session_id: u16,
    ) -> Result<(), P2PError>
    where
        M: Serialize + Send + 'static,
    {
        let data = bincode::serialize(msg)
            .map_err(|e| P2PError::Protocol(format!("Serialization error: {}", e)))?;

        if let Ok(mut swarm) = self.swarm.try_lock() {
            match recipient {
                None => {
                    // Broadcast message
                    let topic = Self::get_broadcast_topic(session_id);
                    swarm
                        .behaviour_mut()
                        .publish(topic, data)
                        .map(|_| ())
                        .map_err(|e| P2PError::Protocol(e.to_string()))?;
                }
                Some(party_id) => {
                    // P2P message
                    let topic = Self::get_p2p_topic(party_id, session_id);
                    swarm
                        .behaviour_mut()
                        .publish(topic, data)
                        .map(|_| ())
                        .map_err(|e| P2PError::Protocol(e.to_string()))?;
                }
            }
            Ok(())
        } else {
            Err(P2PError::Protocol("Failed to acquire swarm lock".into()))
        }
    }
}
