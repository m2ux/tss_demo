//! P2P-based delivery layer for distributed protocol communication.
//!
//! This module provides a P2P alternative to the network delivery system,
//! using libp2p and gossipsub for peer-to-peer message routing while
//! maintaining API compatibility with the existing delivery interface.

use crate::network::WireMessage;
use futures::StreamExt;
use libp2p::{swarm::SwarmEvent, yamux, Multiaddr, PeerId, Swarm};
use libp2p_core::{transport::upgrade::Version, Transport};
use libp2p_gossipsub as gossipsub;
use libp2p_identity::{self, Keypair};
use round_based::{Incoming, MessageDestination};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
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
#[derive(Clone)]
pub struct SessionInfo<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
{
    pub party_id: u16,
    pub session_id: u16,
    pub sender: UnboundedSender<Incoming<M>>,
}

pub trait SessionInfoTrait: Send + Sync {
    fn party_id(&self) -> u16;
    fn session_id(&self) -> u16;
    fn forward_message(&self, wire_msg: WireMessage, msg_type: round_based::MessageType);
}

// Implement the trait for SessionInfo
impl<M> SessionInfoTrait for SessionInfo<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
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
    swarm: Arc<Mutex<Swarm<gossipsub::Behaviour>>>,
    keypair: Keypair,
    sessions: Arc<RwLock<HashMap<gossipsub::TopicHash, Box<dyn SessionInfoTrait>>>>,
    running: Arc<RwLock<bool>>,
}

impl P2PNode {
    /// Creates or returns the singleton P2P node instance
    pub async fn new(config: P2PConfig) -> Result<Arc<Self>, P2PError> {
        // Create identity keypair
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        // Create gossipsub configuration
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| P2PError::Protocol(e.to_string()))?;

        // Create gossipsub protocol
        let behaviour = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| P2PError::Protocol(e.to_string()))?;

        // Create noise keys for encryption
        let noise_config =
            libp2p_noise::Config::new(&keypair).map_err(|e| P2PError::Protocol(e.to_string()))?;

        // Create transport with noise encryption and multiplexing
        let transport = libp2p_tcp::tokio::Transport::new(libp2p_tcp::Config::default())
            .upgrade(Version::V1Lazy)
            .authenticate(noise_config)
            .multiplex(yamux::Config::default())
            .boxed();

        // Create swarm config with tokio executor
        let swarm_config = libp2p_swarm::Config::with_executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .with_idle_connection_timeout(Duration::from_secs(60));

        // Build the swarm
        let mut swarm = Swarm::new(transport, behaviour, peer_id, swarm_config);

        // Listen on provided addresses
        for addr in config.listen_addresses {
            swarm
                .listen_on(addr)
                .map_err(|e| P2PError::Transport(e.to_string()))?;
        }

        // Connect to bootstrap peers
        for addr in config.bootstrap_peers {
            swarm
                .dial(addr)
                .map_err(|e| P2PError::Transport(e.to_string()))?;
        }

        // Build the node
        let node = Arc::new(Self {
            swarm: Arc::new(Mutex::new(swarm)),
            keypair,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(true)),
        });

        // Start the run loop in a separate task
        let node_clone = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(e) = Self::run(node_clone).await {
                println!("P2P node start error: {}", e);
            }
        });

        Ok(node)
    }

    /// Publishes a message to a topic
    pub fn publish(
        &self,
        topic: &gossipsub::IdentTopic,
        data: Vec<u8>,
    ) -> Result<(), P2PError> {
        if let Ok(mut swarm) = self.swarm.try_lock() {
            swarm
                .behaviour_mut()
                .publish(topic.clone(), data)
                .map(|_| ())
                .map_err(|e| P2PError::Protocol(e.to_string()))
        } else {
            Err(P2PError::Protocol("Failed to acquire swarm lock".into()))
        }
    }

    /// Subscribes to a topic and registers a session
    pub async fn subscribe_and_register<M>(
        &self,
        party_id: u16,
        session_id: u16,
        sender: UnboundedSender<Incoming<M>>,
    ) -> Result<(), P2PError>
    where
        M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
    {
        let topic = gossipsub::IdentTopic::new(format!(
            "cggmp21/session/{}/{}",
            session_id.clone(),
            party_id
        ));

        let session_info = SessionInfo {
            party_id,
            session_id,
            sender,
        };

        // Subscribe to topic
        if let Ok(mut swarm) = self.swarm.try_lock() {
            swarm
                .behaviour_mut()
                .subscribe(&topic)
                .map_err(|e| P2PError::Protocol(e.to_string()))?;
        } else {
            return Err(P2PError::Protocol("Failed to acquire swarm lock".into()));
        }

        // Register session
        self.sessions
            .write()
            .await
            .insert(topic.hash(), Box::new(session_info));

        Ok(())
    }

    /// Creates a topic identifier for a given party and session
    pub fn get_topic(party_id: u16, session_id: u16) -> gossipsub::IdentTopic {
        gossipsub::IdentTopic::new(format!("cggmp21/session/{}/{}", session_id, party_id))
    }

    /// Main event loop for P2P node operation
    pub async fn run(self: Arc<Self>) -> Result<(), P2PError> {
        loop {
            // Lock the swarm for this iteration
            let mut swarm = self.swarm.lock().await;

            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) => {
                    // Attempt to deserialize the message to check if it's a broadcast
                    if let Ok(wire_msg) = bincode::deserialize::<WireMessage>(&message.data) {
                        let sessions = self.sessions.read().await;

                        if let Some(session) = sessions.get(&message.topic) {
                            let msg_type = match wire_msg.to_message_destination() {
                                None => round_based::MessageType::Broadcast,
                                Some(MessageDestination::OneParty(_)) => {
                                    round_based::MessageType::P2P
                                }
                                Some(MessageDestination::AllParties) => {
                                    round_based::MessageType::Broadcast
                                }
                            };

                            session.forward_message(wire_msg, msg_type);
                        }
                    } else {
                        println!("Received malformed message");
                    }
                }
                SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, topic }) => {
                    println!("Peer {} subscribed to topic {:?}", peer_id, topic);
                }
                SwarmEvent::Behaviour(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
                    println!("Peer {} unsubscribed from topic {:?}", peer_id, topic);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("Connected to peer: {}", peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    println!("Disconnected from peer: {}", peer_id);
                }
                _ => {}
            }
        }
    }
}
