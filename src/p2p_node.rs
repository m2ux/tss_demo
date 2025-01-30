//! P2P-based delivery layer for distributed protocol communication.
//!
//! This module provides a P2P alternative to the network delivery system,
//! using libp2p and gossipsub for peer-to-peer message routing while
//! maintaining API compatibility with the existing delivery interface.

use futures_util::StreamExt;
use libp2p::{yamux, Multiaddr, Swarm};
use libp2p_core::upgrade::Version;
use libp2p_core::Transport;
use libp2p_gossipsub as gossipsub;
use libp2p_gossipsub::{Behaviour, IdentTopic, TopicHash};
use libp2p_identity::{self, Keypair, PeerId};
use libp2p_swarm::SwarmEvent;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::UnboundedSender, Mutex, RwLock};

/// Message type (broadcast or p2p)
#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
    Broadcast,
    P2P,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct NetworkMessage<T> {
    data: T,
    msg_type: MessageType,
}

/// Configuration for P2P network setup
#[derive(Clone, Debug)]
pub struct P2PConfig {
    pub bootstrap_peers: Vec<Multiaddr>,
    pub listen_addresses: Vec<Multiaddr>,
    pub protocol: String,
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
    pub sender: UnboundedSender<M>,
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
    fn forward_message(&self, data: Vec<u8>);
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

    fn forward_message(&self, data: Vec<u8>) {
        match bincode::deserialize::<M>(&data) {
            Ok(msg) => {
                if let Err(e) = self.sender.send(msg) {
                    println!("Failed to forward message: {}", e);
                }
            }
            Err(e) => {
                println!("Failed to deserialize message: {}", e);
            }
        }
    }
}

pub struct P2PNode {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    keypair: Keypair,
    sessions: Arc<RwLock<HashMap<gossipsub::TopicHash, Box<dyn SessionInfoTrait>>>>,
    running: Arc<RwLock<bool>>,
    pub protocol: String,
}

// p2p_node.rs
impl P2PNode {
    /// Creates a new P2P node with custom configuration
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

        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let running = Arc::new(RwLock::new(true));
        let swarm = Arc::new(Mutex::new(swarm));

        let node = Arc::new(Self {
            swarm,
            keypair,
            sessions,
            running,
            protocol: config.protocol,
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

    /// Main event loop for P2P node operation
    async fn run(node: Arc<Self>) -> Result<(), P2PError> {
        while *node.running.read().await {
            let mut swarm = node.swarm.lock().await;

            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(gossipsub::Event::Message {
                                          propagation_source: _,
                                          message_id: _,
                                          message,
                                      }) => {
                    // Deserialize the network message
                    match bincode::deserialize::<NetworkMessage<Vec<u8>>>(&message.data) {
                        Ok(network_msg) => {
                            let sessions = node.sessions.read().await;

                            match network_msg.msg_type {
                                MessageType::Broadcast => {
                                    // Extract session_id from topic
                                    if let Some(session_id) = node.extract_session_id(&message.topic) {
                                        // Forward to all sessions with matching session_id
                                        for session in sessions.values() {
                                            if session.session_id() == session_id {
                                                session.forward_message(network_msg.data.clone());
                                            }
                                        }
                                    }
                                }
                                MessageType::P2P => {
                                    // Forward only to the specific session matching the topic
                                    if let Some(session) = sessions.get(&message.topic) {
                                        session.forward_message(network_msg.data);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("Failed to deserialize network message: {}", e);
                        }
                    }
                }
                SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, topic }) => {
                    println!("Peer {} subscribed to topic {:?}", peer_id, topic);
                }
                SwarmEvent::Behaviour(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
                    println!("Peer {} unsubscribed from topic {:?}", peer_id, topic);
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    println!(
                        "Connection established with peer {}: {:?}",
                        peer_id, endpoint
                    );
                }
                SwarmEvent::ConnectionClosed {
                    peer_id, endpoint, ..
                } => {
                    println!("Connection closed with peer {}: {:?}", peer_id, endpoint);
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node listening on {}", address);
                }
                SwarmEvent::IncomingConnection {
                    local_addr,
                    send_back_addr,
                    ..
                } => {
                    println!(
                        "Incoming connection from {} to {}",
                        send_back_addr, local_addr
                    );
                }
                SwarmEvent::Dialing {
                    peer_id,
                    connection_id: _,
                } => {
                    println!("Dialing peer {:?}", peer_id);
                }
                _ => {}
            }

            drop(swarm);

            // Small delay to prevent tight loop
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    /// Gracefully shut down the node
    pub async fn shutdown(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    fn is_broadcast_topic(&self, topic_hash: &TopicHash) -> bool {
        // Check if this topic hash matches any of our broadcast topics
        let sessions = self.sessions.blocking_read();
        for session in sessions.values() {
            let broadcast_topic = self.get_broadcast_topic(session.session_id());
            if topic_hash == &broadcast_topic.hash() {
                return true;
            }
        }
        false
    }

    /// Creates a broadcast topic for a session
    pub fn get_broadcast_topic(&self, session_id: u16) -> IdentTopic {
        IdentTopic::new(format!("{}/broadcast/{}", self.protocol, session_id))
    }

    /// Creates a P2P topic for a specific party in a session
    pub fn get_p2p_topic(&self, party_id: u16, session_id: u16) -> IdentTopic {
        IdentTopic::new(format!("{}/p2p/{}/{}", self.protocol, session_id, party_id))
    }

    /// Subscribes to relevant topics for a party
    pub(crate) async fn subscribe_to_session<M>(
        &self,
        party_id: u16,
        session_id: u16,
        sender: UnboundedSender<M>,
    ) -> Result<(), P2PError>
    where
        M: Serialize + for<'de> Deserialize<'de> + Send + 'static + Clone,
    {
        let broadcast_topic = self.get_broadcast_topic(session_id);
        let p2p_topic = self.get_p2p_topic(party_id, session_id);

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

    /// Creates a new P2P node connection with production configuration
    pub async fn connect(
        server_addr: &str,
        listen_addr: Option<&str>,
        protocol: impl Into<String>,
    ) -> Result<Arc<Self>, P2PError> {
        let listen_addr = listen_addr
            .unwrap_or("/ip4/0.0.0.0/tcp/9000")
            .parse()
            .map_err(|e| P2PError::Transport(format!("Failed to parse listen address: {:?}", e)))?;
        let config = P2PConfig {
            bootstrap_peers: vec![server_addr.parse().map_err(|e| {
                P2PError::Transport(format!("Failed to parse server address: {:?}", e))
            })?],
            listen_addresses: vec![listen_addr],
            protocol: protocol.into(),
        };

        Self::new(config).await
    }

    // Add helper method to extract session_id from topic
    fn extract_session_id(&self, topic_hash: &TopicHash) -> Option<u16> {
        // Convert topic hash to string and parse session_id
        let topic_str = topic_hash.to_string();
        let parts: Vec<&str> = topic_str.split('/').collect();

        // Expected format: "{protocol}/broadcast/{session_id}"
        if parts.len() == 3 && parts[1] == "broadcast" {
            parts[2].parse::<u16>().ok()
        } else {
            None
        }
    }

    /// Publishes a message to the appropriate topic
    pub(crate) fn publish_message<M>(
        &self,
        data: &M,
        recipient: Option<u16>,
        session_id: u16,
    ) -> Result<(), P2PError>
    where
        M: Serialize + Send + 'static,
    {
        // Create the network message
        let network_msg = NetworkMessage {
            data,
            msg_type: match recipient {
                None => MessageType::Broadcast,
                Some(_) => MessageType::P2P,
            },
        };

        let msg_data = bincode::serialize(&network_msg)
            .map_err(|e| P2PError::Protocol(format!("Network message serialization error: {}", e)))?;

        if let Ok(mut swarm) = self.swarm.try_lock() {
            match recipient {
                None => {
                    // Broadcast message
                    let topic = self.get_broadcast_topic(session_id);
                    swarm
                        .behaviour_mut()
                        .publish(topic, msg_data)
                        .map(|_| ())
                        .map_err(|e| P2PError::Protocol(e.to_string()))?;
                }
                Some(party_id) => {
                    // P2P message
                    let topic = self.get_p2p_topic(party_id, session_id);
                    swarm
                        .behaviour_mut()
                        .publish(topic, msg_data)
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
