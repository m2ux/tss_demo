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
pub struct NetworkMessage {
    data: Vec<u8>,
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
pub struct SessionInfo
{
    pub party_id: u16,
    pub session_id: u16,
    pub sender: UnboundedSender<NetworkMessage>,
}

// Implement the trait for SessionInfo
impl SessionInfo
{
    fn forward_message(&self, msg: NetworkMessage) {
        match bincode::deserialize::<Vec<u8>>(&msg.data) {
            Ok(_) => {
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

impl Clone for SessionInfo
{
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            session_id: self.session_id,
            sender: self.sender.clone(),
        }
    }
}

pub struct P2PNode {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    keypair: Keypair,
    sessions: Arc<RwLock<HashMap<TopicHash, SessionInfo>>>,
    running: Arc<RwLock<bool>>,
    pub protocol: String,
}

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

        let node = Arc::new(Self {
            swarm: Arc::new(Mutex::new(swarm)),
            keypair,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(true)),
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
                    Self::handle_incoming_message(&node, message.topic, message.data).await;
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

    async fn handle_incoming_message(node: &Arc<Self>, topic_hash: TopicHash, data: Vec<u8>) {
        let sessions = node.sessions.read().await;
        let topic = ProtocolTopic::from_ident_topic(
            IdentTopic::new(topic_hash.to_string()),
            node.protocol.clone(),
        );

        // Infer message type based on topic format
        if topic.is_broadcast() {
            // Broadcast message - forward to all sessions with matching session_id
            if let Some(session_id) = topic.session_id() {
                // Create broadcast network message
                let network_msg = NetworkMessage {
                    data: data.clone(),
                    msg_type: MessageType::Broadcast,
                };

                // Forward the network message
                for session in sessions.values() {
                    if session.session_id == session_id {
                        session.forward_message(network_msg.clone());
                    }
                }
            }
        } else if topic.is_p2p(){
            // P2P message - forward only to the specific session matching the topic
            if let Some(session) = sessions.get(&topic.hash()) {
                // Create P2P network message
                let network_msg = NetworkMessage {
                    data,
                    msg_type: MessageType::P2P,
                };

                // Forward the network message
                session.forward_message(network_msg);
            }
        } else {
            // TODO: Error: Unrecognised topic
        }
    }

    /// Creates a broadcast topic for a session
    fn get_broadcast_topic(&self, session_id: u16) -> ProtocolTopic {
        ProtocolTopic::new_broadcast(&self.protocol, session_id)
    }

    /// Creates a P2P topic for a specific party in a session
    fn get_p2p_topic(&self, party_id: u16, session_id: u16) -> ProtocolTopic {
        ProtocolTopic::new_p2p(&self.protocol, session_id, party_id)
    }

    /// Subscribes to relevant topics for a party
    pub async fn subscribe_to_session(
        &self,
        party_id: u16,
        session_id: u16,
        sender: UnboundedSender<NetworkMessage>,
    ) -> Result<(), P2PError>
    {
        // Create topics using the new Topic struct
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
                .subscribe(broadcast_topic.as_ident_topic())
                .map_err(|e| P2PError::Protocol(e.to_string()))?;

            // Subscribe to P2P topic
            swarm
                .behaviour_mut()
                .subscribe(p2p_topic.as_ident_topic())
                .map_err(|e| P2PError::Protocol(e.to_string()))?;
        } else {
            return Err(P2PError::Protocol("Failed to acquire swarm lock".into()));
        }

        // Register session for both topics
        let mut sessions = self.sessions.write().await;
        sessions.insert(broadcast_topic.hash(), session_info.clone());
        sessions.insert(p2p_topic.hash(), session_info);

        Ok(())
    }

    /// Unsubscribes from a session, removing all associated topic subscriptions and session data.
    ///
    /// This method removes the party from both broadcast and P2P topics for the specified session
    /// and cleans up any associated session data.
    ///
    /// # Arguments
    ///
    /// * `party_id` - The ID of the party to unsubscribe
    /// * `session_id` - The ID of the session to unsubscribe from
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if unsubscription was successful, or a `P2PError` if an error occurred.
    ///
    /// # Errors
    ///
    /// Returns `P2PError` if:
    /// * Failed to acquire swarm lock
    /// * Protocol error during unsubscription
    pub async fn unsubscribe_from_session(
        &self,
        party_id: u16,
        session_id: u16,
    ) -> Result<(), P2PError> {
        // Create topics using the existing topic creation methods
        let broadcast_topic = self.get_broadcast_topic(session_id);
        let p2p_topic = self.get_p2p_topic(party_id, session_id);

        if let Ok(mut swarm) = self.swarm.try_lock() {
            // Unsubscribe from broadcast topic
            swarm
                .behaviour_mut()
                .unsubscribe(broadcast_topic.as_ident_topic());

            // Unsubscribe from P2P topic
            swarm
                .behaviour_mut()
                .unsubscribe(p2p_topic.as_ident_topic());
        } else {
            return Err(P2PError::Protocol("Failed to acquire swarm lock".into()));
        }

        // Remove session information from storage
        let mut sessions = self.sessions.write().await;
        sessions.remove(&broadcast_topic.hash());
        sessions.remove(&p2p_topic.hash());

        Ok(())
    }
    
    pub fn publish_message<M>(
        &self,
        data: &M,
        recipient: Option<u16>,
        session_id: u16,
    ) -> Result<(), P2PError>
    where
        M: Serialize + Send + 'static,
    {
        // Serialize the network message
        let msg_data = bincode::serialize(&data).map_err(|e| {
            P2PError::Protocol(format!("Network message serialization error: {}", e))
        })?;

        if let Ok(mut swarm) = self.swarm.try_lock() {
            match recipient {
                None => {
                    // Broadcast message
                    let topic = self.get_broadcast_topic(session_id);
                    swarm
                        .behaviour_mut()
                        .publish(topic.as_ident_topic().clone(), msg_data)
                        .map(|_| ())
                        .map_err(|e| P2PError::Protocol(e.to_string()))?;
                }
                Some(party_id) => {
                    // P2P message
                    let topic = self.get_p2p_topic(party_id, session_id);
                    swarm
                        .behaviour_mut()
                        .publish(topic.as_ident_topic().clone(), msg_data)
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
}