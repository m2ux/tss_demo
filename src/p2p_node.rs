//! P2P-based delivery layer for distributed protocol communication.
//!
//! This module provides a P2P alternative to the network delivery system,
//! using libp2p and gossipsub for peer-to-peer message routing while
//! maintaining API compatibility with the existing delivery interface.

use crate::p2p_behaviour::{AgentBehaviour, AgentBehaviourEvent};
use libp2p::identify::{
    Behaviour as IdentifyBehavior, Config as IdentifyConfig, Event as IdentifyEvent,
};
use libp2p::kad::{
    store::MemoryStore as KadInMemory, Behaviour as KadBehavior, Config as KadConfig,
    Event as KadEvent, RoutingUpdate,
};
use libp2p::noise::Config as NoiseConfig;
use libp2p::{
    identify, tcp::Config as TcpConfig, yamux, yamux::Config as YamuxConfig, Multiaddr,
    StreamProtocol, Swarm, SwarmBuilder,
};
use libp2p_core::upgrade::Version;
use libp2p_core::Transport;
use libp2p_gossipsub as gossipsub;
use libp2p_gossipsub::{Behaviour, Event as GossipEvent, Event, IdentTopic, TopicHash};
use libp2p_identity::{self, Keypair, PeerId};
use libp2p_kad::store::MemoryStore;
use libp2p_kad::{GetProvidersOk, QueryResult, RecordKey};
use libp2p_swarm::{NetworkBehaviour, SwarmEvent};
use log::{debug, info, warn};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, Mutex, RwLock};

/// Message type (broadcast or p2p)
#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageType {
    Broadcast,
    P2P,
}
/// Configuration for P2P network setup
#[derive(Clone, Debug)]
pub struct P2PConfig {
    pub bootstrap_peers: Vec<Multiaddr>,
    pub listen_addresses: Vec<Multiaddr>,
    pub protocol: String,
    pub is_bootstrap_node: bool,
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
pub struct SessionInfo {
    pub party_id: u16,
    pub session_id: u16,
    pub sender: mpsc::UnboundedSender<Vec<u8>>,
}

// Implement the trait for SessionInfo
impl SessionInfo {
    fn forward_message(&self, data: Vec<u8>) {
        if let Err(e) = self.sender.send(data) {
            println!("Failed to forward message: {}", e);
        }
    }
}

impl Clone for SessionInfo {
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            session_id: self.session_id,
            sender: self.sender.clone(),
        }
    }
}

pub struct P2PNode {
    swarm: Arc<Mutex<Swarm<AgentBehaviour>>>,
    keypair: Keypair,
    sessions: Arc<RwLock<HashMap<TopicHash, SessionInfo>>>,
    running: Arc<RwLock<bool>>,
    pub protocol: String,
    peers: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
    bootstrap_completed: AtomicBool,
}

const CGGMP_KAD_PROTOCOL: &'static str = "/cggmp/kad/1.0.0";

impl P2PNode {
    /// Constants for peer discovery
    const DISCOVERY_INTERVAL: Duration = Duration::from_secs(600);
    const INITIAL_DISCOVERY_DELAY: Duration = Duration::from_secs(5);
    const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

    /// Creates a new P2P node with custom configuration
    pub async fn new(config: P2PConfig) -> Result<Arc<Self>, P2PError> {
        // Create identity keypair
        let keypair = Keypair::generate_ed25519();
        //let kad_protocol_id = format!("/{}/kad/1.0.0", config.protocol);
        let kad_protocol = StreamProtocol::new(CGGMP_KAD_PROTOCOL);

        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(TcpConfig::default(), NoiseConfig::new, YamuxConfig::default)
            .map_err(|e| P2PError::Protocol(e.to_string()))?
            .with_behaviour(|key| {
                let local_peer_id = PeerId::from(key.clone().public());
                println!("Local peer ID: {local_peer_id}");

                // Set up the Kademlia behavior for peer discovery.
                let mut kad_config = KadConfig::new(kad_protocol);
                kad_config.set_query_timeout(Self::QUERY_TIMEOUT);

                let kad_memory = KadInMemory::new(local_peer_id);
                let kad = KadBehavior::with_config(local_peer_id, kad_memory, kad_config);

                let identity_config = IdentifyConfig::new(
                    format!("/{}/identify/1.0.0", config.protocol),
                    key.clone().public(),
                )
                .with_push_listen_addr_updates(true)
                .with_interval(Duration::from_secs(30));

                let identify = IdentifyBehavior::new(identity_config);

                // Create gossipsub configuration
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .max_transmit_size(262144) // 256KB
                    .protocol_id_prefix(format!("/{}/gossip/1.0", config.protocol))
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .build()
                    .unwrap();

                // Create gossipsub protocol
                let gossipsub = Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                    gossipsub_config,
                )
                .unwrap();

                AgentBehaviour::new(kad, identify, gossipsub)
            })
            .map_err(|e| P2PError::Protocol(e.to_string()))?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        swarm.behaviour_mut().set_server_mode();

        // Listen address setup
        for addr in config.listen_addresses {
            swarm
                .listen_on(addr)
                .map_err(|e| P2PError::Transport(e.to_string()))?;
        }

        // Regular nodes connect to bootstrap peers
        if !config.is_bootstrap_node {
            for addr in config.bootstrap_peers {
                swarm
                    .dial(addr.clone())
                    .map_err(|e| P2PError::Transport(e.to_string()))?;
                println!("Dialed to: {addr}");
            }
        }

        let node = Arc::new(Self {
            swarm: Arc::new(Mutex::new(swarm)),
            keypair,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(true)),
            protocol: config.protocol,
            peers: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_completed: AtomicBool::new(false),
        });

        // Start the event handler loop in a separate task
        let node_clone = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(e) = Self::run(node_clone).await {
                println!("P2P node start error: {}", e);
            }
        });

        // Start periodic protocol announcements if we're not a bootstrap node
        if !config.is_bootstrap_node {
            Arc::clone(&Arc::clone(&node))
                .start_protocol_announcements()
                .await;
        }

        Ok(node)
    }

    /// Creates a new P2P node connection with production configuration
    pub async fn connect(
        bootstrap_addresses: Option<Vec<String>>,
        listen_addresses: Vec<String>,
        protocol: impl Into<String>,
    ) -> Result<Arc<Self>, P2PError> {
        let is_bootstrap_node = bootstrap_addresses.is_none();

        info!("Initializing P2P node:");

        // Parse listening addresses
        let listen_multiaddrs = listen_addresses
            .into_iter()
            .map(|addr| addr.parse())
            .collect::<Result<Vec<Multiaddr>, _>>()
            .map_err(|e| P2PError::Transport(e.to_string()))?;

        // Parse bootstrap peers (empty for bootstrap nodes)
        let bootstrap_peers = bootstrap_addresses
            .unwrap_or_default() // Empty vec for bootstrap nodes
            .into_iter()
            .map(|addr| addr.parse())
            .collect::<Result<Vec<Multiaddr>, _>>()
            .map_err(|e| P2PError::Transport(e.to_string()))?;

        let config = P2PConfig {
            bootstrap_peers,
            listen_addresses: listen_multiaddrs,
            protocol: protocol.into(),
            is_bootstrap_node,
        };

        Self::new(config).await
    }

    /// Main event loop for P2P node operation
    async fn run(node: Arc<Self>) -> Result<(), P2PError> {
        println!("Running");
        while *node.running.read().await {
            // A future that polls the swarm without holding the lock
            let event = {
                let mut swarm = node.swarm.lock().await;
                // Poll once and immediately release the lock
                if let Poll::Ready(Some(event)) = futures::Stream::poll_next(
                    Pin::new(&mut *swarm),
                    &mut Context::from_waker(futures::task::noop_waker_ref()),
                ) {
                    Some(event)
                } else {
                    None
                }
            };

            match event {
                Some(SwarmEvent::Behaviour(AgentBehaviourEvent::Identify(event))) => {
                    P2PNode::handle_identify_event(Arc::clone(&node), event).await;
                }
                Some(SwarmEvent::Behaviour(AgentBehaviourEvent::Gossipsub(event))) => {
                    P2PNode::handle_gossipsub_event(Arc::clone(&node), event).await;
                }
                Some(SwarmEvent::Behaviour(AgentBehaviourEvent::Kad(event))) => {
                    P2PNode::handle_kadelia_event(Arc::clone(&node), event).await;
                }
                Some(SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                }) => {
                    debug!(
                        "Connection established with peer: {}. {:?}",
                        peer_id, endpoint
                    );

                    // Only proceed with bootstrap discovery if:
                    // 1. This is an outbound connection (we initiated it)
                    // 2. We haven't completed bootstrap before
                    // 3. We're not the bootstrap node
                    if endpoint.is_dialer() && !node.bootstrap_completed.load(Ordering::SeqCst) {
                        if let Err(e) =
                            P2PNode::handle_bootstrap_discovery(node.clone(), peer_id).await
                        {
                            info!("Failed to initialize peer discovery: {}", e);
                        } else {
                            // Mark bootstrap as completed
                            node.bootstrap_completed.store(true, Ordering::SeqCst);
                            info!("Bootstrap discovery process completed");
                        }
                    }
                }
                Some(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                    info!("Connection closed with peer: {}", peer_id);

                    // Remove peer from our peers list
                    let mut peers = node.peers.write().await;
                    if peers.remove(&peer_id).is_some() {
                        debug!("Removed disconnected peer {} from peers list", peer_id);
                        info!(
                            "Available peers: {:?}",
                            peers.keys().map(|p| p.to_base58()).collect::<Vec<_>>()
                        );
                    }

                    // Optionally, if you want to also remove from Kademlia DHT
                    let mut swarm = node.swarm.lock().await;
                    swarm.behaviour_mut().remove_peer(&peer_id);

                    // If this was the bootstrap peer and we haven't completed bootstrap,
                    // we might want to log that
                    if !node.bootstrap_completed.load(Ordering::SeqCst) {
                        warn!(
                            "Connection to peer {} closed before bootstrap completion",
                            peer_id
                        );
                    }
                }
                Some(SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                }) => {
                    info!("New listen address: ({listener_id}): {address}");
                }
                Some(SwarmEvent::IncomingConnection {
                    local_addr,
                    send_back_addr,
                    ..
                }) => {
                    debug!(
                        "Incoming connection from: {} to {}",
                        send_back_addr, local_addr
                    );
                }
                Some(SwarmEvent::Dialing {
                    peer_id,
                    connection_id: _,
                }) => {
                    debug!("Dialing peer: {:?}", peer_id);
                }
                Some(_) => {}
                None => {
                    // Small delay to prevent tight loop
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }

        Ok(())
    }

    pub async fn handle_kadelia_event(node: Arc<Self>, event: KadEvent) {
        match event {
            KadEvent::RoutablePeer { peer, address } => {
                info!("Found routable peer: {} at {}", peer, address);
                let mut swarm = node.swarm.lock().await;
                // Attempt to connect to the discovered peer
                if let Err(e) = swarm.dial(address.clone()) {
                    info!("Failed to dial discovered peer: {}", e);
                }
            }
            KadEvent::OutboundQueryProgressed { result, .. } => {
                match result {
                    QueryResult::GetClosestPeers(Ok(ok)) => {
                        debug!("Discovered {} peers near key {:?}", ok.peers.len(), ok.key);
                        for peer_info in ok.peers {
                            let mut swarm = node.swarm.lock().await;
                            // Try to connect to the peer using its provided addresses
                            for addr in peer_info.addrs {
                                if let Err(e) = swarm.dial(addr.clone()) {
                                    debug!(
                                        "Failed to dial discovered peer {}: {}",
                                        peer_info.peer_id, e
                                    );
                                } else {
                                    debug!(
                                        "Successfully dialing peer {} at {}",
                                        peer_info.peer_id, addr
                                    );
                                }
                            }
                        }
                    }
                    QueryResult::GetProviders(Ok(result)) => {
                        match result {
                            GetProvidersOk::FoundProviders { key, providers } => {
                                debug!("Found {} providers for key {:?}", providers.len(), key);
                                for peer in providers {
                                    let mut swarm = node.swarm.lock().await;
                                    // Try to connect if we have the peer's addresses
                                    if let Some(addrs) = node.peers.read().await.get(&peer) {
                                        for addr in addrs {
                                            if let Err(e) = swarm.dial(addr.clone()) {
                                                debug!("Failed to dial provider {}: {}", peer, e);
                                            }
                                        }
                                    }
                                }
                            }
                            GetProvidersOk::FinishedWithNoAdditionalRecord { closest_peers } => {
                                debug!(
                                    "No providers found, but got {} closest peers",
                                    closest_peers.len()
                                );
                                // Try to connect to closest peers as they might be useful for future queries
                                for peer in closest_peers {
                                    let mut swarm = node.swarm.lock().await;
                                    if let Some(addrs) = node.peers.read().await.get(&peer) {
                                        for addr in addrs {
                                            if let Err(e) = swarm.dial(addr.clone()) {
                                                debug!(
                                                    "Failed to dial closest peer {}: {}",
                                                    peer, e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    pub async fn handle_gossipsub_event(node: Arc<Self>, event: GossipEvent) {
        match event {
            GossipEvent::Message {
                propagation_source: _propagation_source,
                message_id,
                message,
            } => {
                Self::handle_incoming_message(&node, message.topic, message.data).await;
            }
            GossipEvent::Subscribed { peer_id, topic } => {
                debug!(
                    "Peer {} subscribed to topic: {}",
                    peer_id,
                    topic.to_string()
                );
            }
            GossipEvent::Unsubscribed { peer_id, topic } => {
                debug!(
                    "Peer {} unsubscribed from topic: {}",
                    peer_id,
                    topic.to_string()
                );
            }
            _ => {}
        }
    }

    pub async fn handle_identify_event(node: Arc<Self>, event: IdentifyEvent) {
        match event {
            IdentifyEvent::Sent {
                connection_id: _connection_id,
                peer_id,
            } => debug!("IdentifyEvent:Sent: {peer_id}"),
            IdentifyEvent::Pushed {
                connection_id: _connection_id,
                peer_id,
                info,
            } => debug!("IdentifyEvent:Pushed: {peer_id} | {info:?}"),
            IdentifyEvent::Received {
                connection_id: _connection_id,
                peer_id,
                info,
            } => {
                debug!("IdentifyEvent:Received: {peer_id} | {info:?}");
                {
                    let mut peers = node.peers.write().await;
                    if peers.insert(peer_id, info.clone().listen_addrs).is_none() {
                        info!(
                            "Available peers: {:?}",
                            peers.keys().map(|p| p.to_base58()).collect::<Vec<_>>()
                        );
                    }
                }

                for addr in info.clone().listen_addrs {
                    let mut swarm = node.swarm.lock().await;
                    let agent_routing = swarm.behaviour_mut().register(&peer_id, addr.clone());
                    match agent_routing {
                        RoutingUpdate::Failed => {
                            warn!("IdentifyReceived: Failed to register address to Kademlia")
                        }
                        RoutingUpdate::Pending => {
                            debug!("IdentifyReceived: Register address pending")
                        }
                        RoutingUpdate::Success => {
                            debug!("IdentifyReceived: {addr}: Success register address");
                        }
                    }

                    _ = swarm.behaviour_mut().register(&peer_id, addr.clone());
                }
            }
            _ => {}
        }
    }

    /// Handles peer discovery after bootstrap connection
    async fn handle_bootstrap_discovery(
        node: Arc<Self>,
        bootstrap_peer: PeerId,
    ) -> Result<(), P2PError> {
        info!("Starting bootstrap discovery process");

        // First announce ourselves as a provider
        node.announce_protocol().await?;

        // Get closest peers to bootstrap peer
        info!("Querying closest peers to bootstrap peer");
        let mut swarm = node.swarm.lock().await;
        swarm.behaviour_mut().get_closest_peers(bootstrap_peer);

        // Look for other protocol providers
        info!("Searching for other protocol providers");
        let protocol_key = node.get_protocol_key();
        swarm.behaviour_mut().get_providers(protocol_key);

        // Start periodic discovery
        let periodic_node = Arc::clone(&node);
        tokio::spawn(async move {
            // Initial delay to allow connection setup
            tokio::time::sleep(Self::INITIAL_DISCOVERY_DELAY).await;

            let mut interval = tokio::time::interval(Self::DISCOVERY_INTERVAL);
            while *periodic_node.running.read().await {
                if let Err(e) = periodic_node.announce_protocol().await {
                    debug!("Failed to announce protocol: {}", e);
                }
                interval.tick().await;
            }
        });

        Ok(())
    }

    /// Performs a discovery cycle
    async fn perform_discovery(&self) -> Result<(), P2PError> {
        // Get current peers for discovery
        let peers: Vec<PeerId> = self.peers.read().await.keys().cloned().collect();

        let mut swarm = self.swarm.lock().await;

        // Query random peers to expand network view
        for peer_id in peers.choose_multiple(&mut rand::thread_rng(), 3) {
            swarm.behaviour_mut().get_closest_peers(*peer_id);
        }

        // Refresh protocol-specific discovery
        let protocol_key = self.get_protocol_key();
        let mut swarm = self.swarm.lock().await;
        swarm.behaviour_mut().get_providers(protocol_key);

        Ok(())
    }

    /// Start periodic protocol announcements
    async fn start_protocol_announcements(self: Arc<Self>) {
        let node = Arc::clone(&self);
        tokio::spawn(async move {
            info!("Starting periodic protocol announcements");
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            while let Ok(true) = node.running.try_read().map(|guard| *guard) {
                let announcement_result = {
                    // Scope the lock to ensure it's released quickly
                    let protocol_key = node.get_protocol_key();
                    if let Ok(mut swarm) = node.swarm.try_lock() {
                        match swarm.behaviour_mut().start_providing(protocol_key) {
                            Ok(query_id) => {
                                debug!(
                                    "Successfully announced as protocol provider: {:?}",
                                    query_id
                                );
                                Ok(())
                            }
                            Err(e) => Err(P2PError::Protocol(format!(
                                "Failed to start providing: {}",
                                e
                            ))),
                        }
                    } else {
                        Ok(()) // Don't treat lock contention as an error
                    }
                };

                // Use timeout for tick to prevent permanent blocking
                if tokio::time::timeout(Duration::from_secs(5), interval.tick())
                    .await
                    .is_err()
                {
                    debug!("Interval tick timed out");
                }
            }
            warn!("Protocol announcements stopped");
        });
    }

    async fn announce_protocol(&self) -> Result<(), P2PError> {
        let protocol_key = self.get_protocol_key();

        // Use try_lock with timeout to prevent deadlock
        let mut swarm = tokio::time::timeout(Duration::from_secs(5), self.swarm.lock())
            .await
            .map_err(|_| P2PError::Protocol("Swarm lock timeout".into()))?;

        // Scope the lock usage
        let result = swarm.behaviour_mut().start_providing(protocol_key);

        match result {
            Ok(query_id) => {
                debug!(
                    "Successfully announced as protocol provider: {:?}",
                    query_id
                );
                Ok(())
            }
            Err(e) => Err(P2PError::Protocol(format!(
                "Failed to start providing: {}",
                e
            ))),
        }
    }

    /// Generates a protocol-specific key for discovery
    fn get_protocol_key(&self) -> RecordKey {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.protocol.as_bytes());
        RecordKey::new(&hasher.finalize())
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

        debug!("Incoming message on topic: {}", topic.inner.hash());

        // Infer message type based on topic format
        if topic.is_broadcast() {
            // Broadcast message - forward to all sessions with matching session_id
            if let Some(session) = sessions.get(&topic.hash()) {
                session.forward_message(data);
            }
        } else if topic.is_p2p() {
            // P2P message - forward only to the specific session matching the topic
            if let Some(session) = sessions.get(&topic.hash()) {
                // Forward the network message
                session.forward_message(data);
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
        sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<(), P2PError> {
        // Create topics using the new Topic struct
        let broadcast_topic = self.get_broadcast_topic(session_id);
        let p2p_topic = self.get_p2p_topic(party_id, session_id);

        let session_info = SessionInfo {
            party_id,
            session_id,
            sender,
        };

        let mut swarm = self.swarm.lock().await;

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

        let mut swarm = self.swarm.lock().await;

        // Unsubscribe from broadcast topic
        swarm
            .behaviour_mut()
            .unsubscribe(broadcast_topic.as_ident_topic());

        // Unsubscribe from P2P topic
        swarm
            .behaviour_mut()
            .unsubscribe(p2p_topic.as_ident_topic());

        // Remove session information from storage
        let mut sessions = self.sessions.write().await;
        sessions.remove(&broadcast_topic.hash());
        sessions.remove(&p2p_topic.hash());

        Ok(())
    }

    pub async fn publish_message<M>(
        &self,
        data: &M,
        recipient: Option<u16>,
        session_id: u16,
    ) -> Result<(), P2PError>
    where
        M: Serialize + Send + 'static,
    {
        debug!(
            "Publishing message to session {}, recipient: {}",
            session_id,
            recipient.map_or("all".to_string(), |r| r.to_string())
        );

        // Serialize the network message
        let msg_data = bincode::serialize(&data).map_err(|e| {
            P2PError::Protocol(format!("Network message serialization error: {}", e))
        })?;

        let mut swarm = self.swarm.lock().await;

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
