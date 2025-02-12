//! P2P-based delivery layer for distributed protocol communication.
//!
//! This module provides P2P networking capabilities using libp2p for peer-to-peer
//! message routing and discovery. It implements:
//! - Peer discovery using Kademlia DHT
//! - Topic-based pub/sub using GossipSub
//! - Secure message transport with noise encryption
//! - Session-based message routing
//!
//! # Architecture
//!
//! The system is built on several key components:
//! * P2PNode - Core node managing network operations
//! * ProtocolTopic - Topic management for message routing
//! * SessionInfo - Session-based message handling
//!
//! # Protocol Components
//!
//! The node implements multiple libp2p protocols:
//! * Kademlia - For peer discovery and DHT operations
//! * GossipSub - For pub/sub message distribution
//! * Identify - For peer information exchange
//! * Noise - For transport encryption
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use crate::p2p_node::P2PNode;
//!
//! async fn example() -> Result<(), P2PError> {
//!     let node = P2PNode::connect(
//!         Some(vec!["bootstrap-addr".to_string()]),
//!         vec!["listen-addr".to_string()],
//!         "cggmp".to_string(),
//!     ).await?;
//!
//!     // Use node for P2P communication
//!     Ok(())
//! }
//! ```

use crate::p2p_behaviour::{AgentBehaviour, AgentBehaviourEvent};
use crate::p2p_topic::ProtocolTopic;
use libp2p::identify::{
    Behaviour as IdentifyBehavior, Config as IdentifyConfig, Event as IdentifyEvent,
};
use libp2p::kad::{
    store::MemoryStore as KadInMemory, Behaviour as KadBehavior, Config as KadConfig,
    Event as KadEvent, RoutingUpdate,
};
use libp2p::noise::Config as NoiseConfig;
use libp2p::{
    tcp::Config as TcpConfig, yamux::Config as YamuxConfig, Multiaddr, StreamProtocol, Swarm,
    SwarmBuilder,
};
use libp2p_gossipsub as gossipsub;
use libp2p_gossipsub::{Behaviour, Event as GossipEvent, IdentTopic, TopicHash};
use libp2p_identity::{self, Keypair, PeerId};
use libp2p_kad::{GetProvidersOk, QueryResult, RecordKey};
use libp2p_swarm::SwarmEvent;
use log::{debug, info, warn};
use serde::Serialize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{mpsc, Mutex, RwLock};

/// Configuration for P2P network setup
#[derive(Clone, Debug)]
pub struct P2PConfig {
    /// Addresses of bootstrap nodes for initial network connection
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Local addresses to listen on
    pub listen_addresses: Vec<Multiaddr>,
    /// Protocol identifier for network separation
    pub protocol: String,
    /// Whether this node is a bootstrap node
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
    /// Unique identifier for the party in this session
    pub party_id: u16,
    /// Unique identifier for the session
    pub session_id: u16,
    /// Channel for sending messages to this session
    pub sender: mpsc::UnboundedSender<Vec<u8>>,
}

impl SessionInfo {
    fn new(party_id: u16, session_id: u16, sender: UnboundedSender<Vec<u8>>) -> Self {
        SessionInfo {
            party_id,
            session_id,
            sender,
        }
    }
}

// Implement the trait for SessionInfo
impl SessionInfo {
    fn forward_message(&self, data: Vec<u8>) {
        if let Err(e) = self.sender.send(data) {
            info!("Failed to forward message: {}", e);
        }
    }
}

/// Clone implementation for SessionInfo
impl Clone for SessionInfo {
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            session_id: self.session_id,
            sender: self.sender.clone(),
        }
    }
}

/// Core P2P networking node
///
/// Manages peer connections, message routing, and protocol operations.
/// Provides topic-based pub/sub and session management capabilities.
pub struct P2PNode {
    /// Protocol identifier
    pub protocol: String,
    /// Bootstrap completion flag
    pub bootstrap_completed: AtomicBool,
    /// Network swarm managing peer connections and protocols
    swarm: Arc<Mutex<Swarm<AgentBehaviour>>>,
    /// Node identity keypair
    keypair: Keypair,
    /// Active communication sessions
    sessions: Arc<RwLock<HashMap<TopicHash, SessionInfo>>>,
    /// Node running state
    running: Arc<RwLock<bool>>,
    /// Known peers and their addresses
    peers: Arc<RwLock<HashMap<PeerId, Vec<Multiaddr>>>>,
}

impl P2PNode {
    /// Constants for peer discovery
    const DISCOVERY_INTERVAL: Duration = Duration::from_secs(600);
    const INITIAL_DISCOVERY_DELAY: Duration = Duration::from_secs(5);
    const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

    /// Creates a new P2P node with custom configuration
    ///
    /// # Arguments
    /// * `config` - Configuration for the P2P node
    ///
    /// # Returns
    /// Arc-wrapped P2PNode or error if initialization fails
    ///
    /// # Errors
    /// Returns P2PError for transport, swarm, or protocol initialization failures
    pub async fn new(config: P2PConfig) -> Result<Arc<Self>, P2PError> {
        // Create identity keypair
        let keypair = Keypair::generate_ed25519();
        let kad_protocol = StreamProtocol::new("/kad/1.0.0");

        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(TcpConfig::default(), NoiseConfig::new, YamuxConfig::default)
            .map_err(|e| P2PError::Protocol(e.to_string()))?
            .with_behaviour(|key| {
                let local_peer_id = PeerId::from(key.clone().public());
                info!("Local peer ID: {local_peer_id}");

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
                info!("Dialed to: {addr}");
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
                info!("P2P node start error: {}", e);
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

    /// Creates a new P2P node with standard configuration
    ///
    /// # Arguments
    /// * `bootstrap_addresses` - Optional list of bootstrap node addresses
    /// * `listen_addresses` - Addresses to listen on
    /// * `protocol` - Protocol identifier
    ///
    /// # Returns
    /// Arc-wrapped P2PNode or error if initialization fails
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
    ///
    /// Handles network events, peer connections, and message routing
    async fn run(node: Arc<Self>) -> Result<(), P2PError> {
        info!("Running");
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
                // Handle Identify protocol events for peer discovery and identification
                Some(SwarmEvent::Behaviour(AgentBehaviourEvent::Identify(event))) => {
                    P2PNode::handle_identify_event(Arc::clone(&node), event).await;
                }
                // Handle GossipSub events for pub/sub messaging
                Some(SwarmEvent::Behaviour(AgentBehaviourEvent::Gossipsub(event))) => {
                    P2PNode::handle_gossipsub_event(Arc::clone(&node), event).await;
                }
                // Handle Kademlia DHT events for peer discovery and routing
                Some(SwarmEvent::Behaviour(AgentBehaviourEvent::Kad(event))) => {
                    P2PNode::handle_kadelia_event(Arc::clone(&node), event).await;
                }
                // Handle new peer connections and bootstrap discovery
                Some(SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                }) => {
                    info!("Connection established with peer: {}", peer_id);

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
                // Handle peer disconnections and cleanup
                Some(SwarmEvent::ConnectionClosed { peer_id, .. }) => {
                    info!("Connection closed with peer: {}", peer_id);

                    // Remove peer from our peers list
                    let mut peers = node.peers.write().await;
                    if peers.remove(&peer_id).is_some() {
                        debug!("Removed disconnected peer {} from peers list", peer_id);
                        debug!(
                            "Available peers: {:?}",
                            peers.keys().map(|p| p.to_base58()).collect::<Vec<_>>()
                        );
                    }

                    // Remove from Kademlia DHT
                    let mut swarm = node.swarm.lock().await;
                    swarm.behaviour_mut().remove_peer(&peer_id);

                    // If this was the bootstrap peer and we haven't completed bootstrap,
                    // we might want to log that
                    if !node.bootstrap_completed.load(Ordering::SeqCst) {
                        debug!(
                            "Connection to peer {} closed before bootstrap completion",
                            peer_id
                        );
                    }
                }
                // Handle new local listening addresses
                Some(SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                }) => {
                    info!("New listen address: ({listener_id}): {address}");
                }
                // Handle incoming connection attempts
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
                // Handle outgoing connection attempts
                Some(SwarmEvent::Dialing {
                    peer_id,
                    connection_id: _,
                }) => {
                    debug!("Dialing peer: {:?}", peer_id);
                }
                // Ignore other swarm events
                Some(_) => {}
                // No events available, add small delay to prevent busy loop
                None => {
                    // Small delay to prevent tight loop
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }

        Ok(())
    }

    /// Returns the PeerId of this node
    pub fn peer_id(&self) -> PeerId {
        PeerId::from(self.keypair.public())
    }

    /// Handles Kademlia DHT events
    ///
    /// Processes peer discovery and routing table updates
    pub async fn handle_kadelia_event(node: Arc<Self>, event: KadEvent) {
        match event {
            // Handle discovery of a directly routable peer with known address
            KadEvent::RoutablePeer { peer, address } => {
                info!("Found routable peer: {} at {}", peer, address);
                let mut swarm = node.swarm.lock().await;
                // Attempt to connect to the discovered peer
                if let Err(e) = swarm.dial(address.clone()) {
                    info!("Failed to dial discovered peer: {}", e);
                }
            }
            // Handle results from outbound Kademlia queries
            KadEvent::OutboundQueryProgressed { result, .. } => {
                match result {
                    // Handle response when searching for closest peers to a key
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
                    // Handle response when querying for providers of a specific key
                    QueryResult::GetProviders(Ok(result)) => {
                        match result {
                            // Found peers providing the requested key
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
                            // No providers found, but received list of closest peers
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
                    // Ignore other query results
                    _ => {}
                }
            }
            // Ignore other Kademlia events
            _ => {}
        }
    }

    /// Handles GossipSub messaging events
    ///
    /// Processes pub/sub messages and subscription changes
    pub async fn handle_gossipsub_event(node: Arc<Self>, event: GossipEvent) {
        match event {
            // Handle incoming messages from the network
            GossipEvent::Message {
                propagation_source: _propagation_source,
                message_id: _message_id,
                message,
            } => {
                Self::handle_incoming_message(&node, message.topic, message.data).await;
            }
            // Handle peer subscription events
            GossipEvent::Subscribed { peer_id, topic } => {
                debug!(
                    "Peer {} subscribed to topic: {}",
                    peer_id,
                    topic.to_string()
                );
            }
            // Handle peer unsubscription events
            GossipEvent::Unsubscribed { peer_id, topic } => {
                debug!(
                    "Peer {} unsubscribed from topic: {}",
                    peer_id,
                    topic.to_string()
                );
            }
            // Ignore other gossipsub events
            _ => {}
        }
    }

    /// Handles Identify protocol events
    ///
    /// Processes peer information updates and address registration
    pub async fn handle_identify_event(node: Arc<Self>, event: IdentifyEvent) {
        match event {
            // Handle sent identify protocol messages
            IdentifyEvent::Sent {
                connection_id: _connection_id,
                peer_id,
            } => debug!("IdentifyEvent:Sent: {peer_id}"),

            // Handle pushed identify updates
            IdentifyEvent::Pushed {
                connection_id: _connection_id,
                peer_id,
                info,
            } => debug!("IdentifyEvent:Pushed: {peer_id} | {info:?}"),

            // Handle received identify information from remote peers
            IdentifyEvent::Received {
                connection_id: _connection_id,
                peer_id,
                info,
            } => {
                debug!("IdentifyEvent:Received: {peer_id} | {info:?}");
                {
                    // Update peers map with newly received addresses
                    let mut peers = node.peers.write().await;
                    if peers.insert(peer_id, info.clone().listen_addrs).is_none() {
                        debug!(
                            "Available peers: {:?}",
                            peers.keys().map(|p| p.to_base58()).collect::<Vec<_>>()
                        );
                    }
                }

                // Register each address with Kademlia DHT
                for addr in info.clone().listen_addrs {
                    let mut swarm = node.swarm.lock().await;
                    let agent_routing = swarm.behaviour_mut().register(&peer_id, addr.clone());
                    match agent_routing {
                        // Log failures to add addresses to routing table
                        RoutingUpdate::Failed => {
                            warn!("IdentifyReceived: Failed to register address to Kademlia")
                        }
                        // Log pending address validations
                        RoutingUpdate::Pending => {
                            debug!("IdentifyReceived: Register address pending")
                        }
                        // Log successful address registrations
                        RoutingUpdate::Success => {
                            debug!("IdentifyReceived: {addr}: Success register address");
                        }
                    }

                    _ = swarm.behaviour_mut().register(&peer_id, addr.clone());
                }
            }
            // Ignore other identify events
            _ => {}
        }
    }

    /// Handles peer discovery after bootstrap connection
    ///
    /// Sets up initial peer discovery and protocol announcements
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

    /// Start periodic protocol announcements
    ///
    /// Announces node presence to the network periodically
    async fn start_protocol_announcements(self: Arc<Self>) {
        let node = Arc::clone(&self);
        tokio::spawn(async move {
            info!("Starting periodic protocol announcements");
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            while let Ok(true) = node.running.try_read().map(|guard| *guard) {
                let _announcement_result = {
                    // Scope the lock to ensure it's released quickly
                    if let Ok(mut swarm) = node.swarm.try_lock() {
                        let protocol_key = node.get_protocol_key();
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

    /// Announces this node's protocol support to the network
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

    /// Handles incoming messages and routes them to the appropriate sessions.
    ///
    /// This method processes messages received over the P2P network and forwards them
    /// to the relevant session handlers based on topic matching. It supports both
    /// broadcast and point-to-point message routing.
    ///
    /// # Arguments
    ///
    /// * `node` - Reference to the P2P node instance
    /// * `topic_hash` - Hash of the topic the message was received on
    /// * `data` - Raw message data as bytes
    ///
    /// # Message Routing
    ///
    /// Messages are routed based on their topic type:
    /// - Broadcast topics (`{protocol}/broadcast/{session_id}`):
    ///   * Messages are forwarded to all sessions matching the session ID
    ///   * Used for protocol-wide announcements and coordination
    ///
    /// - P2P topics (`{protocol}/p2p/{session_id}/{party_id}`):
    ///   * Messages are forwarded only to the specific session matching both
    ///     session ID and party ID
    ///   * Used for direct communication between parties
    ///
    /// # Implementation Details
    ///
    /// 1. Converts the topic hash to a ProtocolTopic instance
    /// 2. Determines message type (broadcast or P2P) from topic format
    /// 3. Looks up relevant sessions in the sessions registry
    /// 4. Forwards message data to matching session channels
    ///
    ///
    /// # Thread Safety
    ///
    /// - Uses read-only access to sessions registry
    /// - Message forwarding is done through thread-safe channels
    /// - Topic parsing is performed immutably
    ///
    async fn handle_incoming_message(node: &Arc<Self>, topic_hash: TopicHash, data: Vec<u8>) {
        debug!("Incoming message on topic: {}", topic.hash());

        let sessions = node.sessions.read().await;
        let topic = ProtocolTopic::from_protocol(topic_hash, node.protocol.clone());

        // Forward valid topic to relevant session
        if topic.is_broadcast() || topic.is_p2p() {
            if let Some(session) = sessions.get(&topic.hash()) {
                session.forward_message(data);
            }
        }
    }

    /// Subscribes to relevant topics for a party in a session
    ///
    /// # Arguments
    /// * `party_id` - Party identifier
    /// * `session_id` - Session identifier
    /// * `sender` - Channel for forwarding received messages
    ///
    /// # Errors
    /// Returns P2PError if subscription fails
    pub async fn subscribe_to_session(
        &self,
        party_id: u16,
        session_id: u16,
        sender: UnboundedSender<Vec<u8>>,
    ) -> Result<(), P2PError> {
        let broadcast_topic = ProtocolTopic::new_broadcast(&self.protocol, session_id);
        let p2p_topic = ProtocolTopic::new_p2p(&self.protocol, party_id, session_id);
        let session_info = SessionInfo::new(party_id, session_id, sender);

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

    /// Unsubscribes from a session's topics
    ///
    /// # Arguments
    /// * `party_id` - Party identifier
    /// * `session_id` - Session identifier
    ///
    /// # Errors
    /// Returns P2PError if unsubscription fails
    pub async fn unsubscribe_from_session(
        &self,
        party_id: u16,
        session_id: u16,
    ) -> Result<(), P2PError> {
        // Create topics using the existing topic creation methods
        let broadcast_topic = ProtocolTopic::new_broadcast(&self.protocol, session_id);
        let p2p_topic = ProtocolTopic::new_p2p(&self.protocol, party_id, session_id);

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

    /// Publishes a message to the network
    ///
    /// # Arguments
    /// * `data` - Message to publish
    /// * `recipient` - Optional specific recipient
    /// * `session_id` - Session identifier
    ///
    /// # Type Parameters
    /// * `M` - Message type implementing Serialize
    ///
    /// # Errors
    /// Returns P2PError if publishing fails
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
                let topic = ProtocolTopic::new_broadcast(&self.protocol, session_id);
                swarm
                    .behaviour_mut()
                    .publish(topic.as_ident_topic().clone(), msg_data)
                    .map(|_| ())
                    .map_err(|e| P2PError::Protocol(e.to_string()))?;
            }
            Some(party_id) => {
                // P2P message
                let topic = ProtocolTopic::new_p2p(&self.protocol, party_id, session_id);
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
