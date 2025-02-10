//! P2P network behavior implementation for the CGGMP21 protocol.
//!
//! This module defines the network behavior for P2P nodes, combining multiple libp2p
//! protocols:
//! - Kademlia for peer discovery and DHT operations
//! - GossipSub for pub/sub message distribution
//! - Identify for peer information exchange
//!
//! The behavior implementation coordinates these protocols to provide a complete
//! networking solution for the distributed protocol.
//!
//! # Protocol Integration
//!
//! The behavior combines three key libp2p protocols:
//! * Kademlia - Distributed Hash Table (DHT) for peer discovery
//! * GossipSub - Publish/Subscribe messaging system
//! * Identify - Peer metadata and address exchange
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use crate::p2p_behaviour::AgentBehaviour;
//!
//! let kad = KademliaBehavior::new(...);
//! let identify = IdentifyBehavior::new(...);
//! let gossipsub = Behaviour::new(...);
//!
//! let behaviour = AgentBehaviour::new(kad, identify, gossipsub);
//! ```
use gossipsub::Event as GossipEvent;
use libp2p::identify::{Behaviour as IdentifyBehavior, Event as IdentifyEvent};
use libp2p::kad::RoutingUpdate;
use libp2p::kad::{
    store::MemoryStore as KademliaInMemory, Behaviour as KademliaBehavior, Event as KademliaEvent,
};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, Multiaddr, PeerId};
use libp2p_gossipsub::{Hasher, MessageId, PublishError, SubscriptionError, Topic, TopicHash};
use libp2p_kad::store::MemoryStore;
use libp2p_kad::{store, Addresses, EntryView, KBucketKey, PeerInfo, QueryId, RecordKey};

/// Network behavior implementation combining Kademlia, GossipSub, and Identify protocols.
///
/// This struct implements the NetworkBehaviour trait to provide a complete P2P
/// networking solution. It manages peer discovery, message routing, and network
/// metadata exchange.
#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct AgentBehaviour {
    /// Identify protocol for peer metadata exchange
    identify: identify::Behaviour,
    /// GossipSub protocol for pub/sub messaging
    gossipsub: gossipsub::Behaviour,
    /// Kademlia protocol for DHT and peer discovery
    kad: libp2p_kad::Behaviour<MemoryStore>,
}

impl AgentBehaviour {
    /// Creates a new AgentBehaviour instance.
    ///
    /// # Arguments
    ///
    /// * `kad` - Configured Kademlia behavior instance
    /// * `identify` - Configured Identify behavior instance
    /// * `gossipsub` - Configured GossipSub behavior instance
    ///
    /// # Returns
    ///
    /// Returns a new AgentBehaviour instance combining the provided protocol behaviors
    pub fn new(
        kad: KademliaBehavior<KademliaInMemory>,
        identify: IdentifyBehavior,
        gossipsub: gossipsub::Behaviour,
    ) -> Self {
        Self {
            kad,
            identify,
            gossipsub,
        }
    }

    /// Registers a peer's address in the Kademlia routing table.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - ID of the peer to register
    /// * `addr` - Multiaddress of the peer
    ///
    /// # Returns
    ///
    /// Returns a RoutingUpdate indicating the result of the registration
    pub fn register(&mut self, peer_id: &PeerId, addr: Multiaddr) -> RoutingUpdate {
        self.kad.add_address(peer_id, addr)
    }

    /// Removes a peer from the Kademlia routing table.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - ID of the peer to remove
    ///
    /// # Returns
    ///
    /// Returns the removed entry if the peer was present
    pub fn remove_peer(
        &mut self,
        peer_id: &PeerId,
    ) -> Option<EntryView<KBucketKey<PeerId>, Addresses>> {
        self.kad.remove_peer(peer_id)
    }

    /// Initiates a query for peers closest to a given key.
    ///
    /// # Arguments
    ///
    /// * `key` - Key to search for in the DHT
    ///
    /// # Returns
    ///
    /// Returns a QueryId for tracking the query
    pub fn get_closest_peers<K>(&mut self, key: K) -> QueryId
    where
        K: Into<Vec<u8>> + Clone,
        KBucketKey<K>: From<K>,
    {
        self.kad.get_closest_peers(key)
    }

    /// Announces this node as a provider for a key in the DHT.
    ///
    /// # Arguments
    ///
    /// * `key` - Key to provide
    ///
    /// # Returns
    ///
    /// Returns a Result containing the QueryId or a store error
    pub fn start_providing(&mut self, key: RecordKey) -> Result<QueryId, store::Error> {
        self.kad.start_providing(key)
    }

    /// Initiates a query for providers of a key.
    ///
    /// # Arguments
    ///
    /// * `key` - Key to find providers for
    ///
    /// # Returns
    ///
    /// Returns a QueryId for tracking the query
    pub fn get_providers(&mut self, key: RecordKey) -> QueryId {
        self.kad.get_providers(key)
    }

    /// Sets the Kademlia node into server mode.
    ///
    /// Server mode nodes participate fully in DHT operations and maintain
    /// routing tables.
    pub fn set_server_mode(&mut self) {
        self.kad.set_mode(Some(libp2p::kad::Mode::Server))
    }

    /// Subscribes to a GossipSub topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic to subscribe to
    ///
    /// # Returns
    ///
    /// Returns a Result indicating subscription success or failure
    pub fn subscribe<H: Hasher>(&mut self, topic: &Topic<H>) -> Result<bool, SubscriptionError> {
        self.gossipsub.subscribe(topic)
    }

    /// Unsubscribes from a GossipSub topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic to unsubscribe from
    ///
    /// # Returns
    ///
    /// Returns true if successfully unsubscribed
    pub fn unsubscribe<H: Hasher>(&mut self, topic: &Topic<H>) -> bool {
        self.gossipsub.unsubscribe(topic)
    }

    /// Publishes a message to a GossipSub topic.
    ///
    /// # Arguments
    ///
    /// * `topic` - Topic to publish to
    /// * `data` - Message data to publish
    ///
    /// # Returns
    ///
    /// Returns a Result containing the MessageId or publishing error
    pub fn publish(
        &mut self,
        topic: impl Into<TopicHash>,
        data: impl Into<Vec<u8>>,
    ) -> Result<MessageId, PublishError> {
        self.gossipsub.publish(topic, data)
    }
}

/// Conversion implementations for behavior events
/// 
impl From<IdentifyEvent> for AgentBehaviourEvent {
    fn from(value: IdentifyEvent) -> Self {
        Self::Identify(value)
    }
}

impl From<KademliaEvent> for AgentBehaviourEvent {
    fn from(value: KademliaEvent) -> Self {
        Self::Kad(value)
    }
}

impl From<GossipEvent> for AgentBehaviourEvent {
    fn from(value: GossipEvent) -> Self {
        Self::Gossipsub(value)
    }
}
