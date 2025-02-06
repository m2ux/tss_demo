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

#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct AgentBehaviour {
    identify: identify::Behaviour,
    gossipsub: gossipsub::Behaviour,
    kad: libp2p_kad::Behaviour<MemoryStore>,
}

impl AgentBehaviour {
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

    pub fn register(&mut self, peer_id: &PeerId, addr: Multiaddr) -> RoutingUpdate {
        self.kad.add_address(peer_id, addr)
    }

    pub fn remove_peer(
        &mut self,
        peer_id: &PeerId,
    ) -> Option<EntryView<KBucketKey<PeerId>, Addresses>> {
        self.kad.remove_peer(peer_id)
    }

    pub fn get_closest_peers<K>(&mut self, key: K) -> QueryId
    where
        K: Into<Vec<u8>> + Clone,
        KBucketKey<K>: From<K>,
    {
        self.kad.get_closest_peers(key)
    }

    pub fn start_providing(&mut self, key: RecordKey) -> Result<QueryId, store::Error> {
        self.kad.start_providing(key)
    }

    pub fn get_providers(&mut self, key: RecordKey) -> QueryId {
        self.kad.get_providers(key)
    }

    pub fn set_server_mode(&mut self) {
        self.kad.set_mode(Some(libp2p::kad::Mode::Server))
    }

    pub fn subscribe<H: Hasher>(&mut self, topic: &Topic<H>) -> Result<bool, SubscriptionError> {
        self.gossipsub.subscribe(topic)
    }

    pub fn unsubscribe<H: Hasher>(&mut self, topic: &Topic<H>) -> bool {
        self.gossipsub.unsubscribe(topic)
    }

    pub fn publish(
        &mut self,
        topic: impl Into<TopicHash>,
        data: impl Into<Vec<u8>>,
    ) -> Result<MessageId, PublishError> {
        self.gossipsub.publish(topic, data)
    }
}

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
