use crate::network::{MessageState, PartySession, SessionMessage, WireMessage};
use futures::{AsyncRead, AsyncWrite, StreamExt};
use libp2p_core::transport::{Boxed, OrTransport, upgrade::Version};
use libp2p_identify as identify;
use libp2p_identity::{self, Keypair, PeerId, PublicKey};
use libp2p_kad::{
    self,
    store::MemoryStore,
    Behaviour as KademliaBehaviour,
    Config as KademliaConfig,
    Event as KademliaEvent,
};
use libp2p_noise as noise;
use libp2p_request_response::{
    self, Behaviour as RequestResponseBehaviour, Codec as RequestResponseCodec, Config as RequestResponseConfig,
    Event as RequestResponseEvent, Message as RequestMessage, ProtocolSupport,
    ResponseChannel,
};
use libp2p_swarm::{
    NetworkBehaviour,
    Swarm,
    SwarmEvent,
    ConnectionHandler,
    ToSwarm,
};
use libp2p_tcp as tcp;
use libp2p_yamux as yamux;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use std::future::Future;
use std::pin::Pin;
use async_trait::async_trait;
use futures_util::{AsyncReadExt, AsyncWriteExt};
use libp2p::kad::QueryResult;
use libp2p::Multiaddr;
use libp2p_core::Transport;
use thiserror::Error;
use tokio::sync::RwLock;
/// Protocol version for compatibility checking
const PROTOCOL_VERSION: &str = "cggmp21/1.0.0";

#[derive(Error, Debug)]
pub enum P2PError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Swarm error: {0}")]
    Swarm(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Network error: {0}")]
    Network(String),
}

#[derive(Clone, Debug)]
pub struct P2PConfig {
    pub party_id: u16,
    pub session_id: u16,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub listen_addresses: Vec<Multiaddr>,
}

#[derive(Debug)]
pub enum CggmpBehaviourEvent {
    RequestResponse(RequestResponseEvent<P2PMessage, ()>),
    Kademlia(KademliaEvent),
    Identify(identify::Event),
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "CggmpBehaviourEvent")]
#[behaviour(event_process = false)]
struct CggmpBehaviour {
    request_response: RequestResponseBehaviour<CggmpCodec>,
    kademlia: KademliaBehaviour<MemoryStore>,
    identify: identify::Behaviour,
}

impl From<RequestResponseEvent<P2PMessage, ()>> for CggmpBehaviourEvent {
    fn from(event: RequestResponseEvent<P2PMessage, ()>) -> Self {
        CggmpBehaviourEvent::RequestResponse(event)
    }
}

impl From<KademliaEvent> for CggmpBehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        CggmpBehaviourEvent::Kademlia(event)
    }
}

impl From<identify::Event> for CggmpBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        CggmpBehaviourEvent::Identify(event)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Protocol(WireMessage),
    Session(SessionMessage),
}

#[derive(Clone)]
#[derive(Default)]
pub struct CggmpCodec;

pub struct P2PNode {
    swarm: Swarm<CggmpBehaviour>,
    local_session: PartySession,
    peers: Arc<RwLock<HashMap<PeerId, PartySession>>>,
    message_state: Arc<RwLock<MessageState>>,
}

impl P2PNode {
    pub async fn new(config: P2PConfig) -> Result<Self, P2PError> {
        // Create identity keypair
        let id_keys = Keypair::generate_ed25519();
        let peer_id = PeerId::from(id_keys.public());

        // Create noise keys for encryption
        let noise_config =
            libp2p_noise::Config::new(&id_keys).map_err(|e| P2PError::Protocol(e.to_string()))?;

        // Create transport with noise encryption and yamux multiplexing
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(Version::V1Lazy)
            .authenticate(noise_config)
            .multiplex(yamux::Config::default())
            .boxed();

        // Create request-response protocol
        let request_response = RequestResponseBehaviour::new(
            vec![(PROTOCOL_VERSION.to_string(), ProtocolSupport::Full)],
            RequestResponseConfig::default(),
        );

        // Create Kademlia DHT
        let store = MemoryStore::new(peer_id);
        let kad_config = KademliaConfig::default();
        let kademlia = KademliaBehaviour::with_config(
            peer_id,
            store,
            kad_config,
        );

        // Create identify protocol
        let identify = identify::Behaviour::new(identify::Config::new(
            PROTOCOL_VERSION.to_string(),
            id_keys.public(),
        ));

        // Create behaviour
        let behaviour = CggmpBehaviour {
            request_response,
            kademlia,
            identify,
        };

        // Create swarm config with tokio executor
        let swarm_config = libp2p_swarm::Config::with_executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
            .with_idle_connection_timeout(Duration::from_secs(60));

        let mut swarm = libp2p_swarm::Swarm::new(
            transport,
            behaviour,
            peer_id,
            swarm_config,
        );

        // Listen on provided addresses
        for addr in config.listen_addresses {
            swarm
                .listen_on(addr)
                .map_err(|e| P2PError::Swarm(e.to_string()))?;
        }

        Ok(Self {
            swarm,
            local_session: PartySession {
                party_id: config.party_id,
                session_id: config.session_id,
            },
            peers: Arc::new(RwLock::new(HashMap::new())),
            message_state: Arc::new(RwLock::new(MessageState::new())),
        })
    }

    async fn handle_protocol_message(&mut self, msg: &WireMessage) -> Result<(), P2PError> {
        // Get message state first
        let mut message_state = self.message_state.write().await;
        message_state.validate_and_update_id(msg.id)
            .map_err(|e| P2PError::Protocol(e.to_string()))?;
        drop(message_state); // Release the lock

        match msg.receiver {
            Some(receiver_id) => {
                if receiver_id == self.local_session.party_id {
                    println!("Processing P2P message from party {}", msg.sender);
                }
            }
            None => {
                if msg.sender != self.local_session.party_id {
                    println!("Processing broadcast message from party {}", msg.sender);
                }
            }
        }

        Ok(())
    }

    async fn handle_session_message(&mut self, peer: PeerId, msg: SessionMessage) -> Result<(), P2PError> {
        match msg {
            SessionMessage::Register { session } => {
                self.peers.write().await.insert(peer, session.clone());
                println!("Registered peer {} with session {:?}", peer, session);
            }
            SessionMessage::Unregister { session } => {
                let should_disconnect = {
                    let mut peers = self.peers.write().await;
                    if let Some(stored_session) = peers.remove(&peer) {
                        stored_session == session
                    } else {
                        false
                    }
                };

                if should_disconnect {
                    self.swarm.disconnect_peer_id(peer)
                        .map_err(|e| P2PError::Swarm(format!("{:?}",e)))?;
                    println!("Unregistered peer {} with session {:?}", peer, session);
                }
            }
        }
        Ok(())
    }

    /// Handles incoming events from the swarm
    pub async fn handle_event(&mut self, event: SwarmEvent<CggmpBehaviourEvent>) -> Result<(), P2PError> {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("Connected to peer: {}", peer_id);
                // Send session registration
                let reg_msg = P2PMessage::Session(SessionMessage::Register {
                    session: self.local_session.clone(),
                });
                self.send_message(peer_id, reg_msg).await?;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                if let Some(session) = self.peers.write().await.remove(&peer_id) {
                    println!("Peer disconnected: {} (Party {})", peer_id, session.party_id);
                }
            }
            SwarmEvent::Behaviour(CggmpBehaviourEvent::RequestResponse(event)) => {
                match event {
                    RequestResponseEvent::Message {
                        peer,
                        message: RequestMessage::Request {
                            request,
                            channel, ..
                        }, ..
                    } => {
                        // Handle the message first
                        match request {
                            P2PMessage::Protocol(wire_msg) => {
                                // Handle protocol message
                                self.handle_protocol_message(&wire_msg).await?;
                            }
                            P2PMessage::Session(session_msg) => {
                                // Handle session message
                                self.handle_session_message(peer, session_msg).await?;
                            }
                        }

                        // Send empty response
                        self.swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, ())
                            .map_err(|_| P2PError::Protocol("Failed to send response".into()))?;
                    }
                    RequestResponseEvent::OutboundFailure { peer, request_id, error, .. } => {
                        println!("Outbound failure to {} for request {}: {:?}", peer, request_id, error);
                    }
                    RequestResponseEvent::InboundFailure { peer, error, .. } => {
                        println!("Inbound failure from {}: {:?}", peer, error);
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(CggmpBehaviourEvent::Kademlia(event)) => {
                // Handle Kademlia events with updated event types
                match event {
                    KademliaEvent::RoutingUpdated { peer, is_new_peer, .. } => {
                        println!("Kademlia routing updated for peer: {} (new: {})", peer, is_new_peer);
                    }
                    KademliaEvent::OutboundQueryProgressed {
                        id: _id,
                        result,
                        stats: _stats,
                        step: _step,
                        ..
                    } => {
                        match result {
                            QueryResult::GetClosestPeers(Ok(peers)) => {
                                println!("Found closest peers: {:?}", peers);
                            }
                            QueryResult::GetProviders(Ok(providers)) => {
                                println!("Found providers: {:?}", providers);
                            }
                            QueryResult::GetRecord(Ok(records)) => {
                                println!("Found records: {:?}", records);
                            }
                            QueryResult::PutRecord(Ok(_)) => {
                                println!("Successfully put record");
                            }
                            QueryResult::StartProviding(Ok(_)) => {
                                println!("Successfully started providing");
                            }
                            err => {
                                println!("Kademlia query error: {:?}", err);
                            }
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(CggmpBehaviourEvent::Identify(event)) => {
                // Handle Identify events
                match event {
                    identify::Event::Received { peer_id, info, .. } => {
                        println!("Received identify info from {}: {:?}", peer_id, info);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Runs the P2P node's event loop
    pub async fn run(&mut self) -> Result<(), P2PError> {
        loop {
            tokio::select! {
            event = self.swarm.select_next_some() => {
                self.handle_event(event).await?;
            }
        }
        }
    }

    /// Sends a message to a specific peer
    pub async fn send_message(&mut self, peer_id: PeerId, msg: P2PMessage) -> Result<(), P2PError> {
        self.swarm.behaviour_mut().request_response.send_request(
            &peer_id,
            msg,
        );
        Ok(())
    }

    /// Broadcasts a message to all connected peers
    pub async fn broadcast_message(&mut self, msg: P2PMessage) -> Result<(), P2PError> {
        // First, collect the peers we need to send to
        let peers_to_send: Vec<(PeerId, PartySession)> = {
            let peers = self.peers.read().await;
            peers.iter()
                .filter(|(_, session)| session.session_id == self.local_session.session_id)
                .map(|(peer_id, session)| (*peer_id, session.clone()))
                .collect()
        };

        // Then send the message to each peer
        for (peer_id, _) in peers_to_send {
            self.swarm.behaviour_mut().request_response.send_request(
                &peer_id,
                msg.clone(),
            );
        }

        Ok(())
    }

    /// Gets the list of connected peers
    pub async fn get_connected_peers(&self) -> Vec<(PeerId, PartySession)> {
        self.peers.read().await
            .iter()
            .map(|(peer_id, session)| (*peer_id, session.clone()))
            .collect()
    }
}

impl Drop for P2PNode {
    fn drop(&mut self) {
        // Attempt to gracefully disconnect from all peers
        let peers: Vec<_> = self.peers.try_read()
            .map(|peers| peers.keys().cloned().collect())
            .unwrap_or_default();

        for peer in peers {
            let _ = self.swarm.disconnect_peer_id(peer);
        }
    }
}

#[async_trait]
impl RequestResponseCodec for CggmpCodec {
    type Protocol = String;
    type Request = P2PMessage;
    type Response = ();

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        Ok(())
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let buf = bincode::serialize(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        io.write_all(&buf).await?;
        io.flush().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        _res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.flush().await?;
        Ok(())
    }
}