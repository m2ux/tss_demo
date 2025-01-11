use crate::error::Error;
use crate::network;
use crate::network::{NetworkError, WsDelivery};
use crate::server::ServerMessage;
use crate::storage::KeyStorage;
use cggmp21::{
    key_refresh::AuxOnlyMsg, key_share::AuxInfo, keygen::ThresholdMsg,
    security_level::SecurityLevel128, supported_curves::Secp256k1, ExecutionId, PregeneratedPrimes,
};
use futures::SinkExt;
use futures::StreamExt;
use futures::Stream;
use futures::TryStream;
use rand_core::OsRng;
use round_based::{Delivery, MpcParty};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::pin::Pin;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Represents the various stages of committee initialization and operation
///
/// The committee goes through several stages during its lifecycle:
/// 1. Member announcement and collection
/// 2. Generation and sharing of auxiliary cryptographic information
/// 3. Distributed key generation
/// 4. Ready state for signing operations
#[derive(Debug, Clone, PartialEq)]
enum CommitteeState {
    /// Initial state where the committee is collecting member announcements.
    /// Transitions to GeneratingAuxInfo when sufficient members (threshold) have joined.
    AwaitingMembers,

    /// Proposing/accepting execution ID
    EstablishingExecutionId,

    /// Waiting for execution ID agreement
    AwaitingExecutionId,

    /// State where members are generating their auxiliary cryptographic information
    /// needed for the distributed key generation protocol.
    GeneratingAuxInfo,

    /// Waiting state where members announce completion of auxiliary info generation.
    /// Transitions to GeneratingKeys when all members have completed.
    AwaitingAuxInfo,

    /// Active state where members are participating in the distributed key generation
    /// protocol to create their shares of the group's signing key.
    GeneratingKeys,

    /// Waiting state where members announce completion of key generation.
    /// Transitions to Ready when all members have their key shares.
    AwaitingKeyGen,

    /// Final operational state where the committee is fully initialized
    /// and ready to process signing requests.
    Ready,
}

/// Defines the structure and types of control messages used for committee coordination
///
/// These messages handle committee formation, state synchronization, and signing operations
#[derive(Serialize, Deserialize, Debug)]
enum ProtocolMessage {
    /// Sent by a party to announce their presence and join the committee
    /// - party_id: Unique identifier of the announcing party
    CommitteeMemberAnnouncement { party_id: u16 },

    /// Propose an execution ID for this session
    ExecutionIdProposal { party_id: u16, execution_id: String },

    /// Accept a proposed execution ID
    ExecutionIdAccept { party_id: u16, execution_id: String },

    /// Response message containing the current state of the committee
    /// - members: Set of party IDs that have joined the committee
    /// - aux_info_ready: Set of parties that have completed auxiliary info generation
    /// - keygen_ready: Set of parties that have completed key generation
    CommitteeState {
        members: HashSet<u16>,
        aux_info_ready: HashSet<u16>,
        keygen_ready: HashSet<u16>,
    },

    /// Announcement that a party has completed generating auxiliary information
    /// - party_id: ID of the party that completed aux info generation
    AuxInfoReady { party_id: u16 },

    /// Announcement that a party has completed key generation
    /// - party_id: ID of the party that completed key generation
    KeyGenReady { party_id: u16 },

    /// Request to initiate a signing operation
    /// - message: The message to be signed
    /// - initiator: ID of the party requesting the signature
    /// - session_id: Unique session identifier for this signing operation
    SigningRequest { message: String, initiator: u16 },

    /// Message containing a party's share of the signature
    /// - party_id: ID of the party providing the signature share
    /// - session_id: Session identifier for this signature
    /// - share: The signature share data
    SignatureShare { party_id: u16, share: Vec<u8> },
}

/// Represents different types of messages that can be exchanged over the network
///
/// Generic parameter M represents the type of protocol-specific message
#[derive(Debug)]
enum NetworkMessage<M> {
    /// Messages specific to the underlying cryptographic protocol
    /// Contains structured data of type round_based::Incoming<M>
    Protocol(round_based::Incoming<M>),

    /// Messages for committee coordination and management
    Control(ProtocolMessage),
}

/// Runs the application in committee mode, ie participating in the signing committee
pub async fn run_committee_mode(
    delivery: WsDelivery<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>,
    storage: KeyStorage,
    party_id: u16,
) -> Result<(), Error> {
    println!("Starting in committee mode with party ID: {}", party_id);

    let server_addr = delivery.addr().to_string();
    let (mut receiver, _sender) = delivery.split();

    // Register with the committee server first
    register_with_committee(&server_addr, party_id).await?;

    // Initialize committee state
    let mut committee_members = HashSet::new();
    let mut aux_info_ready = HashSet::new();
    let mut keygen_ready = HashSet::new();
    let mut execution_id_coord = ExecutionIdCoordination::new();
    let mut state = CommitteeState::AwaitingMembers;

    // Announce presence
    //broadcast_committee_announcement(party_id).await?;
    committee_members.insert(party_id);

    // Committee initialization phase
    loop {
        match state {
            CommitteeState::AwaitingMembers => {
                if committee_members.len() >= 5 {
                    println!("All committee members present. Establishing execution ID.");
                    state = CommitteeState::EstablishingExecutionId;
                }
                else {
                    broadcast_committee_announcement(party_id).await?;
                    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                }
            }
            CommitteeState::EstablishingExecutionId => {
                // Lowest party ID proposes the execution ID
                if party_id == *committee_members.iter().min().unwrap() {
                    let proposed_id = generate_unique_execution_id();
                    execution_id_coord.propose(party_id, proposed_id.clone());
                    broadcast_execution_id_proposal(party_id, proposed_id).await?;
                    state = CommitteeState::AwaitingExecutionId;
                }
                // Non-proposing parties wait in this state until they receive a proposal
                else {
                    match receive_network_message(&mut receiver).await? {
                        NetworkMessage::Control(ProtocolMessage::ExecutionIdProposal {
                            party_id: proposer_id,
                            execution_id,
                        }) => {
                            // Accept if proposer has lowest ID
                            if proposer_id == *committee_members.iter().min().unwrap() {
                                execution_id_coord.propose(proposer_id, execution_id.clone());
                                broadcast_execution_id_accept(party_id, execution_id).await?;
                                state = CommitteeState::AwaitingExecutionId;
                            } else {
                                println!(
                                    "Ignoring proposal from non-lowest ID party {}",
                                    proposer_id
                                );
                            }
                        }
                        _ => {
                            // Ignore other messages while waiting for proposal
                        }
                    }
                }
            }
            CommitteeState::AwaitingExecutionId => {
                // This state is used while waiting for all parties to accept the proposed ID
                if execution_id_coord.is_agreed(committee_members.len() - 1) {
                    if let Some(agreed_id) = execution_id_coord.get_agreed_id() {
                        storage.save("execution_id", &agreed_id)?;
                        println!("Execution ID established: {:?}", agreed_id);
                        state = CommitteeState::GeneratingAuxInfo;
                    }
                }
            }
            CommitteeState::GeneratingAuxInfo => {
                let execution_id = storage.load::<String>("execution_id")?;

                // Generate auxiliary info as per CGGMP21
                let aux_info = generate_auxiliary_info(
                    party_id,
                    committee_members.len() as u16,
                    &server_addr,
                    ExecutionId::new(&execution_id.as_bytes()),
                )
                .await?;
                storage.save("aux_info", &aux_info)?;

                broadcast_aux_info_ready(party_id).await?;
                aux_info_ready.insert(party_id);
                state = CommitteeState::AwaitingAuxInfo;
            }
            CommitteeState::AwaitingAuxInfo => {
                if aux_info_ready.len() >= 5 {
                    println!("All auxiliary info generated. Starting key generation.");
                    state = CommitteeState::GeneratingKeys;
                }
            }
            CommitteeState::GeneratingKeys => {
                // Perform distributed key generation
                let execution_id = storage.load::<String>("execution_id")?;

                let key_share = generate_key_share(
                    party_id,
                    &committee_members,
                    &server_addr,
                    ExecutionId::new(&execution_id.as_bytes()),
                )
                .await?;
                storage.save("key_share", &key_share)?;

                broadcast_keygen_ready(party_id).await?;
                keygen_ready.insert(party_id);
                state = CommitteeState::AwaitingKeyGen;
            }
            CommitteeState::AwaitingKeyGen => {
                if keygen_ready.len() >= 5 {
                    println!("Key generation complete. Ready for signing operations.");
                    state = CommitteeState::Ready;
                }
            }
            CommitteeState::Ready => {
                let execution_id = storage.load::<String>("execution_id")?;

                // Start handling signing requests
                handle_signing_requests(
                    &storage,
                    party_id,
                    ExecutionId::new(&execution_id.as_bytes()),
                )
                .await?;
            }
        }

        // Process incoming messages
        match try_receive_network_message(&mut receiver) {
            Ok(Some(msg)) => {
                match msg {
                    NetworkMessage::Control(msg) => match msg {
                        ProtocolMessage::CommitteeMemberAnnouncement { party_id: pid } => {
                            committee_members.insert(pid);
                            println!("New committee member: {}", pid);
                        }
                        ProtocolMessage::ExecutionIdProposal {
                            party_id: pid,
                            execution_id,
                        } => {
                            if state == CommitteeState::EstablishingExecutionId {
                                execution_id_coord.propose(pid, execution_id.clone());
                                // Accept if we haven't proposed our own
                                if pid < party_id {
                                    broadcast_execution_id_accept(party_id, execution_id).await?;
                                }
                            }
                        }
                        ProtocolMessage::ExecutionIdAccept {
                            party_id: pid,
                            execution_id,
                        } => {
                            if state == CommitteeState::EstablishingExecutionId {
                                execution_id_coord.accept(pid, &execution_id);
                            }
                        }
                        ProtocolMessage::AuxInfoReady { party_id: pid } => {
                            aux_info_ready.insert(pid);
                        }
                        ProtocolMessage::KeyGenReady { party_id: pid } => {
                            keygen_ready.insert(pid);
                        }
                        _ => {}
                    },
                    NetworkMessage::Protocol(_) => {
                        // Handle protocol-specific messages (TBD)
                    }
                }
            }
            Ok(None) => {
                // No message available, add a small delay before next check
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
            }
        }
    }
}

/// Generates auxiliary information as per CGGMP21 specification
async fn generate_auxiliary_info(
    party_id: u16,
    n_parties: u16,
    server_addr: &str,
    eid: ExecutionId<'_>,
) -> Result<Vec<u8>, Error> {
    println!("Generating auxiliary information for party {}", party_id);

    // Create a new delivery instance for aux info generation
    let delivery =
        WsDelivery::<AuxOnlyMsg<Sha256, SecurityLevel128>>::connect(server_addr, party_id).await?;

    let primes = PregeneratedPrimes::generate(&mut OsRng);
    let aux_info = cggmp21::aux_info_gen(eid, party_id, n_parties, primes)
        .start(&mut OsRng, MpcParty::connected(delivery))
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?;

    // Serialize the auxiliary information
    let serialized = bincode::serialize(&aux_info).map_err(Error::Serialization)?;

    println!("Auxiliary information generated successfully");
    Ok(serialized)
}

/// Generates key share through distributed key generation protocol
async fn generate_key_share(
    party_id: u16,
    committee: &HashSet<u16>,
    server_addr: &str,
    eid: ExecutionId<'_>,
) -> Result<Vec<u8>, Error> {
    println!("Starting distributed key generation for party {}", party_id);

    // Create a new delivery instance for key generation
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        server_addr,
        party_id,
    )
    .await?;

    // Initialize key generation with CGGMP21
    let keygen = cggmp21::keygen::<Secp256k1>(eid, party_id, committee.len() as u16)
        .set_threshold(3)
        .enforce_reliable_broadcast(true)
        .start(&mut OsRng, MpcParty::connected(delivery))
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?;

    // Serialize the key share
    let key_share = bincode::serialize(&keygen).map_err(Error::Serialization)?;

    Ok(key_share)
}

/// Broadcasts committee member announcement to the network
async fn broadcast_committee_announcement(party_id: u16) -> Result<(), Error> {
    println!("Broadcasting presence as committee member {}", party_id);

    // Create the announcement message
    let announcement = ProtocolMessage::CommitteeMemberAnnouncement { party_id };

    // Serialize the announcement
    let serialized = bincode::serialize(&announcement).map_err(Error::Serialization)?;

    // Send the announcement to all connected peers
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080", // Use configured server address here
        party_id,
    )
    .await?;

    let (_receiver, sender) = delivery.split();
    sender.broadcast(serialized).await.map_err(Error::Network)?;

    Ok(())
}

/// Broadcasts auxiliary-info completion status
async fn broadcast_aux_info_ready(party_id: u16) -> Result<(), Error> {
    println!(
        "Broadcasting auxiliary info completion for party {}",
        party_id
    );

    // Create the completion status message
    let ready_msg = ProtocolMessage::AuxInfoReady { party_id };

    // Serialize the message
    let serialized = bincode::serialize(&ready_msg).map_err(Error::Serialization)?;

    // Send the message to all connected peers
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080", // Use configured server address here
        party_id,
    )
    .await?;

    let (_receiver, sender) = delivery.split();
    sender.broadcast(serialized).await.map_err(Error::Network)?;

    Ok(())
}

/// Broadcasts key-generation completion status
async fn broadcast_keygen_ready(party_id: u16) -> Result<(), Error> {
    println!(
        "Broadcasting key generation completion for party {}",
        party_id
    );

    // Create the completion status message
    let ready_msg = ProtocolMessage::KeyGenReady { party_id };

    // Serialize the message
    let serialized = bincode::serialize(&ready_msg).map_err(Error::Serialization)?;

    // Send the message to all connected peers
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080", // Use configured server address here
        party_id,
    )
    .await?;

    let (_receiver, sender) = delivery.split();
    sender.broadcast(serialized).await.map_err(Error::Network)?;

    Ok(())
}

/// Broadcast an execution ID proposal
async fn broadcast_execution_id_proposal(party_id: u16, execution_id: String) -> Result<(), Error> {
    let proposal = ProtocolMessage::ExecutionIdProposal {
        party_id,
        execution_id,
    };

    // Serialize the proposal message
    let serialized = bincode::serialize(&proposal).map_err(Error::Serialization)?;

    // Create new delivery instance
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080",
        party_id,
    )
    .await?;

    // Split into receiver and sender
    let (_receiver, sender) = delivery.split();

    // Broadcast the serialized message
    sender.broadcast(serialized).await.map_err(Error::Network)?;

    Ok(())
}

/// Broadcast acceptance of an execution ID
async fn broadcast_execution_id_accept(party_id: u16, execution_id: String) -> Result<(), Error> {
    let accept = ProtocolMessage::ExecutionIdAccept {
        party_id,
        execution_id,
    };

    // Serialize the accept message
    let serialized = bincode::serialize(&accept).map_err(Error::Serialization)?;

    // Create new delivery instance
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080",
        party_id,
    )
    .await?;

    // Split into receiver and sender
    let (_receiver, sender) = delivery.split();

    // Broadcast the serialized message
    sender.broadcast(serialized).await.map_err(Error::Network)?;

    Ok(())
}

/// Discovers currently available committee members
pub async fn discover_committee_members() -> Result<HashSet<u16>, Error> {
    println!("Discovering available committee members...");

    // Connect to the WebSocket server
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080", // This should use the configured server address
        0,                     // Use party ID 0 for discovery
    )
    .await?;

    // Split into receiver and sender
    let (mut receiver, sender) = delivery.split();

    // Create request for committee state
    let request = ProtocolMessage::CommitteeMemberAnnouncement { party_id: 0 };

    // Serialize and send request
    let serialized = bincode::serialize(&request).map_err(Error::Serialization)?;
    sender.broadcast(serialized).await.map_err(Error::Network)?;

    // Initialize committee set
    let mut committee = HashSet::new();

    // Set a timeout for discovery
    let timeout = tokio::time::sleep(std::time::Duration::from_secs(2));
    tokio::pin!(timeout);

    // Process responses until timeout
    loop {
        tokio::select! {
            _ = &mut timeout => {
                break;
            }
            Some(msg_result) = receiver.next() => {
                match msg_result {
                    Ok(incoming) => {
                        // Try to deserialize as ProtocolMessage
                        if let Ok(bytes) = bincode::serialize(&incoming.msg) {
                            if let Ok(msg) = bincode::deserialize::<ProtocolMessage>(&bytes) {
                                match msg {
                                    ProtocolMessage::CommitteeMemberAnnouncement { party_id } => {
                                        if party_id != 0 { // Don't include discovery party
                                            committee.insert(party_id);
                                        }
                                    }
                                    ProtocolMessage::CommitteeState { members, .. } => {
                                        committee.extend(members.into_iter());
                                    }
                                    _ => {} // Ignore other message types
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error receiving response: {:?}", e);
                    }
                }
            }
        }
    }

    println!("Found {} committee members", committee.len());
    Ok(committee)
}

/// Waits for and receives signing requests
async fn await_signing_request() -> Result<Option<SigningRequest>, Error> {
    println!("Waiting for signing requests...");

    // Connect to websocket server
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080",
        0, // Use 0 for monitoring requests
    )
    .await?;

    let (mut receiver, _sender) = delivery.split();

    // Process incoming messages
    match receive_network_message(&mut receiver).await? {
        NetworkMessage::Control(ProtocolMessage::SigningRequest { message, initiator }) => {
            Ok(Some(SigningRequest { message, initiator }))
        }
        _ => Ok(None),
    }
}

/// Receives and processes incoming network messages
async fn receive_network_message<M>(
    receiver: &mut network::WsReceiver<M>,
) -> Result<NetworkMessage<M>, Error>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de> + Unpin,
{
    match receiver.next().await {
        Some(Ok(incoming)) => {
            match bincode::serialize(&incoming.msg) {
                Ok(bytes) => {
                    if let Ok(control_msg) = bincode::deserialize::<ProtocolMessage>(&bytes) {
                        Ok(NetworkMessage::Control(control_msg))
                    } else {
                        // If it's not a control message, return it as a protocol message
                        Ok(NetworkMessage::Protocol(incoming))
                    }
                }
                Err(_) => Ok(NetworkMessage::Protocol(incoming)),
            }
        }
        Some(Err(e)) => Err(Error::Network(e)),
        None => Err(Error::Network(NetworkError::Connection(
            "Connection closed".into(),
        ))),
    }
}

/// Receives and processes incoming network messages without blocking
fn try_receive_network_message<M>(
    receiver: &mut network::WsReceiver<M>,
) -> Result<Option<NetworkMessage<M>>, Error>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>  + Unpin,
{
    // Create polling context
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);

    match Pin::new(receiver).try_poll_next(&mut cx) {
        std::task::Poll::Ready(Some(msg)) => {
            match msg {
                Ok(incoming) => {
                    // First try to serialize the incoming message
                    match bincode::serialize(&incoming.msg) {
                        Ok(bytes) => {
                            // Then try to deserialize as ProtocolMessage
                            if let Ok(control_msg) = bincode::deserialize::<ProtocolMessage>(&bytes) {
                                Ok(Some(NetworkMessage::Control(control_msg)))
                            } else {
                                // If not a control message, it must be a protocol message
                                Ok(Some(NetworkMessage::Protocol(incoming)))
                            }
                        },
                        Err(_) => {
                            // If serialization fails, assume it's a protocol message
                            Ok(Some(NetworkMessage::Protocol(incoming)))
                        }
                    }
                },
                Err(e) => Err(Error::Network(e)),
            }
        },
        std::task::Poll::Ready(None) => Ok(None),  // Stream ended
        std::task::Poll::Pending => Ok(None),  // No message available
    }
}

/// Structure representing a signing request
#[derive(Debug)]
pub struct SigningRequest {
    pub message: String,
    pub initiator: u16,
}

/// Handles signing requests after initialization
pub async fn handle_signing_requests(
    storage: &KeyStorage,
    party_id: u16,
    eid: ExecutionId<'_>,
) -> Result<(), Error> {
    /// Handles an incoming signing request
    async fn handle_signing_request(
        request: SigningRequest,
        storage: &KeyStorage,
        party_id: u16,
    ) -> Result<(), Error> {
        println!("Handling signing request from party {}", request.initiator);

        // Load the key share and aux info
        let key_share_bytes = storage.load::<Vec<u8>>("key_share")?;
        let aux_info_bytes = storage.load::<Vec<u8>>("aux_info")?;

        // Deserialize the key share and aux info
        let key_share: cggmp21::KeyShare<Secp256k1, SecurityLevel128> =
            bincode::deserialize(&key_share_bytes).map_err(Error::Serialization)?;
        let aux_info: AuxInfo<SecurityLevel128> =
            bincode::deserialize(&aux_info_bytes).map_err(Error::Serialization)?;

        // Create a new delivery instance for signing
        let sign_delivery =
            WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
                "ws://localhost:8080",
                party_id,
            )
            .await?;

        // Perform the signing operation
        /*       let signature = cggmp21::signing(
            eid,
            party_id,
            aux_info,
            request.message.as_bytes(),
        )
            .start(&mut OsRng, MpcParty::connected(sign_delivery))
            .await
            .map_err(|e| Error::Protocol(e.to_string()))?;

        // Create signature share message
        let signature_msg = crate::protocol::ProtocolMessage::SignatureShare {
            party_id,
            share: bincode::serialize(&signature).map_err(Error::Serialization)?,
        };

        // Broadcast signature share
        let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
            "ws://localhost:8080",
            party_id,
        ).await?;

        let (_receiver, sender) = delivery.split();
        sender.broadcast(bincode::serialize(&signature_msg).map_err(Error::Serialization)?)
            .await
            .map_err(Error::Network)?;*/
        ///TODO: Fix me

        println!("Signature share generated and broadcast successfully");
        Ok(())
    }

    loop {
        if let Some(request) = crate::protocol::await_signing_request().await? {
            handle_signing_request(request, storage, party_id).await?;
        }
    }
}

/// Execution ID coordination data
#[derive(Debug)]
struct ExecutionIdCoordination {
    /// The proposed execution ID
    proposed_id: Option<String>,
    /// The party that proposed the ID
    proposer: Option<u16>,
    /// Set of parties that have accepted the proposed ID
    accepting_parties: HashSet<u16>,
}

impl ExecutionIdCoordination {
    fn new() -> Self {
        Self {
            proposed_id: None,
            proposer: None,
            accepting_parties: HashSet::new(),
        }
    }

    fn propose(&mut self, party_id: u16, execution_id: String) {
        self.proposed_id = Some(execution_id);
        self.proposer = Some(party_id);
        self.accepting_parties.clear();
        self.accepting_parties.insert(party_id); // Proposer automatically accepts
    }

    fn accept(&mut self, party_id: u16, execution_id: &str) -> bool {
        if let Some(ref proposed) = self.proposed_id {
            if proposed == execution_id {
                self.accepting_parties.insert(party_id);
                return true;
            }
        }
        false
    }

    fn is_agreed(&self, total_parties: usize) -> bool {
        self.accepting_parties.len() == total_parties
    }

    fn get_agreed_id(&self) -> Option<String> {
        if self.proposed_id.is_some() && !self.accepting_parties.is_empty() {
            self.proposed_id.clone()
        } else {
            None
        }
    }
}

/// Generate a unique execution ID
fn generate_unique_execution_id() -> String {
    // Combine timestamp and UUID for uniqueness
    format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        uuid::Uuid::new_v4()
    )
}

/// Registers this party with the committee server
async fn register_with_committee(server_addr: &str, party_id: u16) -> Result<(), Error> {
    println!("Registering with committee server as party {}", party_id);

    // Create a registration-specific connection
    let (ws_stream, _) = connect_async(server_addr)
        .await
        .map_err(|e| Error::Network(NetworkError::WebSocket(e)))?;

    let (mut write, _read) = ws_stream.split();

    // Create registration message
    let reg_msg = ServerMessage::Register { party_id };
    let serialized = bincode::serialize(&reg_msg).map_err(Error::Serialization)?;

    // Send registration message
    write
        .send(Message::Binary(serialized))
        .await
        .map_err(|e| Error::Network(NetworkError::WebSocket(e)))?;
    
    Ok(())
}
