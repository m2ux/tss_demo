use crate::error::Error;
use crate::network::WsDelivery;
use crate::signing::Signing;
use crate::storage::KeyStorage;
use cggmp21::key_share::AuxInfo;
use cggmp21::{key_refresh::AuxOnlyMsg, keygen::ThresholdMsg, security_level::SecurityLevel128, supported_curves::Secp256k1, ExecutionId, KeyShare, PregeneratedPrimes};
use cggmp21_keygen::key_share::CoreKeyShare;
use futures::StreamExt;
use rand_core::OsRng;
use round_based::{Delivery, Incoming, MpcParty};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

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

    /// Wait for all committee members to indicate readiness
    WaitForReady,
    /// Final operational state where the committee is fully initialized
    /// and ready to process signing requests.
    Ready,
}

/// Defines the structure and types of control messages used for committee coordination
///
/// These messages handle committee formation, state synchronization, and signing operations
#[derive(Serialize, Deserialize, Debug, Clone)]
#[repr(u8)]
pub enum ControlMessage {
    /// Sent by a party to announce their presence and join the committee
    /// - party_id: Unique identifier of the announcing party
    CommitteeMemberAnnouncement = 3,

    /// Propose an execution ID for this session
    ExecutionIdProposal { execution_id: String },

    /// Accept a proposed execution ID
    ExecutionIdAccept { execution_id: String },

    /// Response message containing the current state of the committee
    CommitteeState {
        members: HashSet<u16>,        // Set of party IDs that have joined the committee
        aux_info_ready: HashSet<u16>, // Set of parties that have completed aux info generation
        keygen_ready: HashSet<u16>,   // Set of parties that have completed key generation
    },

    /// Announcement that a party has completed generating auxiliary information
    AuxInfoReady,

    /// Announcement that a party has completed key generation
    KeyGenReady,

    /// Request to initiate a signing operation
    /// - message: The message to be signed
    SigningRequest { message: String },

    /// Message containing a party's share of the signature
    /// - share: The signature share data
    //SignatureShare { share: Vec<u8> },

    /// Indicate that the protocol is ready to sign
    ReadyToSign,
}

/// Defines the structure and types of control messages used for committee coordination
///
/// These messages handle committee formation, state synchronization, and signing operations
#[derive(Serialize, Debug, Clone)]
#[serde(into = "u16", from = "u16")]
pub enum CommitteeSession {
    Control,
    Protocol,
    SigningControl,
    Signing,
}

impl From<CommitteeSession> for u16 {
    fn from(id: CommitteeSession) -> u16 {
        id as u16
    }
}

/// Structure representing a committee and its state
#[derive(Debug)]
struct Protocol {
    pub committee_members: HashSet<u16>,
    pub aux_info_ready: HashSet<u16>,
    pub keygen_ready: HashSet<u16>,
    pub signing_ready: HashSet<u16>,
    pub execution_id_coord: ExecutionIdCoordination,
    pub signing_request: Option<SigningRequest>,
}

impl Protocol {
    fn new(party_id: u16) -> Self {
        let mut committee_members = HashSet::new();
        committee_members.insert(party_id);

        Self {
            committee_members,
            aux_info_ready: HashSet::new(),
            keygen_ready: HashSet::new(),
            signing_ready: HashSet::new(),
            execution_id_coord: ExecutionIdCoordination::new(),
            signing_request: None,
        }
    }
}

/// Runs the application in committee mode, ie participating in the signing committee
pub async fn run_committee_mode(server_addr: String, party_id: u16) -> Result<(), Error> {
    println!("Starting in committee mode with party ID: {}", party_id);

    // Initialize storage
    let storage = KeyStorage::new(
        format!("keys_{}", party_id),
        "a very secret key that should be properly secured",
    )?;

    // Initialize control message connection
    let delivery =
        WsDelivery::<ControlMessage>::connect(&server_addr, party_id, CommitteeSession::Control)
            .await?;

    // Setup a signing session
    let mut signing = Signing::new(storage.clone()).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Get sender for all outgoing messages
    let (mut receiver, mut sender) = Delivery::split(delivery);

    // Initialize protocol
    let protocol = Arc::new(RwLock::new(Protocol::new(party_id)));

    // Spawn message receiving task
    let protocol_for_receiver = Arc::clone(&protocol);
    let _receiver_handle = tokio::spawn(async move {
        loop {
            match receiver.next().await {
                Some(Ok(message)) => {
                    if let Err(e) = handle_message(message, &protocol_for_receiver).await {
                        println!("Error handling received message: {}", e);
                    }
                }
                Some(Err(e)) => println!("Error receiving message: {}", e),
                None => (),
            }
        }
    });

    let mut committee_state = CommitteeState::AwaitingMembers;
    println!("Broadcasting presence as committee member {}", party_id);

    // Committee initialization phase
    loop {
        let mut protocol = protocol.write().await;

        match committee_state {
            CommitteeState::AwaitingMembers => {
                if protocol.committee_members.len() >= 5 {
                    println!("All committee members present. Establishing execution ID.");
                    committee_state = CommitteeState::EstablishingExecutionId;
                } else {
                    sender
                        .broadcast(ControlMessage::CommitteeMemberAnnouncement)
                        .await
                        .map_err(Error::Network)?;

                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
            CommitteeState::EstablishingExecutionId => {
                // Lowest party ID proposes the execution ID
                if party_id == *protocol.committee_members.iter().min().unwrap() {
                    let proposed_id = generate_unique_execution_id();
                    protocol
                        .execution_id_coord
                        .propose(party_id, proposed_id.clone());

                    let execution_id = protocol.execution_id_coord.proposed_id.clone().unwrap();
                    println!("Proposing execution ID: {}", &execution_id);

                    sender
                        .broadcast(ControlMessage::ExecutionIdProposal { execution_id })
                        .await
                        .map_err(Error::Network)?;
                    committee_state = CommitteeState::AwaitingExecutionId;
                }
                // Non-proposing parties wait in this state until they receive a proposal
                else {
                    match protocol.execution_id_coord.proposer {
                        Some(proposer)
                            if proposer == *protocol.committee_members.iter().min().unwrap() =>
                        {
                            protocol.execution_id_coord.approve(party_id);
                            let execution_id =
                                protocol.execution_id_coord.proposed_id.clone().unwrap();
                            sender
                                .broadcast(ControlMessage::ExecutionIdAccept { execution_id })
                                .await
                                .map_err(Error::Network)?;
                            committee_state = CommitteeState::AwaitingExecutionId;
                        }
                        Some(proposer) => {
                            println!("Ignoring proposal from non-lowest ID party {}", proposer);
                        }
                        None => (),
                    }
                }
            }
            CommitteeState::AwaitingExecutionId => {
                // This state is used while waiting for all parties to accept the proposed ID
                if protocol
                    .execution_id_coord
                    .is_agreed(protocol.committee_members.len() - 1)
                {
                    if let Some(agreed_id) = protocol.execution_id_coord.get_agreed_id() {
                        storage.save("execution_id", &agreed_id)?;
                        println!("Execution ID established: {:?}", agreed_id);
                        committee_state = CommitteeState::GeneratingAuxInfo;
                    }
                }
            }
            CommitteeState::GeneratingAuxInfo => {
                let execution_id = storage.load::<String>("execution_id")?;

                // Generate auxiliary info as per CGGMP21
                let aux_info = generate_auxiliary_info(
                    party_id,
                    protocol.committee_members.len() as u16,
                    &server_addr,
                    ExecutionId::new(execution_id.as_bytes()),
                )
                .await?;
                storage.save("aux_info", &aux_info)?;

                sender
                    .broadcast(ControlMessage::AuxInfoReady)
                    .await
                    .map_err(Error::Network)?;

                protocol.aux_info_ready.insert(party_id);
                committee_state = CommitteeState::AwaitingAuxInfo;
            }
            CommitteeState::AwaitingAuxInfo => {
                if protocol.aux_info_ready.len() >= 5 {
                    println!("All auxiliary info generated. Starting key generation.");
                    committee_state = CommitteeState::GeneratingKeys;
                }
            }
            CommitteeState::GeneratingKeys => {
                // Perform distributed key generation
                let execution_id = storage.load::<String>("execution_id")?;

                let incomplete_key_share = generate_key_share(
                    party_id,
                    &protocol.committee_members,
                    &server_addr,
                    ExecutionId::new(execution_id.as_bytes()),
                )
                .await?;

                println!("Load aux info");
                let aux_info = storage.load::<AuxInfo>("aux_info")?;

                // Reconstruct the key share
                let key_share = cggmp21::KeyShare::from_parts((incomplete_key_share, aux_info))
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                
                storage.save_key_share("key_share", &key_share)?;
                
                sender
                    .broadcast(ControlMessage::KeyGenReady)
                    .await
                    .map_err(Error::Network)?;

                protocol.keygen_ready.insert(party_id);
                committee_state = CommitteeState::AwaitingKeyGen;
            }
            CommitteeState::AwaitingKeyGen => {
                if protocol.keygen_ready.len() >= 5 {
                    println!("Key generation complete");

                    sender
                        .broadcast(ControlMessage::ReadyToSign)
                        .await
                        .map_err(Error::Network)?;

                    protocol.signing_ready.insert(party_id);
                    committee_state = CommitteeState::WaitForReady;
                }
            }

            CommitteeState::WaitForReady => {
                if protocol.signing_ready.len() >= 5 {
                    committee_state = CommitteeState::Ready;
                }
            }

            CommitteeState::Ready => {
                // Start the signing session
                signing.start(party_id, &server_addr).await?;

                // After session ends, end committee session
                committee_state = CommitteeState::AwaitingMembers;
            }
        }
    }
}

/// Network message handler
async fn handle_message(
    incoming: Incoming<ControlMessage>,
    protocol: &Arc<RwLock<Protocol>>,
) -> Result<(), Error> {
    let mut protocol = protocol.write().await;

    // Extract party ID from incoming message
    let pid = incoming.sender;

    // Match the message content
    match incoming.msg {
        ControlMessage::CommitteeMemberAnnouncement => {
            if !protocol.committee_members.contains(&pid) {
                protocol.committee_members.insert(pid);
                println!("New committee member: {}", pid);
            }
        }
        ControlMessage::ExecutionIdProposal { execution_id } => {
            protocol.execution_id_coord.consider(pid, execution_id);
        }
        ControlMessage::ExecutionIdAccept { execution_id } => {
            protocol.execution_id_coord.accept(pid, &execution_id);
            println!("Party {} accepted execution ID", pid);
        }
        ControlMessage::AuxInfoReady => {
            protocol.aux_info_ready.insert(pid);
            println!("Party {} completed aux info generation", pid);
        }
        ControlMessage::KeyGenReady => {
            protocol.keygen_ready.insert(pid);
            println!("Party {} completed key generation", pid);
        }
        ControlMessage::ReadyToSign => {
            protocol.signing_ready.insert(pid);
            println!("Party {} is ready to sign", pid);
        }
        _ => {
            println!("Received unhandled message type from party {}", pid);
        }
    }

    Ok(())
}

/// Generates auxiliary information as per CGGMP21 specification
async fn generate_auxiliary_info(
    party_id: u16,
    n_parties: u16,
    server_addr: &str,
    eid: ExecutionId<'_>,
) -> Result<AuxInfo, Error> {
    println!("Generating auxiliary information for party {}", party_id);

    // Create a new delivery instance for aux info generation
    let delivery = WsDelivery::<AuxOnlyMsg<Sha256, SecurityLevel128>>::connect(
        server_addr,
        party_id,
        CommitteeSession::Protocol,
    )
    .await?;

    let primes = PregeneratedPrimes::generate(&mut OsRng);
    let aux_info = cggmp21::aux_info_gen(eid, party_id, n_parties, primes)
        .start(&mut OsRng, MpcParty::connected(delivery))
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?;

    println!("Auxiliary information generated successfully");
    Ok(aux_info)
}

/// Generates key share through distributed key generation protocol
async fn generate_key_share(
    party_id: u16,
    committee: &HashSet<u16>,
    server_addr: &str,
    eid: ExecutionId<'_>,
) -> Result<CoreKeyShare<Secp256k1>, Error> {
    println!("Starting distributed key generation for party {}", party_id);

    // Create a new delivery instance for key generation
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        server_addr,
        party_id,
        CommitteeSession::Protocol,
    )
    .await?;

    // Initialize key generation
    let keygen = cggmp21::keygen::<Secp256k1>(eid, party_id, committee.len() as u16)
        .set_threshold(3)
        .enforce_reliable_broadcast(true)
        .start(&mut OsRng, MpcParty::connected(delivery))
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?;

    Ok(keygen)
}

/// Discovers currently available committee members
pub async fn discover_committee_members() -> Result<HashSet<u16>, Error> {
    println!("Discovering available committee members...");

    // Connect to the WebSocket server
    let delivery = WsDelivery::<ControlMessage>::connect(
        "ws://localhost:8080", // This should use the configured server address
        0,
        CommitteeSession::Protocol, // Use party ID 0 for discovery
    )
    .await?;

    // Split into receiver and sender
    let (mut receiver, mut sender) = Delivery::split(delivery);

    sender
        .broadcast(ControlMessage::CommitteeMemberAnnouncement)
        .await
        .map_err(Error::Network)?;

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

                        // Extract party ID from incoming message
                        let pid = incoming.sender;

                        // Match the message content
                        match incoming.msg {
                            ControlMessage::CommitteeMemberAnnouncement => {
                                if pid != 0 { // Don't include discovery party
                                    committee.insert(pid);
                                }
                            }
                            ControlMessage::CommitteeState { members, .. } => {
                                committee.extend(members.into_iter());
                            }
                            _ => {} // Ignore other message types
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

/// Structure representing a signing request
#[derive(Debug)]
pub struct SigningRequest {
    pub message: String,
    pub initiator: u16,
}

/// Execution ID coordination data
#[derive(Debug)]
struct ExecutionIdCoordination {
    /// The proposed execution ID
    pub proposed_id: Option<String>,
    /// The party that proposed the ID
    pub proposer: Option<u16>,
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

    fn consider(&mut self, party_id: u16, execution_id: String) {
        self.proposed_id = Some(execution_id);
        self.proposer = Some(party_id);
        self.accepting_parties.clear();
    }

    fn approve(&mut self, party_id: u16) {
        self.accepting_parties.insert(party_id); // Proposer automatically accepts
    }

    fn reject(&mut self, party_id: u16, execution_id: String) {
        self.proposed_id = None;
        self.proposer = None;
        self.accepting_parties.clear();
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
