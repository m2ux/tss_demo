//! Protocol implementation for distributed threshold signing operations.
//!
//! This module implements a distributed committee-based protocol for secure multiparty computation,
//! specifically implementing the CGGMP21 threshold signature scheme. It handles committee formation,
//! key generation, and signing-readiness coordination among multiple parties.
//!
//! # Protocol Flow
//! 1. Committee Formation
//!    - Parties announce themselves
//!    - Committee forms when sufficient members join
//!
//! 2. Execution ID Establishment
//!    - Lowest-ID party proposes execution ID
//!    - Other parties accept or reject
//!    - Protocol proceeds when all accept
//!
//! 3. Key Generation
//!    - Parties generate auxiliary information
//!    - Perform distributed key generation
//!    - Create individual key shares
//!
//! 4. Operational State
//!    - Committee becomes ready for signing operations
//!    - Handles signing requests in Ready state
//! 
//!  Current Weaknesses:
//! 
//! - No validation of party identities beyond party IDs
//! - No timeout handling in some state transitions could lead to deadlocks
//! - The ExecutionIdCoordination doesn't validate uniqueness of execution IDs
use crate::error::Error;
use crate::network::{Receiver, Sender};
use crate::p2p_delivery::P2PDelivery;
use crate::p2p_node::P2PNode;
use crate::storage::KeyStorage;
use crate::{network, signing};
use cggmp21::key_share::AuxInfo;
use cggmp21::{
    key_refresh::AuxOnlyMsg, keygen::ThresholdMsg, security_level::SecurityLevel128,
    supported_curves::Secp256k1, ExecutionId, PregeneratedPrimes,
};
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
use tokio::time::Instant;
use crate::protocol::ProtocolError;

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

/// Control messages used for committee coordination and state management
///
/// These messages handle:
/// - Committee formation
/// - State synchronization
/// - Execution ID coordination
/// - Key generation status
/// - Signing readiness
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

    /// Indicate that the protocol is ready to sign
    ReadyToSign,
}

/// Session types for different committee operations
///
/// Defines distinct session contexts for control messages,
/// protocol messages, and signing operations
#[derive(Serialize, Debug, Clone)]
#[serde(into = "u16", from = "u16")]
pub enum CommitteeSession {
    Control,
    Protocol,
    SigningControl,
    SigningProtocol,
}

impl From<CommitteeSession> for u16 {
    fn from(id: CommitteeSession) -> u16 {
        id as u16
    }
}

/// Committee protocol coordinator managing committee lifecycle and operations
///
/// Handles:
/// - Committee formation and management
/// - Key generation coordination
/// - State transitions
/// - Signing operations
pub struct Protocol {
    /// Shared protocol environment containing committee state
    context: Arc<RwLock<Context>>,
    /// Storage for cryptographic keys and protocol data
    storage: KeyStorage,
    /// Signing protocol implementation
    signing: signing::Protocol,
    p2p_node: Arc<P2PNode>,
    //tss_protocol: TssProtocol,
    party_id: u16,
}

/// Committee protocol context maintaining committee state and coordination data
#[derive(Debug)]
struct Context {
    /// Set of current committee member IDs
    pub committee_members: HashSet<u16>,
    /// Set of parties that have completed auxiliary info generation
    pub aux_info_ready: HashSet<u16>,
    /// Set of parties that have completed key generation
    pub keygen_ready: HashSet<u16>,
    /// Set of parties ready for signing operations
    pub signing_ready: HashSet<u16>,
    /// Execution ID coordination state
    pub execution_id_coord: ExecutionIdCoordination,
    /// Deadline (general purpose)
    pub deadline: Option<Instant>,
}

/// Protocol environment maintaining committee state and coordination data
impl Context {
    /// Creates a new ProtocolEnv instance with empty state
    pub fn new() -> Self {
        Self {
            committee_members: HashSet::new(),
            aux_info_ready: HashSet::new(),
            keygen_ready: HashSet::new(),
            signing_ready: HashSet::new(),
            execution_id_coord: ExecutionIdCoordination::new(),
            deadline: None,
        }
    }

    /// Resets the protocol environment to its initial empty state
    pub fn reset(&mut self) {
        self.committee_members.clear();
        self.aux_info_ready.clear();
        self.keygen_ready.clear();
        self.signing_ready.clear();
        self.execution_id_coord = ExecutionIdCoordination::new();
        self.deadline = None;
    }

    /// Checks if the deadline has passed.
    ///
    /// # Returns
    /// `true` if the deadline has elapsed, `false` otherwise
    fn is_deadline_elapsed(&self) -> bool {
        self.deadline
            .map(|deadline| Instant::now() > deadline)
            .unwrap_or(false)
    }

    /// Sets a deadline
    ///
    /// The deadline is set to the current time plus the timeout duration.
    fn set_deadline(&mut self, timeout: Duration) {
        self.deadline = Some(Instant::now() + timeout);
    }
}

impl Protocol {
    /// Creates a new Protocol instance for the specified party
    ///
    /// # Arguments
    /// * `party_id` - Unique identifier for this protocol participant
    ///
    /// # Returns
    /// * `Result<Protocol, Error>` - New protocol instance or error
    pub async fn new(party_id: u16, p2p_node: Arc<P2PNode>) -> Result<Self, Error> {
        // Initialize storage
        let storage = KeyStorage::new(
            format!("keys_{}", party_id),
            "a very secret key that should be properly secured",
        )?;

        // Initialize the signing protocol
        let signing = signing::Protocol::new(party_id, p2p_node.clone(), storage.clone()).await?;

        Ok(Self {
            context: Arc::new(RwLock::new(Context::new())),
            storage,
            signing,
            p2p_node,
            party_id,
        })
    }

    /// Starts the protocol, connecting to the specified server
    ///
    /// # Returns
    /// * `Result<(), Error>` - Success or error status
    pub async fn start(&mut self) -> Result<(), Error> {
        println!(
            "Starting in committee mode with party ID: {}",
            self.party_id
        );

        // Initialize P2P delivery for control messages
        let delivery = P2PDelivery::<ControlMessage>::connect(
            Arc::clone(&self.p2p_node),
            self.party_id,
            CommitteeSession::Control,
        )
        .await?;

        // Get sender for all outgoing messages
        let (receiver, sender) = Delivery::split(delivery);

        // Spawn message receiving task
        let message_handler = Protocol::handle_messages(Arc::clone(&self.context), receiver);
        let run_handler = self.run(sender);

        // End on termination of either handler
        tokio::select! {
            result = message_handler => result?,
            result = run_handler => result?,
        }

        Ok(())
    }

    /// Runs the committee coordination process
    ///
    /// # Arguments
    /// * `sender` - Channel for sending control messages
    /// * `server_addr` - Address of the coordination server
    ///
    /// # Returns
    /// * `Result<(), Error>` - Success or error status
    async fn run(&mut self, mut sender: Sender<ControlMessage>) -> Result<(), Error> {
        // Get the party ID
        let party_id = sender.get_party_id();

        let mut committee_state = CommitteeState::AwaitingMembers;
        println!("Broadcasting presence as committee member {}", party_id);

        // Insert the part ID
        self.context
            .write()
            .await
            .committee_members
            .insert(party_id);

        // Committee initialization phase
        loop {
            // Acquire a context lock
            let mut context = self.context.write().await;

            match committee_state {
                CommitteeState::AwaitingMembers => {
                    if context.deadline.is_none() {
                        context.set_deadline(Duration::from_secs(15));
                    }

                    if context.is_deadline_elapsed() {
                        if context.committee_members.len() >= 3 {
                            println!("All committee members present. Establishing execution ID.");
                            committee_state = CommitteeState::EstablishingExecutionId;
                            context.deadline = None;
                        } else {
                            return Err(Error::Protocol(ProtocolError::Other(format!(
                                "Insufficient parties ({}) available to form a committee!",
                                context.committee_members.len()
                            ))));
                        }
                    } else {
                        sender
                            .broadcast(ControlMessage::CommitteeMemberAnnouncement)
                            .await?;

                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }

                CommitteeState::EstablishingExecutionId => {
                    // Lowest party ID proposes the execution ID
                    if party_id == *context.committee_members.iter().min().unwrap() {
                        let proposed_id = generate_unique_execution_id();
                        context
                            .execution_id_coord
                            .propose(party_id, proposed_id.clone());

                        let execution_id = context.execution_id_coord.proposed_id.clone().unwrap();
                        println!("Proposing execution ID: {}", &execution_id);
                        sender
                            .broadcast(ControlMessage::ExecutionIdProposal { execution_id })
                            .await
                            .map_err(Error::Network)?;
                        committee_state = CommitteeState::AwaitingExecutionId;
                    }
                    // Non-proposing parties wait in this state until they receive a proposal
                    else {
                        match context.execution_id_coord.proposer {
                            Some(proposer)
                                if proposer == *context.committee_members.iter().min().unwrap() =>
                            {
                                context.execution_id_coord.approve(party_id);
                                let execution_id =
                                    context.execution_id_coord.proposed_id.clone().unwrap();
                                println!("Accepted execution ID proposal from party {}", proposer);
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
                    if context
                        .execution_id_coord
                        .is_agreed(context.committee_members.len() - 1)
                    {
                        if let Some(agreed_id) = context.execution_id_coord.get_agreed_id() {
                            self.storage.save("execution_id", &agreed_id)?;
                            println!("Execution ID established: {:?}", agreed_id);
                            committee_state = CommitteeState::GeneratingAuxInfo;
                        }
                    }
                }
                CommitteeState::GeneratingAuxInfo => {
                    let execution_id = self.storage.load::<String>("execution_id")?;

                    // Create P2P delivery instance for aux info generation
                    let delivery = P2PDelivery::<AuxOnlyMsg<Sha256, SecurityLevel128>>::connect(
                        Arc::clone(&self.p2p_node),
                        party_id,
                        CommitteeSession::Protocol,
                    ).await?;

                    // Generate auxiliary info as per CGGMP21
                    let aux_info = Protocol::generate_auxiliary_info(
                        party_id,
                        context.committee_members.len() as u16,
                        ExecutionId::new(execution_id.as_bytes()),
                        delivery,
                    )
                    .await?;
                    self.storage.save("aux_info", &aux_info)?;
                    
                    sender
                        .broadcast(ControlMessage::AuxInfoReady)
                        .await
                        .map_err(Error::Network)?;

                    context.aux_info_ready.insert(party_id);
                    committee_state = CommitteeState::AwaitingAuxInfo;
                }
                CommitteeState::AwaitingAuxInfo => {
                    if context.aux_info_ready.len() == context.committee_members.len() {
                        println!("All auxiliary info generated. Starting key generation.");
                        committee_state = CommitteeState::GeneratingKeys;
                    }
                }
                CommitteeState::GeneratingKeys => {
                    // Perform distributed key generation
                    let execution_id = self.storage.load::<String>("execution_id")?;

                    // Create P2P delivery instance
                    let delivery = P2PDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
                        Arc::clone(&self.p2p_node),
                        party_id,
                        CommitteeSession::Protocol,
                    ).await?;

                    // Generate key share
                    let incomplete_key_share = Protocol::generate_key_share(
                        party_id,
                        &context.committee_members,
                        ExecutionId::new(execution_id.as_bytes()),
                        3,
                        delivery,
                    )
                    .await?;

                    println!("Load aux info");
                    let aux_info = self.storage.load::<AuxInfo>("aux_info")?;

                    // Reconstruct the key share
                    let key_share = cggmp21::KeyShare::from_parts((incomplete_key_share, aux_info))
                        .map_err(|e| Error::Protocol(ProtocolError::InvalidShare(e.to_string())))?;

                    self.storage.save_key_share("key_share", &key_share)?;

                    sender
                        .broadcast(ControlMessage::KeyGenReady)
                        .await
                        .map_err(Error::Network)?;

                    context.keygen_ready.insert(party_id);
                    committee_state = CommitteeState::AwaitingKeyGen;
                }
                CommitteeState::AwaitingKeyGen => {
                    if context.keygen_ready.len() == context.committee_members.len() {
                        println!("Key generation complete");

                        sender
                            .broadcast(ControlMessage::ReadyToSign)
                            .await
                            .map_err(Error::Network)?;

                        context.signing_ready.insert(party_id);
                        committee_state = CommitteeState::WaitForReady;
                    }
                }
                CommitteeState::WaitForReady => {
                    if context.signing_ready.len() == context.committee_members.len() {
                        committee_state = CommitteeState::Ready;
                    }
                }
                CommitteeState::Ready => {
                    // Start the signing session
                    self.signing.start().await?;

                    // After session ends, end committee session
                    committee_state = CommitteeState::AwaitingMembers;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Handles incoming network messages and updates protocol state
    ///
    /// # Arguments
    /// * `context` - Shared protocol environment
    /// * `receiver` - Channel for receiving control messages
    ///
    /// # Returns
    /// * `Result<(), Error>` - Success or error status
    async fn handle_messages(
        context: Arc<RwLock<Context>>,
        mut receiver: Receiver<ControlMessage>,
    ) -> Result<(), Error> {
        pub async fn handle_message(
            incoming: Incoming<ControlMessage>,
            context: &Arc<RwLock<Context>>,
        ) -> Result<(), Error> {
            let mut protocol = context.write().await;

            // Extract party ID from incoming message
            let pid = incoming.sender;

            // Match the message content
            match incoming.msg {
                ControlMessage::CommitteeMemberAnnouncement => {
                    if !protocol.committee_members.contains(&pid) {
                        protocol.committee_members.insert(pid);
                        println!("New committee member: {}", pid);
                    };
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

        loop {
            match receiver.next().await {
                Some(Ok(message)) => {
                    if let Err(e) = handle_message(message, &context).await {
                        println!("Error handling received message: {}", e);
                    }
                }
                Some(Err(e)) => {
                    // Log error and implement recovery strategy
                    return Err(Error::Network(e));
                }
                None => {
                    // Handle disconnection
                    return Err(Error::Network(network::NetworkError::Connection(
                        "Channel closed".to_string(),
                    )));
                }
            }
        }
    }
    /// Generates auxiliary information as per CGGMP21 specification
    ///
    /// # Arguments
    /// * `party_id` - Unique identifier for this protocol participant
    /// * `n_parties` - Total number of participating parties
    /// * `server_addr` - Address of the coordination server
    /// * `eid` - Unique execution identifier
    ///
    /// # Returns
    /// * `Result<AuxInfo, Error>` - Generated auxiliary information or error
    async fn generate_auxiliary_info(
        party_id: u16,
        n_parties: u16,
        eid: ExecutionId<'_>,
        delivery: P2PDelivery::<AuxOnlyMsg<Sha256, SecurityLevel128>>,
    ) -> Result<AuxInfo, Error> {
        println!("Generating auxiliary information for party {}", party_id);

        let primes = PregeneratedPrimes::generate(&mut OsRng);
        let aux_info = cggmp21::aux_info_gen(eid, party_id, n_parties, primes)
            .start(&mut OsRng, MpcParty::connected(delivery))
            .await
            .map_err(|e| Error::Protocol(ProtocolError::AuxGenFailed(e.to_string())))?;

        println!("Auxiliary information generated successfully");
        Ok(aux_info)
    }

    /// Generates key share through distributed key generation protocol
    ///
    /// # Arguments
    /// * `party_id` - Unique identifier for this protocol participant
    /// * `committee` - Set of participating committee members
    /// * `server_addr` - Address of the coordination server
    /// * `eid` - Unique execution identifier
    ///
    /// # Returns
    /// * `Result<CoreKeyShare<Secp256k1>, Error>` - Generated key share or error
    async fn generate_key_share(
        party_id: u16,
        committee: &HashSet<u16>,
        eid: ExecutionId<'_>,
        threshold: u16,
        delivery: P2PDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>,
    ) -> Result<CoreKeyShare<Secp256k1>, Error> {
        println!("Starting distributed key generation for party {}", party_id);

        let keygen = cggmp21::keygen::<Secp256k1>(eid, party_id, committee.len() as u16)
            .set_threshold(threshold)
            .enforce_reliable_broadcast(true)
            .start(&mut OsRng, MpcParty::connected(delivery))
            .await
            .map_err(|e| Error::Protocol(ProtocolError::KeyGenFailed(e.to_string())))?;

        Ok(keygen)
    }
}
/// Coordinates execution ID proposal and acceptance among committee members
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
    /// Creates a new ExecutionIdCoordination instance
    fn new() -> Self {
        Self {
            proposed_id: None,
            proposer: None,
            accepting_parties: HashSet::new(),
        }
    }

    /// Records a proposed execution ID from a party
    fn consider(&mut self, party_id: u16, execution_id: String) {
        self.proposed_id = Some(execution_id);
        self.proposer = Some(party_id);
        self.accepting_parties.clear();
    }

    /// Records party approval of the current proposal
    fn approve(&mut self, party_id: u16) {
        self.accepting_parties.insert(party_id); // Proposer automatically accepts
    }

    /// Rejects the proposed execution ID
    fn reject(&mut self) {
        self.proposed_id = None;
        self.proposer = None;
        self.accepting_parties.clear();
    }

    /// Proposes a new execution ID
    fn propose(&mut self, party_id: u16, execution_id: String) {
        self.proposed_id = Some(execution_id);
        self.proposer = Some(party_id);
        self.accepting_parties.clear();
        self.accepting_parties.insert(party_id); // Proposer automatically accepts
    }

    /// Records acceptance of the proposed ID by a party
    fn accept(&mut self, party_id: u16, execution_id: &str) -> bool {
        if let Some(ref proposed) = self.proposed_id {
            if proposed == execution_id {
                self.accepting_parties.insert(party_id);
                return true;
            }
        }
        false
    }

    /// Checks if all parties have agreed on the execution ID
    fn is_agreed(&self, total_parties: usize) -> bool {
        self.accepting_parties.len() == total_parties
    }

    /// Retrieves the agreed execution ID if consensus is reached
    fn get_agreed_id(&self) -> Option<String> {
        if self.proposed_id.is_some() && !self.accepting_parties.is_empty() {
            self.proposed_id.clone()
        } else {
            None
        }
    }
}

/// Generates a unique execution ID combining timestamp and UUID
fn generate_unique_execution_id() -> String {
    // Combine timestamp and UUID for uniqueness
    format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        uuid::Uuid::new_v4()
    )
}
