//! Signing Protocol Implementation
//!
//! This module implements a distributed signing protocol based on CGGMP21. It provides:
//! - State machine-based protocol management for robust signing coordination
//! - Multi-party signature generation with threshold security (3-of-n)
//! - P2P-based communication between parties
//! - Deterministic signer selection based on party IDs
//!
//! # Protocol Flow
//!
//! The distributed signing process follows these stages:
//! 1. **Sign Request Reception**: A party initiates a signing request with a message
//! 2. **Candidate Collection**: Available parties respond within a 5-second window
//! 3. **Candidate Set Comparison**: Parties ensure consistent views of available signers
//! 4. **Quorum Formation**: Parties agree on the signing group (lowest 3 party IDs)
//! 5. **Signature Generation**: Selected parties generate their signature shares
//! 6. **Signature Verification**: All parties verify the combined signature
//!
//! # Security Considerations
//!
//! - Uses P2P communication with libp2p for secure message transport
//! - Deterministic signer selection prevents manipulation of signing group
//! - 5-second collection window ensures timely participation
//! - Requires exact matching of candidate sets across all parties
//! - All parties must approve the quorum before signing begins
//! - Signature shares are verified for consistency
//!
//! # Examples
//!
//! Basic usage within a committee:
//!
//! ```no_run
//! use cggmp21_demo::signing::{Protocol, KeyStorage};
//! use cggmp21_demo::p2p_node::P2PNode;
//!
//! #[tokio::main]
//! async fn main() {
//!     let storage = KeyStorage::new("keys", "secure-password").unwrap();
//!     let p2p_node = Arc::new(P2PNode::connect(
//!         Some(vec!["bootstrap-addr".to_string()]),
//!         vec!["listen-addr".to_string()],
//!         "cggmp".to_string()
//!     ).await.unwrap());
//!
//!     let mut protocol = Protocol::new(1, p2p_node, storage).await.unwrap();
//!     protocol.start().await.unwrap();
//! }
//! ```
//!
//! # Message Flow
//!
//! ```text
//! ┌────────┐    ┌──────────┐    ┌─────────────────┐    ┌──────────┐
//! │ Sign   │    │ Collect  │    │ Compare Sets &  │    │ Generate │
//! │Request │───>│ Candidat.│───>│ Form Quorum     │───>│ Shares   │
//! └────────┘    └──────────┘    └─────────────────┘    └──────────┘
//!                    │                   │                    │
//!                    │                   │                    │
//!              5s Timeout          All Must Match       Verify All
//!                    │                   │                    │
//!                    v                   v                    v
//! ```
//!
//! # Implementation Details
//!
//! - Uses tokio for async runtime and concurrent operations
//! - State machine implemented using the `rust-fsm` crate
//! - P2P communication via libp2p with custom protocol identifiers
//! - Thread-safe state management using Arc<RwLock>
//! - Staggered communication delays based on party ID
//! - Automatic session cleanup on drop
//!
//! # Error Handling
//!
//! The protocol handles several categories of errors:
//! - Network communication failures (P2P disconnections, timeouts)
//! - Protocol violations (mismatched sets, invalid transitions)
//! - Signing operation failures (share generation, verification)
//! - Storage errors (key access, serialization)
//!
//! Errors are propagated through the Result type and include detailed context.
//! 
//!  Current Weaknesses:
//!  - Potential timing attacks in signature verification: The comparison isn't constant-time, 
//!    potentially leaking information about signatures
//! - Some state transitions lack proper error handling, leading to potential protocol violations
//! 
use crate::committee::CommitteeSession;
use crate::error::Error;
use crate::network;
use crate::network::{Receiver, Sender};
use crate::p2p_delivery::P2PDelivery;
use crate::p2p_node::P2PNode;
use crate::signing::fsm::Input;
use crate::storage::KeyStorage;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{ExecutionId, Signature};
use futures_util::StreamExt;
use inline_colorization::*;
use rand_core::OsRng;
use round_based::{Delivery, Incoming, MpcParty};
use rust_fsm::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use crate::protocol::ProtocolError;

state_machine! {
    /// State machine definition for the CGGMP21 signing protocol.
    ///
    /// The state machine coordinates the multi-party signing process through well-defined
    /// states and transitions. Each state represents a distinct phase of the protocol,
    /// and transitions occur in response to specific events or conditions.
    ///
    /// # States
    ///
    /// * `Idle` - Initial state, waiting for signing requests
    /// * `CollectingCandidates` - Gathering available signing parties
    /// * `ComparingCandidates` - Verifying consistent candidate sets
    /// * `CollectingApprovals` - Forming signing quorum
    /// * `Signing` - Generating signature shares
    /// * `VerifyingSignatures` - Validating combined signature
    /// * `TidyUp` - Cleanup and reset
    ///
    /// # Transitions and Events
    ///
    /// From Idle:
    /// - `Starting` -> Idle (initialization complete)
    /// - `SignRequestReceived` -> CollectingCandidates (new signing request)
    /// - `EndSigning` -> TidyUp (abort request)
    ///
    /// From CollectingCandidates:
    /// - `CandidateAvailable` -> CollectingCandidates (party announces availability)
    /// - `CollectionTimeout` -> ComparingCandidates[BroadcastCandidatesSet] (5s window elapsed)
    /// - `QuorumDeclined` -> Idle (insufficient parties)
    /// - `EndSigning` -> TidyUp (abort request)
    ///
    /// From ComparingCandidates:
    /// - `CandidateSetReceived` -> ComparingCandidates (received party's candidate set)
    /// - `QuorumApproved` -> CollectingApprovals (sets match)
    /// - `QuorumDeclined` -> Idle (sets mismatch)
    /// - `EndSigning` -> TidyUp (abort request)
    ///
    /// From CollectingApprovals:
    /// - `QuorumApproved` -> CollectingApprovals (party approved quorum)
    /// - `QuorumDeclined` -> Idle (party rejected quorum)
    /// - `ReadyToSign` -> Signing (all parties approved)
    /// - `EndSigning` -> TidyUp (abort request)
    ///
    /// From Signing:
    /// - `SigningComplete` -> VerifyingSignatures (shares generated)
    /// - `SigningSkipped` -> Idle (non-selected party)
    /// - `EndSigning` -> TidyUp (abort request)
    ///
    /// From VerifyingSignatures:
    /// - `VerificationComplete` -> Idle (signature verified)
    /// - `EndSigning` -> TidyUp (abort request)
    ///
    /// # Outputs
    ///
    /// The state machine can produce the following outputs during transitions:
    /// * `BroadcastCandidatesSet` - Broadcast local candidate set to all parties
    ///
    /// # Implementation Details
    ///
    /// - Uses the rust-fsm crate for state machine implementation
    /// - State transitions are atomic and thread-safe
    /// - States persist across async boundaries
    /// - Debug representation available for logging
    /// - C-compatible representation (repr(C))
    ///
    /// ```
    #[derive(Debug)]
    #[repr(C)]
    fsm(Idle)

    Idle => {
        Starting => Idle,
        SignRequestReceived => CollectingCandidates,
        EndSigning => TidyUp
    },

    CollectingCandidates => {
        CandidateAvailable => CollectingCandidates,
        CollectionTimeout => ComparingCandidates[BroadcastCandidatesSet],
        QuorumDeclined => Idle,
        EndSigning => TidyUp
    },

    ComparingCandidates => {
        CandidateSetReceived => ComparingCandidates,
        QuorumApproved => CollectingApprovals,
        QuorumDeclined => Idle,
        EndSigning => TidyUp
    },

    CollectingApprovals => {
        QuorumApproved => CollectingApprovals,
        QuorumDeclined => Idle,
        ReadyToSign => Signing,
        EndSigning => TidyUp
    },

    Signing => {
        SigningComplete => VerifyingSignatures,
        SigningSkipped => Idle,
        EndSigning => TidyUp
    },
    VerifyingSignatures => {
        VerificationComplete => Idle,
        EndSigning => TidyUp
    }
}

/// Protocol messages exchanged between signing participants.
///
/// Each message type represents a specific stage or action in the distributed
/// signing protocol. Messages are exchanged over WebSocket connections and
/// coordinate the multi-party signing process.
#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    /// Request to sign a specific message.
    ///
    /// # Fields
    /// * `message` - The message bytes to be signed
    SignRequest { message: Vec<u8> },

    /// Indicates a party's availability to participate in signing.
    /// Sent in response to a SignRequest.
    SigningAvailable,

    /// Shares the set of available signing candidates.
    ///
    /// # Fields
    /// * `candidates` - Set of party IDs that are available for signing
    CandidateSet { candidates: HashSet<u16> },

    /// Indicates approval of the proposed signing quorum.
    QuorumApproved,

    /// Indicates rejection of the proposed signing quorum.
    QuorumDeclined,

    /// Contains a party's signature share.
    ///
    /// # Fields
    /// * `sig_share` - The partial signature generated by this party
    SignatureShare { sig_share: Signature<Secp256k1> },

    /// Result of signature verification.
    ///
    /// # Fields
    /// * `success` - Whether the signature was successfully verified
    VerificationResult { success: bool },

    /// Signals the end of the signing session.
    EndSigning,
}

/// Context data for the signing protocol state machine.
///
/// Maintains the protocol state and coordinates the signing process
/// across multiple parties. Thread-safe access is provided through Arc<RwLock>.
pub struct Context {
    /// Collected signature shares from participating parties
    received_signatures: HashMap<u16, Signature<Secp256k1>>,

    /// Set of parties available for signing
    signing_candidates: HashSet<u16>,

    /// Candidate sets received from other parties
    received_candidates: HashMap<u16, HashSet<u16>>,

    /// Parties that have approved the quorum
    quorum_approved: HashSet<u16>,

    /// Message to be signed
    current_message: Option<Vec<u8>>,

    /// Deadline for collecting signing candidates
    deadline: Option<Instant>,

    /// Most recent protocol event
    last_event: Option<Input>,

    /// Parties selected for signing
    signing_parties: Vec<u16>,
}

impl Context {
    /// Creates a new signing context with default settings.
    ///
    /// # Returns
    /// A new `SigningEnv` instance initialized with empty collections
    /// and default timeout values.
    pub fn new() -> Self {
        Self {
            received_signatures: HashMap::new(),
            signing_candidates: HashSet::new(),
            received_candidates: HashMap::new(),
            quorum_approved: HashSet::new(),
            current_message: None,
            deadline: None,
            last_event: None,
            signing_parties: Vec::new(),
        }
    }

    /// Resets the signing environment to its initial state.
    ///
    /// Clears all collected data and prepares the environment for
    /// a new signing session.
    fn reset(&mut self) {
        self.received_signatures.clear();
        self.signing_candidates.clear();
        self.received_candidates.clear();
        self.quorum_approved.clear();
        self.current_message = None;
        self.deadline = None;
        self.signing_parties.clear();
    }

    /// Records a new protocol event.
    ///
    /// # Parameters
    /// * `event` - The protocol event to record
    fn event(&mut self, event: Input) {
        self.last_event = Some(event);
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

/// Signing protocol coordinator.
///
/// Manages the distributed signing process through a state machine,
/// coordinating P2P communication and operations between multiple parties.
pub struct Protocol {
    fsm: StateMachine<fsm::Impl>,
    context: Arc<RwLock<Context>>,
    storage: KeyStorage,
    p2p_node: Arc<P2PNode>,
    party_id: u16,
}

impl Protocol {
    /// Creates a new signing protocol instance.
    ///
    /// # Parameters
    /// * `party_id` - Unique identifier for this protocol participant
    /// * `p2p_node` - P2P networking node for communication
    /// * `storage` - Storage for cryptographic keys and protocol data
    ///
    /// # Returns
    /// A Result containing the new Protocol instance or an error
    ///
    /// # Errors
    /// Returns an error if initialization fails
    pub async fn new(
        party_id: u16,
        p2p_node: Arc<P2PNode>,
        storage: KeyStorage,
    ) -> Result<Self, Error> {
        // Initialize signing context data
        let context = Arc::new(RwLock::new(Context::new()));

        Ok(Self {
            fsm: StateMachine::new(),
            context: Arc::clone(&context),
            storage,
            p2p_node,
            party_id,
        })
    }

    /// Starts the signing protocol.
    ///
    /// Initializes P2P communication and begins processing protocol messages.
    /// Runs until explicitly stopped or an error occurs.
    ///
    /// # Returns
    /// A Result indicating success or failure
    ///
    /// # Errors
    /// Returns an error if:
    /// * P2P connection fails
    /// * Protocol initialization fails
    /// * Communication errors occur during the protocol
    pub async fn start(&mut self) -> Result<(), Error> {
        // Initialize P2P delivery for signing control messages
        let delivery = P2PDelivery::<Message>::connect(
            Arc::clone(&self.p2p_node),
            self.party_id,
            CommitteeSession::SigningControl,
        )
        .await?;

        let (receiver, sender) = Delivery::split(delivery);

        // Spawn message receiving task
        let message_handler = handle_messages(Arc::clone(&self.context), receiver);
        let run_handler = self.run_machine(sender);

        // End on termination of either handler
        tokio::select! {
            result = message_handler => result?,
            result = run_handler => result?,
        }
        Ok(())
    }

    /// Executes the signing protocol state machine.
    ///
    /// This is the core protocol execution loop that manages state transitions and
    /// coordinates the distributed signing process. It handles protocol events, manages
    /// state transitions, and coordinates communication between parties.
    ///
    /// # Protocol States Flow:
    /// ```text
    /// ┌────────┐     SignRequest     ┌──────────────────────┐
    /// │  Idle  │ ─────────────────-> │ CollectingCandidates │
    /// └────────┘                     └──────────────────────┘
    ///     ^                                    │
    ///     │                            CollectionTimeout
    ///     │                                    v
    ///     │                          ┌─────────────────────┐
    ///     │                          │ ComparingCandidates │
    ///     │                          └─────────────────────┘
    ///     │                                    │
    ///     │                           QuorumApproved
    /// Verification                             v
    /// Complete                       ┌─────────────────────┐
    ///     │                          │ CollectingApprovals │
    ///     │                          └─────────────────────┘
    ///     │                                     │
    /// ┌─────────────────────┐              ReadyToSign
    /// │ VerifyingSignatures │ <                 │
    /// └─────────────────────┘                   v
    ///           ^                        ┌───────────┐
    ///           └──────────────────────  │  Signing  │
    ///               SigningComplete      └───────────┘
    ///
    /// ```
    ///
    /// # Arguments
    ///
    /// * `sender` - WebSocket sender for broadcasting protocol messages to other parties
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the protocol completes successfully, or an `Error` if execution fails.
    ///
    /// # Protocol Actions by State
    ///
    /// * **Idle**
    ///   - Waits for signing requests
    ///   - Handles protocol initialization
    ///
    /// * **CollectingCandidates**
    ///   - Gathers responses from available signing parties
    ///   - Manages collection deadline
    ///   - Broadcasts availability to other parties
    ///
    /// * **ComparingCandidates**
    ///   - Verifies consistency of candidate sets across parties
    ///   - Broadcasts candidate set to other parties
    ///   - Determines quorum viability
    ///
    /// * **CollectingApprovals**
    ///   - Gathers quorum approvals from parties
    ///   - Validates quorum formation
    ///   - Prepares for signing phase
    ///
    /// * **Signing**
    ///   - Coordinates signature share generation
    ///   - Manages signing timeouts
    ///   - Handles signature share collection
    ///
    /// * **VerifyingSignatures**
    ///   - Validates collected signature shares
    ///   - Verifies combined signature
    ///   - Broadcasts verification results
    ///
    /// * **TidyUp**
    ///   - Performs cleanup operations
    ///   - Resets protocol state
    ///   - Prepares for next signing session
    ///
    /// # Error Handling
    ///
    /// - Network communication failures
    /// - Protocol timeout violations
    /// - Invalid state transitions
    /// - Signature verification failures
    ///
    /// # Timing Considerations
    ///
    /// - Collection deadline enforces timely candidate responses
    /// - Staggered communication delays prevent message flooding
    /// - State transitions include appropriate timing guards
    ///
    /// # Thread Safety
    ///
    /// - Uses Arc<RwLock> for thread-safe state access
    /// - Ensures consistent state updates across async boundaries
    /// - Maintains protocol invariants during concurrent operations
    ///
    /// # Example
    ///
    /// ```no_run
    /// async fn example_usage(mut signing: Signing, sender: WsSender<SigningProtocolMessage>) {
    ///     match signing.run_machine(sender).await {
    ///         Ok(()) => println!("Protocol completed successfully"),
    ///         Err(e) => eprintln!("Protocol error: {}", e),
    ///     }
    /// }
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// - State transitions are guarded by protocol invariants
    /// - Message handling is ordered and synchronized
    /// - Network communication uses non-blocking async operations
    /// - Error propagation maintains protocol safety
    ///
    async fn run_machine(&mut self, mut sender: Sender<Message>) -> Result<(), Error> {
        // Get out party ID
        let party_id = sender.get_party_id();
        let mut delivery_handle: Option<
            Result<P2PDelivery<cggmp21::signing::msg::Msg<Secp256k1, Sha256>>, Error>,
        > = None;

        // Starting event
        self.context.write().await.last_event = Some(Input::Starting);

        loop {
            // Acquire a context lock
            let mut context = self.context.write().await;

            // Pre-transition actions
            match (&self.fsm.state(), context.last_event.take()) {
                (fsm::State::TidyUp, _) => {
                    println!("Transition: TidyUp state - Cleaning up and exiting");
                    // Tidy-up goes here
                    return Ok(());
                }

                (fsm::State::Idle, Some(Input::Starting)) => {
                    let peer_id = self.p2p_node.peer_id();
                    println!("Ready for signing operations as party {party_id} [{peer_id}]");
                }

                (fsm::State::Idle, Some(Input::SignRequestReceived)) => {
                    println!("Transition: Idle -> CollectingCandidates (SignRequestReceived)");
                    println!("- Clearing previous candidates and setting collection deadline");
                    context.signing_candidates.clear();
                    context.set_deadline(Duration::from_secs(5));

                    // Add self to candidates and broadcast availability
                    context.signing_candidates.insert(party_id);
                    println!("- Added self (party_id: {}) to candidates", party_id);
                    sender.broadcast(Message::SigningAvailable).await?;

                    // Spawn delivery handler in a new task
                    delivery_handle = Some(
                        P2PDelivery::<cggmp21::signing::msg::Msg<Secp256k1, Sha256>>::connect(
                            Arc::clone(&self.p2p_node),
                            party_id,
                            CommitteeSession::SigningProtocol,
                        )
                        .await
                        .map_err(Error::from),
                    );

                    context.event(Input::SignRequestReceived);
                }

                (fsm::State::CollectingCandidates, _) => {
                    // Check for timeout
                    if context.is_deadline_elapsed() {
                        println!("- Committee candidate discovery complete");
                        context.event(Input::CollectionTimeout);
                    }
                }
                (fsm::State::ComparingCandidates, Some(Input::CandidateSetReceived)) => {
                    // Delay to stagger comms to account for the fact that IPC queues are unbounded
                    tokio::time::sleep(Duration::from_millis((50 * party_id) as u64)).await;
                    println!("Transition: ComparingCandidates state (CandidateSetReceived)");
                    println!(
                        "- Received candidates count: {}",
                        context.received_candidates.len()
                    );
                    println!(
                        "- Expected candidates count: {}",
                        context.signing_candidates.len() - 1
                    );

                    // Check if we have received candidate sets from all participants
                    if context.received_candidates.len() == context.signing_candidates.len() - 1 {
                        // Compare all received candidate sets, excluding self
                        let all_sets_match = context
                            .received_candidates
                            .iter()
                            .filter(|(&pid, _)| pid != party_id)
                            .all(|(_, set)| set == &context.signing_candidates);

                        println!("- All candidate sets match: {}", all_sets_match);

                        if all_sets_match {
                            println!("- Broadcasting quorum approval");
                            // Broadcast approval
                            sender.broadcast(Message::QuorumApproved).await?;
                            context.event(Input::QuorumApproved);
                        } else {
                            println!("- Broadcasting quorum decline due to mismatched sets");
                            println!("- Reference set: {:?}", context.signing_candidates);
                            // Print each mismatched set with its party ID
                            for (party_id, candidate_set) in &context.received_candidates {
                                if candidate_set != &context.signing_candidates {
                                    println!(
                                        "- Mismatched set from party {}: {:?}",
                                        party_id, candidate_set
                                    );
                                }
                            }
                            // Broadcast decline
                            sender.broadcast(Message::QuorumDeclined).await?
                        }
                    }
                }
                (fsm::State::CollectingApprovals, Some(Input::QuorumApproved)) => {
                    tokio::time::sleep(Duration::from_millis((50 * party_id) as u64)).await;
                    println!("Transition: CollectingApprovals state (QuorumApproved)");
                    println!("- Approvals received: {}", context.quorum_approved.len());
                    println!(
                        "- Required approvals: {}",
                        context.signing_candidates.len() - 1
                    );

                    // Check if we have approval from all candidates
                    if context.quorum_approved.len() == context.signing_candidates.len() - 1 {
                        // Select the lowest-ordered 3 members
                        let mut ordered_candidates: Vec<u16> =
                            context.signing_candidates.iter().cloned().collect();
                        ordered_candidates.sort();

                        // Select the signing parties
                        context.signing_parties =
                            ordered_candidates[..min(3, ordered_candidates.len())].to_vec();

                        println!("- Selected signing parties: {:?}", context.signing_parties);

                        // Raise a ready-to-sign event
                        context.last_event = Some(Input::ReadyToSign);
                    }
                }
                (fsm::State::Signing, _) => {
                    // Perform signing
                    // If we are not a signatory then quit the process
                    if !context.signing_parties.contains(&party_id) {
                        println!("- No further participation in the signing process");
                        context.event(Input::SigningComplete);
                        let _ = delivery_handle.take();
                        context.last_event = Some(Input::SigningSkipped);
                    } else if let Some(message) = &context.current_message.take() {
                        println!(
                            "- Starting signing process for message of length: {}",
                            message.len()
                        );

                        if let Some(Ok(delivery)) = delivery_handle.take() {
                            match handle_signing_request(
                                message,
                                &context.signing_parties,
                                &self.storage,
                                party_id,
                                delivery,
                            )
                            .await
                            {
                                Ok(signature) => {
                                    // Store our signature
                                    context.received_signatures.insert(party_id, signature);
                                    // Broadcast our signature
                                    sender
                                        .broadcast(Message::SignatureShare {
                                            sig_share: signature,
                                        })
                                        .await
                                        .map_err(Error::Network)?;

                                    let r_bytes = &signature.r.to_be_bytes();
                                    let s_bytes = &signature.s.to_be_bytes();

                                    println!(
                                        "{color_blue}- Signature [r,s]: [{:#?},{:#?}]{color_reset}",
                                        hex::encode(r_bytes),
                                        hex::encode(s_bytes)
                                    );
                                    context.event(Input::SigningComplete);
                                }
                                Err(e) => {
                                    println!("- Signing failed, {}", e);
                                    context.event(Input::SigningSkipped);
                                }
                            }
                            tokio::time::sleep(Duration::from_millis((50 * party_id) as u64)).await;
                        }
                        else {
                            println!("Couldn't take delivery handle");
                        }
                    }
                }
                (fsm::State::VerifyingSignatures, _) => {
                    // Check if we have signatures from all signing parties
                    if context.received_signatures.len() == context.signing_parties.len() {
                        // Get the first signature as reference
                        if let Some((_, first_sig)) = context.received_signatures.iter().next() {
                            // Compare all signatures with the first one
                            let all_match = context
                                .received_signatures
                                .iter()
                                .all(|(_, sig)| sig.r == first_sig.r && sig.s == first_sig.s);

                            println!("- Signature verification result: {}", all_match);
                            context.event(Input::VerificationComplete);

                            // Broadcast verification result
                            sender
                                .broadcast(Message::VerificationResult { success: all_match })
                                .await
                                .map_err(Error::Network)?;
                        }
                    }
                }
                _ => {}
            }

            // Perform state transition and perform output actions
            if let Some(last_event) = context.last_event.take() {
                if let Ok(output_event) = self.fsm.consume(&last_event) {
                    // Post-transition actions
                    match (&self.fsm.state(), output_event) {
                        (
                            fsm::State::ComparingCandidates,
                            Some(fsm::Output::BroadcastCandidatesSet),
                        ) => {
                            // Broadcast our candidate set
                            sender
                                .broadcast(Message::CandidateSet {
                                    candidates: context.signing_candidates.clone(),
                                })
                                .await
                                .map_err(Error::Network)?;
                        }
                        (fsm::State::Idle, _) => {
                            println!("Committee ready for signing operations.");
                            context.reset();
                        }
                        _ => {}
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Handles incoming protocol messages from all participating parties.
///
/// Processes and dispatches incoming protocol messages to maintain distributed signing state
/// coordination. This function runs as a separate task, continuously receiving and processing
/// messages until the connection is closed or an error occurs.
///
/// # Message Processing Flow
///
/// ```text
///  ┌──────────┐    ┌──────────┐    ┌─────────────────┐    ┌──────────┐
///  │ Incoming │    │ Validate │    │ Update Protocol │    │ Trigger  │
///  │ Message  │───>│  Message │───>│     Context     │───>│  Event   │
///  └──────────┘    └──────────┘    └─────────────────┘    └──────────┘
/// ```
///
/// # Arguments
///
/// * `context` - Shared signing environment state wrapped in Arc<RwLock>
/// * `receiver` - WebSocket receiver for incoming protocol messages
///
/// # Returns
///
/// Returns `Ok(())` if message handling completes normally (connection closed),
/// or an `Error` if an unrecoverable error occurs.
///
/// # Message Types Handled
///
/// * `SignRequest` - Initiates a new signing session
/// * `SigningAvailable` - Response indicating party availability
/// * `CandidateSet` - Shares view of available signing candidates
/// * `QuorumApproved/Declined` - Quorum formation responses
/// * `SignatureShare` - Partial signatures from participants
/// * `VerificationResult` - Signature verification status
/// * `EndSigning` - Session termination signal
///
/// # Error Handling
///
/// The function handles several error conditions:
/// - Network disconnection
/// - Message deserialization failures
/// - Protocol state violations
/// - Context lock acquisition failures
///
/// # Thread Safety
///
/// - Uses Arc<RwLock> for safe concurrent access to shared state
/// - Ensures atomic message processing
/// - Maintains protocol invariants during updates
///
/// # Implementation Notes
///
/// - Messages are processed sequentially in arrival order
/// - Each message triggers appropriate state machine events
/// - Error conditions trigger graceful shutdown
/// - Network errors are propagated to the caller
///
async fn handle_messages(
    context: Arc<RwLock<Context>>,
    mut receiver: Receiver<Message>,
) -> Result<(), Error> {
    pub async fn handle_message(
        incoming: Incoming<Message>,
        context: &Arc<RwLock<Context>>,
    ) -> Result<(), Error> {
        // Obtain a write lock
        let mut context = context.write().await;

        // Extract party ID from incoming message
        let pid = incoming.sender;

        // Match the message content
        let input = match incoming.msg {
            Message::SignRequest { message } => {
                context.current_message = Some(message);
                Input::SignRequestReceived
            }
            Message::SigningAvailable => {
                if !context.is_deadline_elapsed() {
                    context.signing_candidates.insert(pid);
                    println!(
                        "¬ Adding party {}. Available candidates: {:?}",
                        pid, context.signing_candidates
                    );
                    Input::CandidateAvailable
                } else {
                    println!(
                        "¬ Not adding party {} to available candidates (timeout)",
                        pid
                    );
                    Input::CollectionTimeout
                }
            }
            Message::CandidateSet { candidates } => {
                println!("¬ Adding candidate set from party {}", pid);

                context.received_candidates.insert(pid, candidates);
                Input::CandidateSetReceived
            }
            Message::QuorumApproved => {
                context.quorum_approved.insert(pid);
                Input::QuorumApproved
            }
            Message::QuorumDeclined => {
                println!("¬ Quorum declined by party {}", pid);
                Input::QuorumDeclined
            }
            Message::EndSigning => {
                println!("¬ Signing-ended by party {}", pid);
                Input::EndSigning
            }
            Message::SignatureShare { sig_share } => {
                println!("¬ Received signature share from party {}", pid);
                context.received_signatures.insert(pid, sig_share);
                Input::EndSigning
            }
            Message::VerificationResult { success } => {
                println!(
                    "¬ Received verification result from party {}: {}",
                    pid, success
                );
                Input::VerificationComplete
            }
        };

        // Trigger an event
        context.event(input);

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

/// Handles an incoming signing request.
///
/// Processes the signing request and generates a signature share
/// as part of the threshold signing process.
///
/// # Parameters
/// * `message` - The message to be signed
/// * `signing_parties` - List of parties participating in signing (lowest 3 party IDs)
/// * `storage` - Storage for cryptographic keys
/// * `party_id` - ID of the current party
/// * `delivery` - P2P channel for protocol messages
///
/// # Returns
/// A Result containing the generated signature share or an error
///
/// # Errors
/// Returns an error if:
/// * Signature generation fails
/// * P2P communication errors occur
/// * Key retrieval fails
async fn handle_signing_request(
    message: &[u8],
    signing_parties: &[u16],
    storage: &KeyStorage,
    party_id: u16,
    delivery: P2PDelivery<cggmp21::signing::msg::Msg<Secp256k1, Sha256>>,
) -> Result<Signature<Secp256k1>, Error> {
    println!("- Handling signing request from party ");

    // Load the stored data
    let execution_id = storage.load::<String>("execution_id")?;
    let key_share = storage.load_key_share("key_share")?;

    let execution_id = ExecutionId::new(execution_id.as_bytes());
    let data_to_sign = cggmp21::DataToSign::digest::<Sha256>(message);

    // Generate the signature
    println!("- Generating signature..");
    let signature = cggmp21::signing(execution_id, party_id, signing_parties, &key_share)
        .sign(&mut OsRng, MpcParty::connected(delivery), data_to_sign)
        .await
        .map_err(|e| Error::Protocol(ProtocolError::InvalidSignature(e.to_string())))?;

    Ok(signature)
}
