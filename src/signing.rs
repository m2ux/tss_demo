use crate::error::Error;
use crate::network;
use crate::network::{WsDelivery, WsReceiver, WsSender};
use crate::protocol::CommitteeSession;
use crate::signing::signing_protocol::Input;
use crate::storage::{KeyStorage, StorageError};
use cggmp21::key_share::{AuxInfo, DirtyKeyShare};
use cggmp21_keygen::key_share::{CoreKeyShare, Valid};
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{ExecutionId, Signature};
use futures_util::StreamExt;
use rand_core::OsRng;
use round_based::{Delivery, Incoming, MpcParty};
use rust_fsm::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use cggmp21::generic_ec::NonZero;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};
use inline_colorization::*;

#[derive(Serialize, Deserialize, Debug)]
pub enum SigningProtocolMessage {
    /// Message to be signed
    SignRequest {
        message: Vec<u8>,
    },
    /// Indicates availability to participate in signing
    SigningAvailable,
    /// Share collected signing candidates
    CandidateSet {
        candidates: HashSet<u16>,
    },
    /// Approval of quorum formation
    QuorumApproved,
    /// Decline of quorum formation
    QuorumDeclined,

    SignatureShare {
        sig_share: Signature<Secp256k1>,
    },
    VerificationResult {
        success: bool,
    },
    /// End of signing session
    EndSigning,
}

// Define the state machine
state_machine! {
    #[derive(Debug)]
    #[repr(C)]
    signing_protocol(Idle)

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

/// Data associated with the state machine
pub struct SigningEnv {
    received_signatures: HashMap<u16, Signature<Secp256k1>>,
    signing_candidates: HashSet<u16>,
    received_candidates: HashMap<u16, HashSet<u16>>,
    quorum_approved: HashSet<u16>,
    current_message: Option<Vec<u8>>,
    collection_deadline: Option<Instant>,
    last_event: Option<Input>,
    signing_timeout: Duration,
    signing_parties: Vec<u16>,
}

impl SigningEnv {
    pub fn new() -> Self {
        Self {
            received_signatures: HashMap::new(),
            signing_candidates: HashSet::new(),
            received_candidates: HashMap::new(),
            quorum_approved: HashSet::new(),
            current_message: None,
            collection_deadline: None,
            last_event: None,
            signing_timeout: Duration::from_secs(10),
            signing_parties: Vec::new(),
        }
    }

    /// Reset the protocol data
    fn reset(&mut self) {
        self.received_signatures.clear();
        self.signing_candidates.clear();
        self.received_candidates.clear();
        self.quorum_approved.clear();
        self.current_message = None;
        self.collection_deadline = None;
        self.signing_parties.clear();
    }

    fn event(&mut self, event: Input) {
        self.last_event = Some(event);
    }

    fn is_deadline_elapsed(&self) -> bool {
        self.collection_deadline
            .map(|deadline| Instant::now() > deadline)
            .unwrap_or(false)
    }

    fn set_deadline(&mut self) {
        self.collection_deadline = Some(Instant::now() + self.signing_timeout);
    }
}

/// Complete state machine with data
pub struct Signing {
    fsm: StateMachine<signing_protocol::Impl>,
    context: Arc<RwLock<SigningEnv>>,
    storage: KeyStorage,
}

impl Signing {
    pub async fn new(storage: KeyStorage) -> Result<Self, Error> {
        // Initialize signing context data
        let context = Arc::new(RwLock::new(SigningEnv::new()));

        Ok(Self {
            fsm: StateMachine::new(),
            context: Arc::clone(&context),
            storage,
        })
    }

    pub async fn start(&mut self, party_id: u16, server_addr: &str) -> Result<(), Error> {
        // Create a new delivery instance for aux info generation
        let delivery = WsDelivery::<SigningProtocolMessage>::connect(
            server_addr,
            party_id,
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

    /// Process an event and perform associated actions
    async fn run_machine(
        &mut self,
        mut sender: WsSender<SigningProtocolMessage>,
    ) -> Result<(), Error> {
        // Get out party ID
        let party_id = sender.get_party_id();
        let mut delivery_handle: Option<Result<WsDelivery<cggmp21::signing::msg::Msg<Secp256k1, Sha256>>, Error>> = None;

        // Starting event
        self.context.write().await.last_event = Some(Input::Starting);
        
        loop {
            // Acquire a context lock
            let mut context = self.context.write().await;

            // Pre-transition actions
            match (&self.fsm.state(), context.last_event.take()) {
                (signing_protocol::State::TidyUp, _) => {
                    println!("Transition: TidyUp state - Cleaning up and exiting");
                    // Tidy-up goes here
                    return Ok(());
                }

                (signing_protocol::State::Idle, Some(Input::Starting)) => {
                    println!("Committee ready for signing operations.");
                }

                (signing_protocol::State::Idle, Some(Input::SignRequestReceived)) => {
                    println!("Transition: Idle -> CollectingCandidates (SignRequestReceived)");
                    println!("- Clearing previous candidates and setting collection deadline");
                    context.signing_candidates.clear();
                    context.set_deadline();

                    // Add self to candidates and broadcast availability
                    context.signing_candidates.insert(party_id);
                    println!("- Added self (party_id: {}) to candidates", party_id);
                    sender
                        .broadcast(SigningProtocolMessage::SigningAvailable)
                        .await?;

                    // Spawn delivery handler in a new task
                    delivery_handle = Some(
                        WsDelivery::<cggmp21::signing::msg::Msg<Secp256k1, Sha256>>::connect(
                            "ws://localhost:8080",
                            party_id,
                            CommitteeSession::Signing,
                        )
                            .await
                            .map_err(Error::from));

                    context.event(Input::SignRequestReceived);
                }

                (signing_protocol::State::CollectingCandidates, _) => {
                    // Check for timeout
                    if context.is_deadline_elapsed() {
                        println!("- Committee candidate discovery complete");
                        context.event(Input::CollectionTimeout);
                    }
                }
                (
                    signing_protocol::State::ComparingCandidates,
                    Some(Input::CandidateSetReceived),
                ) => {
                    tokio::time::sleep(Duration::from_millis((10 * party_id) as u64)).await;
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
                            sender
                                .broadcast(SigningProtocolMessage::QuorumApproved)
                                .await?;
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
                            sender
                                .broadcast(SigningProtocolMessage::QuorumDeclined)
                                .await?
                        }
                    }
                }
                (signing_protocol::State::CollectingApprovals, Some(Input::QuorumApproved)) => {
                    tokio::time::sleep(Duration::from_millis((10 * party_id) as u64)).await;
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
                (signing_protocol::State::Signing, _) => {

                    // Perform signing
                    // If we are not a signatory then quite the process
                    if !context.signing_parties.contains(&party_id) {
                        println!("- No further participation in the signing process");
                        context.event(Input::SigningComplete);
                        let _ = delivery_handle.take();
                        context.last_event = Some(Input::SigningSkipped);
                    }else if let Some(message) = &context.current_message.take() {
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
                                        .broadcast(SigningProtocolMessage::SignatureShare {
                                            sig_share: signature,
                                        })
                                        .await
                                        .map_err(Error::Network)?;

                                    let r_bytes = &signature.r.to_be_bytes();
                                    let s_bytes = &signature.s.to_be_bytes();

                                    println!("- Signature [r,s]: [{:#?},{:#?}]", hex::encode(r_bytes), hex::encode(s_bytes));
                                    context.event(Input::SigningComplete);
                                }
                                Err(e) => {
                                    println!("- Signing failed, {}", e);
                                    context.event(Input::SigningComplete);
                                }
                            }
                            tokio::time::sleep(Duration::from_millis((10 * party_id) as u64)).await;
                        }
                    }
                }
                // In the run_machine match block, add:
                (signing_protocol::State::VerifyingSignatures, _) => {
                    // Check if we have signatures from all signing parties
                    if context.received_signatures.len() == context.signing_parties.len() {

                        //println!("- Received signatures: {:?}", &context.received_signatures);

                        // Get the first signature as reference
                        if let Some((_, first_sig)) = context.received_signatures.iter().next() {
                            // Compare all signatures with the first one
                            let all_match = context.received_signatures.iter()
                                .all(|(_, sig)| {
                                    sig.r == first_sig.r && sig.s == first_sig.s
                                });

                            println!("- Signature verification result: {}", all_match);
                            context.event(Input::VerificationComplete);

                            // Broadcast verification result
                            sender
                                .broadcast(SigningProtocolMessage::VerificationResult {
                                    success: all_match,
                                })
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
                            signing_protocol::State::ComparingCandidates,
                            Some(signing_protocol::Output::BroadcastCandidatesSet),
                        ) => {
                            // Broadcast our candidate set
                            sender
                                .broadcast(SigningProtocolMessage::CandidateSet {
                                    candidates: context.signing_candidates.clone(),
                                })
                                .await
                                .map_err(Error::Network)?;
                        }
                        (signing_protocol::State::Idle, _) => {
                            println!("Committee ready for signing operations.");
                            context.reset();
                        }
                        _ => {}
                    }
                }
            }

            //drop(context);
            //tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

/// Task for handling messages
async fn handle_messages(
    context: Arc<RwLock<SigningEnv>>,
    mut receiver: WsReceiver<SigningProtocolMessage>,
) -> Result<(), Error> {
    pub async fn handle_message(
        incoming: Incoming<SigningProtocolMessage>,
        context: &Arc<RwLock<SigningEnv>>,
    ) -> Result<(), Error> {
        // Obtain a write lock
        let mut context = context.write().await;

        // Extract party ID from incoming message
        let pid = incoming.sender;
        
        // Match the message content
        let input = match incoming.msg {
            SigningProtocolMessage::SignRequest { message } => {
                context.current_message = Some(message);
                Input::SignRequestReceived
            }
            SigningProtocolMessage::SigningAvailable => {
                if !context.is_deadline_elapsed() {
                    context.signing_candidates.insert(pid);
                    println!(
                        "{color_blue}¬ Adding party {}. Available candidates: {:?}{color_reset}",
                        pid, context.signing_candidates
                    );
                    Input::CandidateAvailable
                } else {
                    println!("{color_blue}¬ Not adding party {} to available candidates (timeout){color_reset}", pid);
                    Input::CollectionTimeout
                }
            }
            SigningProtocolMessage::CandidateSet { candidates } => {
                println!("{color_blue}¬ Adding candidate set from party {}{color_reset}", pid);

                context.received_candidates.insert(pid, candidates);
                Input::CandidateSetReceived
            }
            SigningProtocolMessage::QuorumApproved => {
                context.quorum_approved.insert(pid);
                Input::QuorumApproved
            }
            SigningProtocolMessage::QuorumDeclined => {
                println!("{color_blue}¬ Quorum declined by party {}{color_reset}", pid);
                Input::QuorumDeclined
            }
            SigningProtocolMessage::EndSigning => {
                println!("{color_blue}¬ Signing-ended by party {}{color_reset}", pid);
                Input::EndSigning
            }
            SigningProtocolMessage::SignatureShare { sig_share } => {
                println!("{color_blue}¬ Received signature share from party {}{color_reset}", pid);
                context.received_signatures.insert(pid, sig_share);
                Input::EndSigning
            }
            SigningProtocolMessage::VerificationResult { success } => {
                println!("{color_blue}¬ Received verification result from party {}: {}{color_reset}", pid, success);
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

/// Handles an incoming signing request
async fn handle_signing_request(
    message: &[u8],
    signing_parties: &[u16],
    storage: &KeyStorage,
    party_id: u16,
    delivery: WsDelivery<cggmp21::signing::msg::Msg<Secp256k1, Sha256>>,
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
        .map_err(|e| Error::Protocol(e.to_string()))?;

    Ok(signature)
}