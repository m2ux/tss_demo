use crate::error::Error;
use crate::network;
use crate::network::{WsDelivery, WsReceiver, WsSender};
use crate::protocol::CommitteeSession;
use crate::signing::signing_protocol::Input;
use crate::storage::KeyStorage;
use cggmp21::security_level::SecurityLevel128;
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
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

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
    /// End of signing session
    EndSigning,
}

// Define the state machine
state_machine! {
    #[derive(Debug)]
    #[repr(C)]
    signing_protocol(Idle)

    Idle => {
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
        SigningComplete => Signing,
        EndSigning => TidyUp
    },

    Signing => {
        SigningComplete => Idle,
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
            signing_timeout: Duration::from_secs(30),
        }
    }

    /// Reset the protocol data
    fn reset(&mut self) {
        self.signing_candidates.clear();
        self.received_candidates.clear();
        self.quorum_approved.clear();
        self.current_message = None;
        self.collection_deadline = None;
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
            CommitteeSession::SigningSession,
        )
        .await?;
        let (receiver, sender) = Delivery::split(delivery);

        // Spawn message receiving task
        let message_handler = handle_messages(Arc::clone(&self.context), receiver);
        let run_handler = self.run_machine(sender);

        tokio::try_join!(message_handler, run_handler)?;
        Ok(())
    }

    /// Process an event and perform associated actions
    async fn run_machine(
        &mut self,
        mut sender: WsSender<SigningProtocolMessage>,
    ) -> Result<(), Error> {
        // Get out party ID
        let party_id = sender.get_party_id();

        loop {
            // Acquire a context lock
            let mut context = self.context.write().await;

            // Detect an incoming events
            let last_event = match context.last_event.take() {
                Some(event) => event,
                None => continue,
            };

            // Pre-transition actions
            match (&self.fsm.state(), last_event) {
                (signing_protocol::State::TidyUp, _) => {
                    println!("Transition: TidyUp state - Cleaning up and exiting");
                    // Tidy-up goes here
                    return Ok(());
                }

                (signing_protocol::State::Idle, Input::SignRequestReceived) => {
                    println!("Transition: Idle -> CollectingCandidates (SignRequestReceived)");
                    println!("- Clearing previous candidates and setting collection deadline");
                    context.signing_candidates.clear();
                    context.set_deadline();

                    // Add self to candidates and broadcast availability
                    context.signing_candidates.insert(party_id);
                    println!("- Added self (party_id: {}) to candidates", party_id);
                    sender
                        .broadcast(SigningProtocolMessage::SigningAvailable)
                        .await?
                }
                (signing_protocol::State::CollectingCandidates, Input::CandidateAvailable) => {
                    let deadline_elapsed = context.is_deadline_elapsed();
                    println!("Transition: CollectingCandidates state (CandidateAvailable)");
                    println!("- Collection deadline elapsed: {}", deadline_elapsed);
                    context.last_event = deadline_elapsed.then(|| {
                        context.signing_candidates.insert(party_id);
                        println!(
                            "- Deadline reached, adding self (party_id: {}) to candidates",
                            party_id
                        );
                        println!("- Current candidates: {:?}", context.signing_candidates);
                        Input::CollectionTimeout
                    });
                }
                (signing_protocol::State::CollectingCandidates, _) => {
                    let deadline_elapsed = context.is_deadline_elapsed();
                    println!("Transition: CollectingCandidates state (checking timeout)");
                    println!("- Collection deadline elapsed: {}", deadline_elapsed);
                    context.last_event = context
                        .is_deadline_elapsed()
                        .then_some(Input::CollectionTimeout);
                }
                (signing_protocol::State::ComparingCandidates, Input::CandidateSetReceived) => {
                    println!("Transition: ComparingCandidates state (CandidateSetReceived)");
                    println!(
                        "- Received candidates count: {}",
                        context.received_candidates.len()
                    );
                    println!(
                        "- Expected candidates count: {}",
                        context.signing_candidates.len()
                    );

                    // Check if we have received candidate sets from all participants
                    if context.received_candidates.len() == context.signing_candidates.len() {
                        // Compare all received candidate sets
                        let all_sets_match = context
                            .received_candidates
                            .values()
                            .all(|set| set == &context.signing_candidates);

                        println!("- All candidate sets match: {}", all_sets_match);

                        if all_sets_match {
                            println!("- Broadcasting quorum approval");
                            // Broadcast approval
                            sender
                                .broadcast(SigningProtocolMessage::QuorumApproved)
                                .await?
                        } else {
                            println!("- Broadcasting quorum decline due to mismatched sets");
                            // Broadcast decline
                            sender
                                .broadcast(SigningProtocolMessage::QuorumDeclined)
                                .await?
                        }
                    }
                }
                (signing_protocol::State::CollectingApprovals, Input::QuorumApproved) => {
                    println!("Transition: CollectingApprovals state (QuorumApproved)");
                    println!("- Approvals received: {}", context.quorum_approved.len());
                    println!("- Required approvals: {}", context.signing_candidates.len());

                    // Check if we have approval from all candidates
                    if context.quorum_approved.len() == context.signing_candidates.len() {
                        // Select the lowest-ordered 3 members
                        let mut ordered_candidates: Vec<u16> =
                            context.signing_candidates.iter().cloned().collect();
                        ordered_candidates.sort();

                        let signing_parties =
                            &ordered_candidates[..min(3, ordered_candidates.len())];

                        println!("- Selected signing parties: {:?}", signing_parties);

                        // Perform signing
                        if let Some(message) = &context.current_message.take() {
                            println!(
                                "- Starting signing process for message of length: {}",
                                message.len()
                            );
                            match handle_signing_request(
                                message,
                                signing_parties,
                                &self.storage,
                                party_id,
                            )
                            .await
                            {
                                Ok(signature) => {
                                    println!("- Signing successful, broadcasting signature share");
                                    // Store our signature
                                    context.received_signatures.insert(party_id, signature);
                                    // Broadcast our signature
                                    sender
                                        .broadcast(SigningProtocolMessage::SignatureShare {
                                            sig_share: signature,
                                        })
                                        .await
                                        .map_err(Error::Network)?;
                                    context.event(Input::SigningComplete);
                                }
                                Err(_) => {
                                    println!("- Signing failed, declining quorum");
                                    context.event(Input::QuorumDeclined);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }

            // Perform state transition and perform output actions
            if let Some(last_event) = context.last_event.take() {
                if let Ok(Some(output_event)) = self.fsm.consume(&last_event) {
                    // Post-transition actions
                    match (&self.fsm.state(), output_event) {
                        (
                            signing_protocol::State::ComparingCandidates,
                            signing_protocol::Output::BroadcastCandidatesSet,
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
                            context.reset();
                        }
                        _ => {}
                    }
                }
            }

            // Prevent tight loop
            drop(context);
            tokio::time::sleep(Duration::from_millis(100)).await;
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
        let mut context = context.write().await;

        // Extract party ID from incoming message
        let pid = incoming.sender;

        // Match the message content
        let input = match incoming.msg {
            SigningProtocolMessage::SignRequest { message } => {
                context.current_message = Some(message);
                Input::SignRequestReceived
            }
            SigningProtocolMessage::SigningAvailable => Input::CandidateAvailable,
            SigningProtocolMessage::CandidateSet { candidates } => {
                context.received_candidates.insert(pid, candidates);
                Input::CandidateSetReceived
            }
            SigningProtocolMessage::QuorumApproved => {
                context.quorum_approved.insert(pid);
                Input::QuorumApproved
            }
            SigningProtocolMessage::QuorumDeclined => Input::QuorumDeclined,
            SigningProtocolMessage::EndSigning => Input::EndSigning,
            SigningProtocolMessage::SignatureShare { sig_share } => {
                context.received_signatures.insert(pid, sig_share);
                Input::EndSigning
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
    message: &Vec<u8>,
    signing_parties: &[u16],
    storage: &KeyStorage,
    party_id: u16,
) -> Result<Signature<Secp256k1>, Error> {
    println!("Handling signing request from party ");

    // Load the stored data
    let execution_id = storage.load::<String>("execution_id")?;
    let key_share = storage.load::<cggmp21::KeyShare<Secp256k1, SecurityLevel128>>("key_share")?;

    let execution_id = ExecutionId::new(execution_id.as_bytes());

    // Hash the message to be signed
    let data_to_sign = cggmp21::DataToSign::digest::<Sha256>(message);

    let delivery = WsDelivery::<cggmp21::signing::msg::Msg<Secp256k1, Sha256>>::connect(
        "ws://localhost:8080",
        party_id,
        CommitteeSession::SigningSession,
    )
    .await?;

    // Generate the signature
    let signature = cggmp21::signing(execution_id, party_id, signing_parties, &key_share)
        .sign(&mut OsRng, MpcParty::connected(delivery), data_to_sign)
        .await
        .map_err(|e| Error::Protocol(e.to_string()))?;

    Ok(signature)
}
