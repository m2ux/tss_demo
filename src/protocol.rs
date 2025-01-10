use crate::network;
use crate::error::Error;
use futures::StreamExt;
use crate::network::{WsDelivery, NetworkError};
use cggmp21::{
    supported_curves::Secp256k1,
    ExecutionId,
    keygen::ThresholdMsg,
    key_refresh::AuxOnlyMsg,
    security_level::SecurityLevel128,
    PregeneratedPrimes,
};
use crate::storage::KeyStorage;
use sha2::Sha256;
use rand_core::OsRng;
use round_based::{Delivery,MpcParty};
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

/// Protocol message types for WebSocket communication
#[derive(Serialize, Deserialize, Debug)]
enum ProtocolMessage {
    /// Announce presence as a committee member
    CommitteeMemberAnnouncement { party_id: u16 },
    /// Response with current committee state
    CommitteeState {
        members: HashSet<u16>,
        aux_info_ready: HashSet<u16>,
        keygen_ready: HashSet<u16>,
    },
    /// Announce auxiliary info generation completion
    AuxInfoReady { party_id: u16 },
    /// Announce key generation completion
    KeyGenReady { party_id: u16 },
    /// Initiate signing process
    SigningRequest {
        message: String,
        initiator: u16,
    },
    /// Accept participation in signing
    SigningAccept { party_id: u16 },
    /// Share the resulting signature
    SignatureShare {
        party_id: u16,
        share: Vec<u8>,
    },
}

/// Committee initialization states
#[derive(Debug, Clone, PartialEq)]
enum CommitteeState {
    /// Waiting for all members to announce presence
    AwaitingMembers,
    /// Generating auxiliary information
    GeneratingAuxInfo,
    /// Waiting for all members to complete aux info generation
    AwaitingAuxInfo,
    /// Performing distributed key generation
    GeneratingKeys,
    /// Waiting for all members to complete key generation
    AwaitingKeyGen,
    /// Ready for signing operations
    Ready,
}

/// Message types that can be received from the network
#[derive(Debug)]
enum NetworkMessage<M> {
    /// Protocol-specific messages (ThresholdMsg)
    Protocol(round_based::Incoming<M>),
    /// Our custom protocol messages
    Control(ProtocolMessage),
}

/// Runs the application in committee mode, participating in the signing committee
pub async fn run_committee_mode(
    delivery: WsDelivery<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>,
    storage: KeyStorage,
    party_id: u16,
) -> Result<(), Error> {
    println!("Starting in committee mode with party ID: {}", party_id);

    let server_addr = delivery.addr().to_string();
    let (mut receiver, _sender) = delivery.split();

    // Initialize committee state
    let mut committee_members = HashSet::new();
    let mut aux_info_ready = HashSet::new();
    let mut keygen_ready = HashSet::new();
    let mut state = CommitteeState::AwaitingMembers;

    // Announce presence
    broadcast_committee_announcement(party_id).await?;
    committee_members.insert(party_id);

    // Committee initialization phase
    loop {
        match state {
            CommitteeState::AwaitingMembers => {
                if committee_members.len() >= 5 {
                    println!("All committee members present. Starting auxiliary info generation.");
                    state = CommitteeState::GeneratingAuxInfo;
                }
            },
            CommitteeState::GeneratingAuxInfo => {
                // Create a new delivery instance for aux info generation
                let aux_delivery = WsDelivery::<AuxOnlyMsg<Sha256, SecurityLevel128>>::connect(
                    &server_addr,
                    party_id,
                ).await?;

                // Generate auxiliary info as per CGGMP21
                let aux_info = generate_auxiliary_info(
                    party_id,
                    committee_members.len() as u16,
                    aux_delivery,
                ).await?;
                storage.save("aux_info", &aux_info)?;

                broadcast_aux_info_ready(party_id).await?;
                aux_info_ready.insert(party_id);
                state = CommitteeState::AwaitingAuxInfo;
            },
            CommitteeState::AwaitingAuxInfo => {
                if aux_info_ready.len() >= 5 {
                    println!("All auxiliary info generated. Starting key generation.");
                    state = CommitteeState::GeneratingKeys;
                }
            },
            CommitteeState::GeneratingKeys => {
                // Create a new delivery instance for key generation
                let keygen_delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
                    &server_addr,
                    party_id,
                ).await?;

                // Perform distributed key generation
                let key_share = generate_key_share(
                    party_id,
                    &committee_members,
                    keygen_delivery,
                ).await?;
                storage.save("incomplete_key_share", &key_share)?;

                broadcast_keygen_ready(party_id).await?;
                keygen_ready.insert(party_id);
                state = CommitteeState::AwaitingKeyGen;
            },
            CommitteeState::AwaitingKeyGen => {
                if keygen_ready.len() >= 5 {
                    println!("Key generation complete. Ready for signing operations.");
                    state = CommitteeState::Ready;
                }
            },
            CommitteeState::Ready => {
                // Start handling signing requests
                handle_signing_requests(&storage, party_id).await?;
            }
        }

        // Process incoming messages
        match receive_network_message(&mut receiver).await? {
            NetworkMessage::Control(msg) => match msg {
                ProtocolMessage::CommitteeMemberAnnouncement { party_id: pid } => {
                    committee_members.insert(pid);
                },
                ProtocolMessage::AuxInfoReady { party_id: pid } => {
                    aux_info_ready.insert(pid);
                },
                ProtocolMessage::KeyGenReady { party_id: pid } => {
                    keygen_ready.insert(pid);
                },
                _ => {}
            },
            NetworkMessage::Protocol(_) => {
                // Handle protocol-specific messages if needed
            }
        }
    }
}

/// Generates auxiliary information as per CGGMP21 specification
async fn generate_auxiliary_info(
    party_id: u16,
    n_parties: u16,
    delivery: WsDelivery<AuxOnlyMsg<Sha256, SecurityLevel128>>, // Updated message type
) -> Result<Vec<u8>, Error> {
    println!("Generating auxiliary information for party {}", party_id);

    // Prime generation can take a while
    let pregenerated_primes = PregeneratedPrimes::generate(&mut OsRng);

    let eid = ExecutionId::new(b"aux-info-1");

    let aux_info = cggmp21::aux_info_gen(
        eid,
        party_id,
        n_parties,
        pregenerated_primes
    )
        .start(&mut OsRng, MpcParty::connected(delivery))
        .await
        .map_err(Error::KeyRefresh)?;

    // Serialize the auxiliary information
    let serialized = bincode::serialize(&aux_info)
        .map_err(Error::Serialization)?;

    println!("Auxiliary information generated successfully");
    Ok(serialized)
}

/// Generates key share through distributed key generation protocol
async fn generate_key_share(
    party_id: u16,
    committee: &HashSet<u16>,
    delivery: WsDelivery<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>,
) -> Result<Vec<u8>, Error> {
    println!("Starting distributed key generation for party {}", party_id);

    // Initialize key generation with CGGMP21
    let keygen_eid = ExecutionId::new(b"keygen-1");
    let keygen = cggmp21::keygen::<Secp256k1>(
        keygen_eid,
        party_id,
        committee.len() as u16
    )
        .set_threshold(3)
        .enforce_reliable_broadcast(true)
        .start(&mut OsRng, MpcParty::connected(delivery))
        .await
        .map_err(Error::Keygen)?;

    // Serialize the key share
    let key_share = bincode::serialize(&keygen)
        .map_err(Error::Serialization)?;

    Ok(key_share)
}

/// Broadcasts committee member announcement to the network
async fn broadcast_committee_announcement(party_id: u16) -> Result<(), Error> {
    println!("Broadcasting presence as committee member {}", party_id);

    // Create the announcement message
    let announcement = ProtocolMessage::CommitteeMemberAnnouncement { party_id };

    // Serialize the announcement
    let serialized = bincode::serialize(&announcement)
        .map_err(Error::Serialization)?;

    // Send the announcement to all connected peers
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080",  // Use configured server address here
        party_id
    ).await?;

    let (_receiver, sender) = delivery.split();
    sender.broadcast(serialized).await
        .map_err(Error::Network)?;

    Ok(())
}

/// Broadcasts auxiliary info completion status
async fn broadcast_aux_info_ready(party_id: u16) -> Result<(), Error> {
    println!("Broadcasting auxiliary info completion for party {}", party_id);

    // Create the completion status message
    let ready_msg = ProtocolMessage::AuxInfoReady { party_id };

    // Serialize the message
    let serialized = bincode::serialize(&ready_msg)
        .map_err(Error::Serialization)?;

    // Send the message to all connected peers
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080",  // Use configured server address here
        party_id
    ).await?;

    let (_receiver, sender) = delivery.split();
    sender.broadcast(serialized).await
        .map_err(Error::Network)?;

    Ok(())
}

/// Broadcasts key generation completion status
async fn broadcast_keygen_ready(party_id: u16) -> Result<(), Error> {
    println!("Broadcasting key generation completion for party {}", party_id);

    // Create the completion status message
    let ready_msg = ProtocolMessage::KeyGenReady { party_id };

    // Serialize the message
    let serialized = bincode::serialize(&ready_msg)
        .map_err(Error::Serialization)?;

    // Send the message to all connected peers
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080",  // Use configured server address here
        party_id
    ).await?;

    let (_receiver, sender) = delivery.split();
    sender.broadcast(serialized).await
        .map_err(Error::Network)?;

    Ok(())
}

/// Discovers currently available committee members
pub async fn discover_committee_members() -> Result<HashSet<u16>, Error> {
    println!("Discovering available committee members...");

    // Connect to the WebSocket server
    let delivery = WsDelivery::<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>::connect(
        "ws://localhost:8080", // This should use the configured server address
        0, // Use party ID 0 for discovery
    ).await?;

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
    // TODO: Implement actual request handling
    Ok(None)
}

/// Structure representing a signing request
#[derive(Debug)]
struct SigningRequest {
    message: String,
    initiator: u16,
}

/// Handles an incoming signing request
async fn handle_signing_request(
    request: SigningRequest,
    storage: &KeyStorage,
) -> Result<(), Error> {
    println!("Handling signing request from party {}", request.initiator);

    // Load the key share
    let _key_share = storage.load::<Vec<u8>>("incomplete_key_share")?;

    // TODO: Implement actual signing request handling
    Ok(())
}

/// Handles signing requests after initialization
async fn handle_signing_requests(storage: &KeyStorage, _party_id: u16) -> Result<(), Error> {
    loop {
        if let Some(request) = await_signing_request().await? {
            handle_signing_request(request, storage).await?;
        }
    }
}

/// Receives and processes incoming network messages
async fn receive_network_message<M>(
    receiver: &mut network::WsReceiver<M>,
) -> Result<NetworkMessage<M>, Error>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de> + std::marker::Unpin,
{
    match receiver.next().await {
        Some(Ok(incoming)) => {
            // The incoming message is already deserialized as Incoming<M>
            // Try to cast the message as a ProtocolMessage
            match bincode::serialize(&incoming.msg) {
                Ok(bytes) => {
                    if let Ok(control_msg) = bincode::deserialize::<ProtocolMessage>(&bytes) {
                        Ok(NetworkMessage::Control(control_msg))
                    } else {
                        // If it's not a control message, return it as a protocol message
                        Ok(NetworkMessage::Protocol(incoming))
                    }
                },
                Err(_) => Ok(NetworkMessage::Protocol(incoming))
            }
        },
        Some(Err(e)) => Err(Error::Network(e)),
        None => Err(Error::Network(NetworkError::Connection("Connection closed".into())))
    }
}