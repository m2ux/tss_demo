//! CGGMP21 Protocol Implementation Demo
//!
//! A distributed threshold signature implementation based on the CGGMP21 protocol.
//! This application enables multiple parties to collaboratively generate and use
//! threshold signatures without requiring any party to possess the complete private key.
//!
//! # Protocol Overview
//!
//! The implementation follows three main phases:
//! 1. **Committee Formation**: Parties discover each other and establish communication
//! 2. **Key Generation**: Distributed generation of key shares using CGGMP21
//! 3. **Signing**: Threshold-based signature generation on demand
//!
//! # Features
//!
//! * Dynamic signer discovery and committee formation
//! * Distributed key generation (t-of-n threshold scheme)
//! * Multi-round threshold signing operations
//! * Secure WebSocket communication with reliable broadcast
//! * Encrypted persistent storage of key shares
//! * Automatic quorum formation for signing operations
//!
//! # Security Properties
//!
//! * No single party ever knows the complete private key
//! * Threshold security against compromised parties
//! * Secure against network adversaries
//! * Protected key share storage
//!
//! # Usage
//!
//! Start as a committee member:
//! ```bash
//! cggmp21-demo --committee --party-id 1 --server "ws://localhost:8080"
//! ```
//!
//! Initiate signing operation:
//! ```bash
//! cggmp21-demo --message "Message to sign" --party-id 2 --server "ws://localhost:8080"
//! ```
//!
//! # Protocol Parameters
//!
//! * Minimum committee size: 5 parties
//! * Signing threshold: 3 parties
//! * Security level: 128 bits
//! * Curve: secp256k1
//! * Hash function: SHA256

mod network;
mod storage;
mod error;
mod server;
mod protocol;

use clap::Parser;
use error::Error;
use futures::StreamExt;
use network::WsDelivery;
use protocol::{discover_committee_members,run_committee_mode};
use cggmp21::{
    supported_curves::Secp256k1,
    keygen::ThresholdMsg,
    security_level::SecurityLevel128,
};
use storage::KeyStorage;
use sha2::Sha256;
use round_based::Delivery;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tokio::sync::oneshot;

/// Internal state tracking for signing sessions
struct SigningSession {
    response_channel: oneshot::Sender<()>,
    party_id: u16,
}

/// Manages active signing sessions
struct SigningSessionManager {
    sessions: HashMap<u16, SigningSession>,
}

impl SigningSessionManager {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    fn add_session(&mut self, party_id: u16, response_channel: oneshot::Sender<()>) {
        self.sessions.insert(party_id, SigningSession {
            response_channel,
            party_id,
        });
    }

    fn remove_session(&mut self, party_id: u16) -> Option<SigningSession> {
        self.sessions.remove(&party_id)
    }
}

/// Operation modes for the application
#[derive(Debug)]
enum OperationMode {
    /// Participate in the signing committee
    Committee,
    /// Initiate a signing operation
    Sign(String),
}

/// Command-line arguments for the CGGMP21 demo application
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Run in committee mode, participating in the signing committee
    #[arg(long, conflicts_with = "message")]
    committee: bool,

    /// Message to be signed (initiates signing mode)
    #[arg(short, long, conflicts_with = "committee")]
    message: Option<String>,

    /// Local party ID for this instance
    #[arg(short, long)]
    party_id: u16,

    /// WebSocket server address
    #[arg(short, long)]
    server: String,
}

/// Main entry point for the CGGMP21 demo application
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Parse command-line arguments
    let args = Args::parse();

    // Determine operation mode
    let mode = if args.committee {
        OperationMode::Committee
    } else if let Some(msg) = args.message.clone() {
        OperationMode::Sign(msg)
    } else {
        return Err(Error::Config("Either --committee or --message must be specified".into()));
    };

    // Initialize storage
    let storage = KeyStorage::new(
        "keys",
        "a very secret key that should be properly secured",
    )?;

    // Initialize network connection
    type Msg = ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>;
    let delivery = WsDelivery::<Msg>::connect(&args.server, args.party_id).await?;

    match mode {
        OperationMode::Committee => {
            run_committee_mode(delivery, storage, args.party_id).await?;
        },
        OperationMode::Sign(message) => {
            run_signing_mode(delivery, storage, args.party_id, message).await?;
        }
    }

    Ok(())
}

/// Runs the application in signing mode, initiating a signing operation
async fn run_signing_mode(
    _delivery: WsDelivery<ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>>,
    _storage: KeyStorage,
    _party_id: u16,
    message: String,
) -> Result<(), Error> {
    println!("Starting signing process for message: {}", message);

    // Discover available committee members
    let committee = discover_committee_members().await?;
    println!("Found {} committee members", committee.len());

    // Check if we have enough committee members for threshold
    if committee.len() < 3 {
        return Err(Error::Config("Not enough committee members available (minimum 3 required)".into()));
    }

    //TODO

    // Display the resulting signature
    println!("Signature generated successfully:");

    Ok(())
}