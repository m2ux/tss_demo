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
mod service;

use clap::Parser;
use error::Error;
use network::WsDelivery;
use protocol::run_committee_mode;
use cggmp21::{
    supported_curves::Secp256k1,
    keygen::ThresholdMsg,
    security_level::SecurityLevel128,
};
use service::run_service_mode;
use storage::KeyStorage;
use sha2::Sha256;
use tokio::sync::oneshot;

/// Internal state tracking for signing sessions
struct SigningSession {
    response_channel: oneshot::Sender<()>,
    party_id: u16,
}

/// Operation modes for the application
#[derive(Debug)]
enum OperationMode {
    /// Participate in the signing committee
    Committee,
    /// Operate as a signing service
    Service(String),
}

/// Command-line arguments
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
        OperationMode::Service(msg)
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

    // Select operating mode
    match mode {
        OperationMode::Committee => {
            run_committee_mode(delivery, storage, args.party_id).await?;
        },
        OperationMode::Service(message) => {
            run_service_mode(delivery, storage, args.party_id, message).await?;
        }
    }

    Ok(())
}