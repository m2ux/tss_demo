//! CGGMP21 Protocol Implementation Demo
//!
//! This application demonstrates the implementation of the CGGMP21 threshold signature
//! protocol, providing a command-line interface for key generation and distributed
//! signing operations. The implementation supports secure communication between
//! parties and persistent storage of key shares.
//!
//! # Protocol Overview
//!
//! The CGGMP21 protocol is a threshold signature scheme that allows a group of
//! parties to collectively generate and manage cryptographic keys, where a subset
//! of parties can collaborate to create valid signatures.
//!
//! # Features
//!
//! * Distributed key generation
//! * Threshold signature creation
//! * Secure WebSocket communication
//! * Encrypted storage of key shares
//! * Command-line interface for easy operation
//!
//! # Usage
//!
//! ```bash
//! cggmp21-demo --message "Message to sign" \
//!              --signers "1,2,3,4,5" \
//!              --party-id 1 \
//!              --server "ws://localhost:8080"
//! ```
//!
//! # Architecture
//!
//! The application is structured around several key components:
//! * Network communication via WebSockets
//! * Secure storage for key shares
//! * Protocol implementation using the CGGMP21 library
//! * Command-line interface for configuration

mod network;
mod storage;
mod error;
mod server;

use clap::Parser;
use error::Error;
use cggmp21::{
    supported_curves::Secp256k1,
    ExecutionId,
    keygen::ThresholdMsg,
    security_level::SecurityLevel128,
};
use network::WsDelivery;
use storage::KeyStorage;
use sha2::Sha256;
use round_based::MpcParty;

/// Command-line arguments for the CGGMP21 demo application
///
/// This struct defines the configuration parameters that can be provided
/// via command-line arguments to customize the application's behavior.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Message to be signed by the threshold signature scheme.
    ///
    /// This message will be signed collaboratively by the specified
    /// number of parties using the distributed key shares.
    #[arg(short, long)]
    message: String,

    /// Party IDs for the signing committee (comma-separated).
    ///
    /// Specifies the identifiers for all parties participating in the
    /// protocol. Example: "1,2,3,4,5"
    ///
    /// # Format
    /// * Comma-separated list of positive integers
    /// * Minimum of 3 parties required
    /// * Each ID must be unique
    #[arg(short, long)]
    signers: String,

    /// Local party ID for this instance.
    ///
    /// The unique identifier for this party in the protocol.
    /// Must be one of the IDs specified in the signers list.
    #[arg(short, long)]
    party_id: u16,

    /// WebSocket server address for network communication.
    ///
    /// The address of the WebSocket server that coordinates
    /// communication between parties.
    ///
    /// # Format
    /// * WebSocket URL (ws:// or wss://)
    /// * Example: "ws://localhost:8080"
    #[arg(short, long)]
    server: String,
}

/// Main entry point for the CGGMP21 demo application.
///
/// This function:
/// 1. Parses and validates command-line arguments
/// 2. Initializes the network connection and storage
/// 3. Executes the key generation protocol
/// 4. Stores the generated key share securely
///
/// # Error Handling
///
/// Returns an error if:
/// * Command-line arguments are invalid
/// * Network connection fails
/// * Protocol execution fails
/// * Storage operations fail
///
/// # Example
///
/// ```bash
/// # Run the application with 5 parties, local party ID 1
/// cggmp21-demo --message "Hello, World!" \
///              --signers "1,2,3,4,5" \
///              --party-id 1 \
///              --server "ws://localhost:8080"
/// ```
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Parse command-line arguments
    let args = Args::parse();

    // Parse and validate the signing committee configuration
    let committee: Vec<u16> = args.signers
        .split(',')
        .map(|s| s.trim().parse::<u16>())
        .collect::<Result<Vec<u16>, _>>()
        .map_err(|_| Error::Config("Invalid committee specification".into()))?;

    // Ensure minimum number of signers
    if committee.len() < 3 {
        return Err(Error::Config("At least 3 signers are required".into()));
    }

    // Initialize secure storage for key shares
    let storage = KeyStorage::new(
        "keys",
        "a very secret key that should be properly secured",
    )?;

    // Initialize network connection
    type Msg = ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>;
    let delivery = WsDelivery::<Msg>::connect(&args.server, args.party_id).await?;

    // Start key generation protocol
    println!("Starting key generation protocol...");
    let keygen_eid = ExecutionId::new(b"keygen-1");

    // Execute the distributed key generation protocol
    let incomplete_key_share = cggmp21::keygen::<Secp256k1>(keygen_eid, args.party_id, committee.len() as u16)
        .set_threshold(3)
        .enforce_reliable_broadcast(true)
        .start(&mut rand_core::OsRng, MpcParty::connected(delivery))
        .await?;

    // Store the generated key share securely
    storage.save("incomplete_key_share", &incomplete_key_share)?;

    println!("Key generation completed successfully!");
    println!("Incomplete key share has been securely stored.");

    Ok(())
}