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
//! * WebSocket server functionality for message relaying
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
//! Run as a WebSocket server:
//! ```bash
//! cggmp21-demo --server-mode --server "localhost:8080"
//! ```
//!
//! # Protocol Parameters
//!
//! * Minimum committee size: 5 parties
//! * Signing threshold: 3 parties
//! * Security level: 128 bits
//! * Curve: secp256k1
//! * Hash function: SHA256

mod error;
mod network;
mod protocol;
mod server;
mod service;
mod signing;
mod storage;
mod p2p;
mod websocket;

use std::time::Duration;
use clap::Parser;
use futures_util::TryFutureExt;
use error::Error;
use service::run_service_mode;

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Config(err.to_string())
    }
}

impl From<tungstenite::Error> for Error {
    fn from(err: tungstenite::Error) -> Self {
        Error::Config(err.to_string())
    }
}

/// Operation modes for the application
#[derive(Debug)]
enum OperationMode {
    /// Participate in the signing committee
    Committee,
    /// Operate as a signing service
    Service(String),
    /// Run as a WebSocket server
    Server,
}

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Run in committee mode, participating in the signing committee
    #[arg(long, conflicts_with_all = ["message", "server_mode"])]
    committee: bool,

    /// Message to be signed (initiates signing mode)
    #[arg(short, long, conflicts_with_all = ["committee", "server_mode"])]
    message: Option<String>,

    /// Run as WebSocket server
    #[arg(long, conflicts_with_all = ["committee", "message", "party_id"])]
    server_mode: bool,

    /// Local party ID for this instance
    #[arg(short, long)]
    party_id: Option<u16>,

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
    let mode = if args.server_mode {
        OperationMode::Server
    } else if args.committee {
        OperationMode::Committee
    } else if let Some(msg) = args.message.clone() {
        OperationMode::Service(msg)
    } else {
        return Err(Error::Config(
            "Either --committee, --message, or --server-mode must be specified".into(),
        ));
    };

    match mode {
        OperationMode::Server => {
            run_server_mode(&args.server).await?;
        }
        _ => {
            let party_id = args.party_id.ok_or_else(|| {
                Error::Config("Party ID is required for committee and service modes".into())
            })?;

            // Select operating mode
            match mode {
                OperationMode::Committee => {
                    run_committee_mode(args.server, party_id).await?;
                }
                OperationMode::Service(message) => {
                    run_service_mode(args.server, party_id, message).await?;
                }
                OperationMode::Server => unreachable!(),
            }
        }
    }

    Ok(())
}

/// Runs the application in server mode, handling WebSocket connections
async fn run_server_mode(server_addr: &str) -> Result<(), Error> {
    // If the address starts with "ws://", remove it for TCP binding
    let bind_addr = server_addr
        .trim_start_matches("ws://")
        .trim_start_matches("wss://");

    println!("Starting WebSocket server on {}", bind_addr);

    // Parse the server address
    let addr = bind_addr
        .parse()
        .map_err(|e| Error::Config(format!("Invalid server address: {}", e)))?;

    // Create and run the WebSocket server
    let server = server::WsServer::new(addr);

    println!("WebSocket server listening for connections...");

    // Run the server (this blocks until shutdown)
    server.run().await.map_err(Error::Server)?;

    Ok(())
}

/// Runs the application in server mode, handling WebSocket connections
pub async fn run_committee_mode(server_addr: String, party_id: u16) -> Result<(), Error> {
    println!("Starting committee mode. Party: {}", party_id);

    // Create and run the service
    let mut protocol =
        protocol::Protocol::new(party_id).map_err(|e| Error::Protocol(e.to_string())).await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    protocol.start(server_addr, party_id).await?;

    Ok(())
}
