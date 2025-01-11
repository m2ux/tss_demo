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
mod storage;

use cggmp21::{
    keygen::ThresholdMsg, security_level::SecurityLevel128, supported_curves::Secp256k1,
};
use clap::Parser;
use error::Error;
use futures_util::{SinkExt, StreamExt};
use network::WsDelivery;
use protocol::run_committee_mode;
use service::run_service_mode;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use storage::KeyStorage;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_tungstenite::accept_async;

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
            // Create a new TCP listener
            let listener = TcpListener::bind(&args.server).await?;
            println!("WebSocket server listening on {}", args.server);

            // Shared state for connected clients
            let clients = Arc::new(RwLock::new(HashMap::<
                std::net::SocketAddr,
                tokio::sync::mpsc::UnboundedSender<tungstenite::Message>,
            >::new()));

            // Accept incoming connections
            while let Ok((stream, addr)) = listener.accept().await {
                println!("New connection from: {}", addr);
                let ws_stream = accept_async(stream).await?;
                let client_clients = Arc::clone(&clients);

                // Spawn a new task for each connection
                tokio::spawn(async move {
                    let (mut _write, mut read) = ws_stream.split();

                    // Handle messages from this client
                    while let Some(Ok(msg)) = read.next().await {
                        let clients = client_clients.read().await;
                        // Broadcast message to all other clients
                        for client_sink in clients.values() {
                            let _ = client_sink.send(msg.clone());
                        }
                    }

                    // Clean up disconnected client
                    client_clients.write().await.remove(&addr);
                    println!("Client disconnected: {}", addr);
                });
            }
        }
        _ => {
            let party_id = args.party_id.ok_or_else(|| {
                Error::Config("Party ID is required for committee and service modes".into())
            })?;

            // Initialize storage
            let storage =
                KeyStorage::new("keys", "a very secret key that should be properly secured")?;

            // Initialize network connection
            type Msg = ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>;
            let delivery = WsDelivery::<Msg>::connect(&args.server, party_id).await?;

            // Select operating mode
            match mode {
                OperationMode::Committee => {
                    run_committee_mode(delivery, storage, party_id).await?;
                }
                OperationMode::Service(message) => {
                    run_service_mode(delivery, storage, party_id, message).await?;
                }
                OperationMode::Server => unreachable!(),
            }
        }
    }

    Ok(())
}