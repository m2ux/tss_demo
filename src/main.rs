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

mod committee;
mod error;
mod message;
mod network;
mod p2p;
mod p2p_behaviour;
mod p2p_node;
mod server;
mod service;
mod signing;
mod storage;
mod websocket;

use crate::error::Error;
use crate::p2p_node::P2PNode;
use crate::service::Service;
use clap::{Parser, Subcommand, ValueEnum};
use env_logger::{Builder, Env};
use log::info;
use log::LevelFilter;
use std::time::Duration;

#[derive(Clone, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

// Implementation to convert LogLevel to LevelFilter
impl LogLevel {
    fn to_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Set the log level (default: info)
    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run in bootstrap mode (previously server mode)
    Bootstrap,
    /// Run in committee mode
    Committee {
        /// Party ID for this node
        #[arg(short, long)]
        party_id: u16,
    },
    /// Run in service mode
    Service,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    Builder::from_env(Env::default().default_filter_or("info"))
        .filter_level(cli.log_level.to_level_filter())
        .init();

    // Fixed bootstrap addresses
    let bootstrap_addresses = vec![format!("/ip4/127.0.0.1/tcp/{}", 8000)];

    match cli.command {
        Command::Bootstrap => {
            run_bootstrap_mode(bootstrap_addresses).await?;
        }
        Command::Committee { party_id } => {
            run_committee_mode(party_id, bootstrap_addresses).await?;
        }
        Command::Service => {
            run_service_mode(bootstrap_addresses).await?;
        }
    }

    Ok(())
}

async fn run_bootstrap_mode(addresses: Vec<String>) -> Result<(), Error> {
    info!("Starting bootstrap node");
    info!("Listening and advertising on: {:?}", addresses);

    let _ = P2PNode::connect(None, addresses, "cggmp".to_string())
        .await
        .map_err(|e| Error::Config(format!("Failed to initialize P2P node: {}", e)))?;

    tokio::time::sleep(Duration::from_secs(20)).await;
    info!("Bootstrap complete");
    Ok(())
}

async fn run_committee_mode(party_id: u16, bootstrap_addresses: Vec<String>) -> Result<(), Error> {
    println!("Starting committee mode. Party: {}", party_id);
    println!("Bootstrap addresses: {:?}", bootstrap_addresses);

    let node_port = 10334 + party_id;
    let p2p_node = P2PNode::connect(
        Some(bootstrap_addresses),
        vec![format!("/ip4/127.0.0.1/tcp/{}", node_port)],
        "cggmp".to_string(),
    )
    .await
    .map_err(|e| Error::Config(format!("Failed to initialize P2P node: {}", e)))?;

    // Create and run the service
    let mut committee_protocol = committee::Protocol::new(party_id, p2p_node).await?;
    tokio::time::sleep(Duration::from_secs(10)).await;
    committee_protocol.start().await
}

pub async fn run_service_mode(
    bootstrap_addresses: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting signing process");
    let node_port = 10334 + 10;
    let p2p_node = P2PNode::connect(
        Some(bootstrap_addresses),
        vec![format!("/ip4/0.0.0.0/tcp/{}", node_port)],
        "cggmp".to_string(),
    )
    .await
    .map_err(|e| Error::Config(format!("Failed to initialize P2P node: {}", e)))?;

    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut service = Service::new(10, p2p_node).await?;
    service.run().await?;

    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("Signing request sent successfully");
    Ok(())
}
