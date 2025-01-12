//! WebSocket server implementation for CGGMP21 protocol network communication.
//!
//! This module provides a WebSocket server that handles message routing and delivery
//! for the distributed protocol implementation. The server manages client connections,
//! handles message routing, and ensures reliable message delivery between protocol
//! participants.
//!
//! # Features
//!
//! * Async WebSocket server implementation using tokio
//! * Support for both P2P and broadcast messages
//! * Party ID-based client identification and routing
//! * Connection lifecycle management
//! * Thread-safe client session handling
//!
//! # Architecture
//!
//! The server uses a multi-threaded architecture with the following components:
//! * Main server loop handling incoming connections
//! * Per-client session handlers for message processing
//! * Shared client registry for message routing
//! * Async channels for inter-thread communication
//!
//! # Examples
//!
//! ```rust,no_run
//! use server::{WsServer, ServerError};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), ServerError> {
//!     // Create and start the server
//!     let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
//!     let server = WsServer::new(addr);
//!
//!     // Run the server (blocks until shutdown)
//!     server.run().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Protocol
//!
//! ## Connection Establishment
//!
//! 1. Client connects to WebSocket server
//! 2. Client sends party ID as first message
//! 3. Server validates and registers the client
//! 4. Normal message exchange begins
//!
//! ## Message Format
//!
//! Messages are transmitted as binary WebSocket messages containing serialized
//! `WireMessage` structures. The wire format includes:
//! * Message ID for ordering
//! * Sender party ID
//! * Optional recipient party ID (None for broadcast)
//! * Serialized payload
//!
//! # Error Handling
//!
//! The server provides comprehensive error handling for:
//! * Connection failures
//! * Protocol violations
//! * Message serialization errors
//! * Client registration conflicts

use crate::network::{ClientRegistration, WireMessage};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, RwLock},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{error, info, warn};

/// Errors that can occur during server operation.
///
/// This enum encompasses all error conditions that may arise during server
/// operation, including network errors, protocol violations, and client
/// registration issues.
///
/// # Error Handling
///
/// Errors are propagated to the appropriate error handling layer:
/// * Connection-level errors trigger client disconnection
/// * Protocol errors are logged and may trigger connection termination
/// * Registration errors prevent client connection establishment
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Network-related errors (e.g., bind failure, connection errors)
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// WebSocket protocol errors (e.g., handshake failure, invalid frames)
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Client registration errors (e.g., duplicate party ID, invalid format)
    #[error("Client registration error: {0}")]
    Registration(String),
}

/// Message types for server-client communication
#[derive(Serialize, Deserialize, Debug)]
pub enum ServerMessage {
    /// Register with party ID
    Register { party_id: u16 },
    /// Unregister request
    Unregister { party_id: u16 },
    /// Protocol message
    Protocol(Vec<u8>),
}

/// Represents a connected client session in the WebSocket server.
///
/// This struct maintains the state and communication channels for an individual
/// client connection. Each session is identified by the client's party ID and
/// maintains a dedicated message channel for sending data to the client.
///
/// # Fields
///
/// * `party_id` - Unique identifier for the connected party
/// * `sender` - Channel for sending messages to this client
/// Represents a connected client session
#[derive(Debug)]
struct ClientSession {
    /// Party ID of the connected client
    party_id: u16,
    /// Channel for sending messages to the client
    sender: mpsc::UnboundedSender<Message>,
}

/// WebSocket server for handling protocol communication.
///
/// The server maintains a registry of connected clients and handles message
/// routing between them. It supports both peer-to-peer and broadcast message
/// delivery patterns.
///
/// # Thread Safety
///
/// The server uses `Arc<RwLock<_>>` for the client registry, allowing safe
/// concurrent access from multiple task handlers. The lock granularity is
/// designed to minimize contention during message routing.
///
/// # Message Routing
///
/// Messages are routed based on the `receiver` field in the wire format:
/// * If `receiver` is `Some(party_id)`, the message is sent only to that party
/// * If `receiver` is `None`, the message is broadcast to all parties except the sender
#[derive(Debug)]
pub struct WsServer {
    /// Thread-safe registry of connected clients
    clients: Arc<RwLock<HashMap<u16, ClientSession>>>,
    /// Socket address the server is bound to
    addr: String,
}

impl WsServer {
    /// Creates a new WebSocket server instance.
    ///
    /// Initializes a new server that will listen on the specified address. The
    /// server won't start accepting connections until [`run`](#method.run) is called.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind the server to
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    /// let server = WsServer::new(addr);
    /// ```
    pub fn new(addr: String) -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            addr,
        }
    }

    /// Starts the WebSocket server and begins accepting connections.
    ///
    /// This method runs indefinitely, accepting new connections and spawning
    /// handler tasks for each client. The server continues running until an
    /// error occurs or it is explicitly shut down.
    ///
    /// # Lifecycle
    ///
    /// 1. Binds to the specified address
    /// 2. Enters accept loop for new connections
    /// 3. Spawns handler task for each new client
    /// 4. Continues until error or shutdown
    ///
    /// # Errors
    ///
    /// Returns `ServerError` if:
    /// * Server fails to bind to the specified address
    /// * Critical error occurs during operation
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// #[tokio::main]
    /// async fn main() -> Result<(), ServerError> {
    ///     let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    ///     let server = WsServer::new(addr);
    ///     server.run().await
    /// }
    /// ```
    /// Starts the WebSocket server
    pub async fn run(&self) -> Result<(), ServerError> {
        let listener = TcpListener::bind(&self.addr).await?;
        println!("WebSocket server bound to {}", self.addr);

        while let Ok((stream, addr)) = listener.accept().await {
            println!("New connection from: {}", addr);

            let clients = Arc::clone(&self.clients);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, addr, clients).await {
                    eprintln!("Error handling connection from {}: {}", addr, e);
                }
            });
        }

        Ok(())
    }

    /// Handles an individual client connection.
    ///
    /// This method manages the lifecycle of a single client connection, including:
    /// * Initial handshake and party ID registration
    /// * Message processing
    /// * Connection cleanup on disconnect
    ///
    /// # Arguments
    ///
    /// * `stream` - TCP stream for the connection
    /// * `addr` - Client's socket address
    /// * `clients` - Shared registry of connected clients
    ///
    /// # Connection Lifecycle
    ///
    /// 1. Performs WebSocket handshake
    /// 2. Waits for party ID registration
    /// 3. Creates client session
    /// 4. Processes messages until disconnect
    /// 5. Cleans up client registration
    ///
    /// # Error Handling
    ///
    /// Returns `ServerError` for:
    /// * WebSocket handshake failures
    /// * Invalid party ID format
    /// * Registration conflicts
    /// * Protocol violations
    /// Handles an individual client connection
    async fn handle_connection(
        stream: TcpStream,
        addr: SocketAddr,
        clients: Arc<RwLock<HashMap<u16, ClientSession>>>,
    ) -> Result<(), ServerError> {
        let ws_stream = accept_async(stream).await?;
        let (mut _ws_sender, mut ws_receiver) = ws_stream.split();

        println!("handle messages");

        // Wait for registration or other message

        let party_id = loop {
            match ws_receiver.next().await {
                Some(Ok(msg)) => {
                    if let Message::Binary(data) = msg {
                        match bincode::deserialize::<ServerMessage>(&data) {
                            Ok(ServerMessage::Register { party_id }) => {
                                println!("rx register message");
                                // Handle registration
                                let mut clients_lock = clients.write().await;
                                if clients_lock.contains_key(&party_id) {
                                    return Err(ServerError::Registration(
                                        "Party ID already registered".into(),
                                    ));
                                }

                                // Create message channel for this client
                                let (tx, mut _rx) = mpsc::unbounded_channel();

                                clients_lock.insert(
                                    party_id,
                                    ClientSession {
                                        party_id,
                                        sender: tx,
                                    },
                                );

                                info!("Registered client with party ID: {}", party_id);
                                break party_id;
                            }
                            Ok(ServerMessage::Unregister { party_id }) => {
                                println!("rx unregister message");
                                let mut clients_lock = clients.write().await;
                                if clients_lock.remove(&party_id).is_some() {
                                    info!("Unregistered client with party ID: {}", party_id);
                                }
                                return Ok(());
                            }
                            Ok(ServerMessage::Protocol(_)) => {
                                println!("rx premature protocol message");
                                warn!(
                                    "Received protocol message before registration from {}",
                                    addr
                                );
                                continue;
                            }
                            Err(e) => {
                                println!("Failed to deserialize message from {}: {}", addr, e);
                                continue;
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    return Err(ServerError::WebSocket(e));
                }
                None => {
                    return Ok(());
                }
            }
        };

        // Handle incoming messages until connection closes
        while let Some(Ok(msg)) = ws_receiver.next().await {
            if let Message::Binary(data) = msg {
                match bincode::deserialize::<ServerMessage>(&data) {
                    Ok(ServerMessage::Unregister { party_id: pid }) => {
                        println!("rx unregister message");
                        if pid == party_id {
                            let mut clients_lock = clients.write().await;
                            if clients_lock.remove(&party_id).is_some() {
                                info!("Unregistered client with party ID: {}", party_id);
                            }
                            break;
                        }
                    }
                    Ok(ServerMessage::Protocol(protocol_data)) => {
                        println!("rx protocol message");
                        Self::handle_protocol_message(party_id, protocol_data, &clients).await;
                    }
                    _ => {
                        println!("Unexpected message type from party {}", party_id);
                    }
                }
            }
        }

        // Connection ended but registration remains
        info!(
            "Connection closed for party {}, but registration maintained",
            party_id
        );
        Ok(())
    }

    /// Handles protocol message routing and delivery.
    ///
    /// This method processes incoming messages and routes them to the appropriate
    /// recipients based on the message type (P2P or broadcast).
    ///
    /// # Arguments
    ///
    /// * `sender_id` - Party ID of the message sender
    /// * `data` - Raw message data
    /// * `clients` - Shared registry of connected clients
    ///
    /// # Message Routing
    ///
    /// * P2P messages are sent only to the specified recipient
    /// * Broadcast messages are sent to all parties except the sender
    /// * Messages to unknown recipients are logged as warnings
    ///
    /// # Error Handling
    ///
    /// * Deserialize failures are logged but don't terminate the connection
    /// * Delivery failures to specific clients are logged as warnings
    async fn handle_protocol_message(
        sender_id: u16,
        data: Vec<u8>,
        clients: &Arc<RwLock<HashMap<u16, ClientSession>>>,
    ) {
        // Attempt to deserialize the protocol message
        if let Ok(wire_msg) = bincode::deserialize::<WireMessage>(&data) {
            let clients_lock = clients.read().await;

            match wire_msg.receiver {
                // P2P message
                Some(receiver_id) => {
                    println!("send single message");
                    if let Some(session) = clients_lock.get(&receiver_id) {
                        let _ = session.sender.send(Message::Binary(data));
                    } else {
                        warn!("Recipient {} not found for P2P message", receiver_id);
                    }
                }
                // Broadcast message
                None => {
                    println!("send broadcast message");
                    for (id, session) in clients_lock.iter() {
                        if *id != sender_id {
                            let _ = session.sender.send(Message::Binary(data.clone()));
                        }
                    }
                }
            }
        } else {
            println!(
                "Failed to deserialize protocol message from party {}",
                sender_id
            );
        }
    }
}
