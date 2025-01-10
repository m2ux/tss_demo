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

use crate::network::WireMessage;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, RwLock},
};
use tokio_tungstenite::{
    accept_async,
    tungstenite::Message,
};
use futures::{StreamExt, SinkExt};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};
use tracing::{info, warn, error};

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
#[derive(Debug)]
struct ClientSession {
    party_id: u16,
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
    addr: SocketAddr,
}

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
    pub fn new(addr: SocketAddr) -> Self {
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
    pub async fn run(&self) -> Result<(), ServerError> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("WebSocket server listening on: {}", self.addr);

        while let Ok((stream, addr)) = listener.accept().await {
            let clients = Arc::clone(&self.clients);
            info!("New connection from: {}", addr);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, addr, clients).await {
                    error!("Error handling connection from {}: {}", addr, e);
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
    async fn handle_connection(
        stream: TcpStream,
        _addr: SocketAddr,
        clients: Arc<RwLock<HashMap<u16, ClientSession>>>,
    ) -> Result<(), ServerError> {
        let ws_stream = accept_async(stream).await?;
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // Handle party ID registration
        let party_id = match ws_receiver.next().await {
            Some(Ok(msg)) => {
                if let Some(id) = String::from_utf8(msg.into_data())
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                {
                    id
                } else {
                    return Err(ServerError::Registration("Invalid party ID format".into()));
                }
            }
            _ => return Err(ServerError::Registration("Failed to receive party ID".into())),
        };

        // Set up client session
        let (tx, mut rx) = mpsc::unbounded_channel();

        // Register client in shared registry
        {
            let mut clients_lock = clients.write().await;
            if clients_lock.contains_key(&party_id) {
                return Err(ServerError::Registration("Party ID already registered".into()));
            }

            clients_lock.insert(party_id, ClientSession {
                party_id,
                sender: tx,
            });

            info!("Registered client with party ID: {}", party_id);
        }

        // Spawn message handling tasks
        let clients_for_receiver = Arc::clone(&clients);
        let receiver_handle = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_receiver.next().await {
                if let Message::Binary(data) = msg {
                    Self::handle_message(party_id, data, &clients_for_receiver).await;
                }
            }
        });

        let sender_handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if ws_sender.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Wait for either handler to complete
        tokio::select! {
            _ = receiver_handle => {},
            _ = sender_handle => {},
        }

        // Clean up client registration
        {
            let mut clients_lock = clients.write().await;
            clients_lock.remove(&party_id);
            info!("Unregistered client with party ID: {}", party_id);
        }

        Ok(())
    }

    /// Handles message routing and delivery.
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
    async fn handle_message(
        sender_id: u16,
        data: Vec<u8>,
        clients: &Arc<RwLock<HashMap<u16, ClientSession>>>,
    ) {
        if let Ok(wire_msg) = bincode::deserialize::<WireMessage>(&data) {
            let clients_lock = clients.read().await;

            match wire_msg.receiver {
                Some(receiver_id) => {
                    if let Some(session) = clients_lock.get(&receiver_id) {
                        let _ = session.sender.send(Message::Binary(data));
                    } else {
                        warn!("Recipient {} not found for P2P message", receiver_id);
                    }
                },
                None => {
                    for (id, session) in clients_lock.iter() {
                        if *id != sender_id {
                            let _ = session.sender.send(Message::Binary(data.clone()));
                        }
                    }
                }
            }
        } else {
            error!("Failed to deserialize message from party {}", sender_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio_tungstenite::connect_async;
    use futures::SinkExt;

    /// Tests basic server startup functionality
    #[tokio::test]
    async fn test_server_startup() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = WsServer::new(addr);

        tokio::spawn(async move {
            server.run().await.expect("Server failed to run");
        });
    }

    /// Tests client connection and party ID registration
    #[tokio::test]
    async fn test_client_connection() -> Result<(), Box<dyn std::error::Error>> {
        // Start server
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = WsServer::new(server_addr);
        let actual_addr = TcpListener::bind(server_addr).await?.local_addr()?;

        tokio::spawn(async move {
            server.run().await.expect("Server failed to run");
        });

        // Connect client
        let url = format!("ws://{}", actual_addr);
        let (mut ws_stream, _) = connect_async(url).await?;

        // Send party ID
        ws_stream.send(Message::Binary(b"1".to_vec())).await?;

        Ok(())
    }
}