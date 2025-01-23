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

use crate::network::{MessageState, WireMessage};
use futures::channel::{mpsc, mpsc::unbounded};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

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

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PartySession {
    pub party_id: u16,
    pub session_id: u16,
}

/// Message types for server-client communication
#[derive(Serialize, Deserialize)]
pub enum ServerMessage {
    /// Register with party ID
    Register {
        session: PartySession,
    },
    Unregister {
        session: PartySession,
    },
}

/// Represents a connected client session in the WebSocket server.
///
/// This struct maintains the state and communication channels for an individual
/// client connection. Each session is identified by the client's party ID and
/// maintains a dedicated message channel for sending data to the client.
///
/// # Fields
///
/// * `sender` - Channel for sending messages to this client
/// Represents a connected client session
struct ClientSession {
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
pub struct WsServer {
    /// Thread-safe registry of connected clients
    clients: Arc<RwLock<HashMap<PartySession, ClientSession>>>,

    message_state: Arc<RwLock<MessageState>>,

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
            message_state: Arc::new(RwLock::new(MessageState::new())),
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
            let message_state = Arc::clone(&self.message_state);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, addr, clients, message_state).await
                {
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
        clients: Arc<RwLock<HashMap<PartySession, ClientSession>>>,
        _message_state: Arc<RwLock<MessageState>>,
    ) -> Result<(), ServerError> {
        let ws_stream = accept_async(stream).await?;
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        let (tx, mut rx) = unbounded();

        // Wait for registration or other message
        let party_session = loop {
            match ws_receiver.next().await {
                Some(Ok(msg)) => {
                    if let Message::Binary(data) = msg {
                        match bincode::deserialize::<ServerMessage>(&data) {
                            Ok(ServerMessage::Register { session }) => {
                                // Handle registration
                                let mut clients_lock = clients.write().await;
                                if clients_lock.contains_key(&session) {
                                    return Err(ServerError::Registration(format!(
                                        "[S{}] Party {} already registered",
                                        &session.session_id, &session.party_id
                                    )));
                                }

                                clients_lock.insert(session.clone(), ClientSession { sender: tx });

                                println!(
                                    "[S{}] Registered party {}",
                                    &session.session_id, session.party_id
                                );
                                break session;
                            }
                            Ok(ServerMessage::Unregister { session }) => {
                                let _ = Self::unregister_client(&session, &clients).await;
                                return Ok(());
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

        // Handle incoming messages
        let clients_for_receiver = Arc::clone(&clients);
        let _receiver_handle = tokio::spawn({
            let party_session = party_session.clone();
            async move {
                while let Some(Ok(msg)) = ws_receiver.next().await {
                    if let Message::Binary(data) = msg {

                        // Try to deserialize as WireMessage (Protocol Message)
                        if let Ok(wire_msg) = bincode::deserialize::<WireMessage>(&data) {
                            Self::handle_client_message(
                                &party_session,
                                wire_msg,
                                &clients_for_receiver,
                            )
                            .await;
                            continue;
                        }

                        // Try to deserialize as ServerMessage
                        if let Ok(server_msg) = bincode::deserialize::<ServerMessage>(&data) {
                            Self::handle_server_message(
                                &party_session,
                                server_msg,
                                &clients_for_receiver,
                            )
                            .await;
                            continue;
                        }

                        println!(
                            "Unable to deserialize message from party {}, session {}",
                            &party_session.party_id, &party_session.session_id
                        );
                    }
                }
                /*println!(
                    "Receiver loop ended for party {}, session {}",
                    &party_session.party_id, &party_session.session_id
                );*/
            }
        });

        // Forward messages from channel to WebSocket
        let _sender_handle = tokio::spawn({
            let party_session = party_session.clone();
            async move {
                while let Some(msg) = rx.next().await {
                    if (ws_sender.send(msg).await).is_err() {
                        /*println!(
                            "Failed to send message to party {}, session {}: {}",
                            &party_session.party_id, &party_session.session_id, e
                        );*/
                        let _ = Self::unregister_client(&party_session, &clients).await;
                        break;
                    }
                }
                /*println!(
                    "Sender loop ended for party {}, session {}",
                    &party_session.party_id, &party_session.session_id
                );*/
            }
        });

        Ok(())
    }

    /// Handles server-specific messages
    async fn handle_server_message(
        _party_session: &PartySession,
        msg: ServerMessage,
        clients: &Arc<RwLock<HashMap<PartySession, ClientSession>>>,
    ) {
        //println!("Handling server message from party {}", sender_id);
        match msg {
            ServerMessage::Register { session } => {
                println!(
                    "[S{}] Party {} already registered!",
                    &session.session_id, &session.party_id
                );
            }
            ServerMessage::Unregister { session } => {
                let _ = Self::unregister_client(&session, clients).await;
            }
        }
    }

    /// Handles client messages
    async fn handle_client_message(
        party_session: &PartySession,
        wire_msg: WireMessage,
        clients: &Arc<RwLock<HashMap<PartySession, ClientSession>>>,
    ) {
        //println!("Handling client message from party {}, {:?}", sender_id, &wire_msg);
        let clients_lock = clients.read().await;

        match wire_msg.receiver {
            // P2P message
            Some(receiver_id) => {
                println!(
                    "[S{}] P2P message from {} to {}",
                    &party_session.session_id, &party_session.party_id, receiver_id
                );

                if let Some(client_session) = clients_lock.get(&PartySession {
                    party_id: receiver_id,
                    session_id: party_session.session_id,
                }) {
                    let encoded =
                        bincode::serialize(&wire_msg).expect("Failed to serialize wire message");
                    let _ = client_session
                        .sender
                        .unbounded_send(Message::Binary(encoded));
                } else {
                    println!("Recipient {} not found for P2P message", receiver_id);
                }
            }
            // Broadcast message
            None => {
                for (session, client_session) in clients_lock.iter() {
                    if session.party_id != party_session.party_id
                        && session.session_id == party_session.session_id
                    {
                        println!(
                            "[S{}] Broadcast from party {}",
                            session.session_id, session.party_id
                        );
                        let encoded = bincode::serialize(&wire_msg)
                            .expect("Failed to serialize wire message");
                        let _ = client_session
                            .sender
                            .unbounded_send(Message::Binary(encoded));
                    }
                }
            }
        }
    }

    /// Unregisters a client session from the server.
    ///
    /// # Arguments
    ///
    /// * `session` - The party session to unregister
    /// * `clients` - The shared client registry
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if unregistration was successful, regardless of whether
    /// the client was actually registered.
    async fn unregister_client(
        session: &PartySession,
        clients: &Arc<RwLock<HashMap<PartySession, ClientSession>>>,
    ) -> Result<(), ServerError> {
        let mut clients_lock = clients.write().await;
        if clients_lock.remove(session).is_some() {
            println!(
                "[S{}] Unregistered party {}",
                &session.session_id, session.party_id
            );
        }
        Ok(())
    }
}
