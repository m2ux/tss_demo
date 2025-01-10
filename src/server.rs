//! WebSocket server implementation for CGGMP21 protocol network communication.
//!
//! This module provides a WebSocket server that handles message routing and delivery
//! for the distributed protocol implementation. It supports both peer-to-peer and
//! broadcast messages while maintaining message ordering guarantees.
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

/// Represents a connected client session
struct ClientSession {
    /// Party ID of the connected client
    party_id: u16,
    /// Channel for sending messages to the client
    sender: mpsc::UnboundedSender<Message>,
}

/// WebSocket server for handling protocol communication
pub struct WsServer {
    /// Map of connected clients indexed by their party ID
    clients: Arc<RwLock<HashMap<u16, ClientSession>>>,
    /// Server address to bind to
    addr: SocketAddr,
}

/// Errors that can occur in the WebSocket server
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Network-related errors
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// WebSocket protocol errors
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Client registration errors
    #[error("Client registration error: {0}")]
    Registration(String),
}

impl WsServer {
    /// Creates a new WebSocket server instance
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind the server to
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            addr,
        }
    }

    /// Starts the WebSocket server
    ///
    /// This method initiates the server and begins accepting connections.
    /// It runs indefinitely until the server is shut down.
    ///
    /// # Errors
    ///
    /// Returns `ServerError` if the server fails to start or encounters
    /// errors during operation.
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

    /// Handles an individual client connection
    ///
    /// # Arguments
    ///
    /// * `stream` - TCP stream for the connection
    /// * `addr` - Client's socket address
    /// * `clients` - Shared map of connected clients
    async fn handle_connection(
        stream: TcpStream,
        addr: SocketAddr,
        clients: Arc<RwLock<HashMap<u16, ClientSession>>>,
    ) -> Result<(), ServerError> {
        let ws_stream = accept_async(stream).await?;
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // Wait for initial message containing party ID
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

        // Create message channel for this client
        let (tx, mut rx) = mpsc::unbounded_channel();

        // Register client
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

        // Handle incoming messages
        let clients_for_receiver = Arc::clone(&clients);
        let receiver_handle = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_receiver.next().await {
                if let Message::Binary(data) = msg {
                    Self::handle_message(party_id, data, &clients_for_receiver).await;
                }
            }
        });

        // Forward messages to client
        let sender_handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if ws_sender.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Wait for either handle to complete (connection closed or error)
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

    /// Handles an incoming message and routes it to appropriate recipients
    ///
    /// # Arguments
    ///
    /// * `sender_id` - Party ID of the message sender
    /// * `data` - Raw message data
    /// * `clients` - Shared map of connected clients
    async fn handle_message(
        sender_id: u16,
        data: Vec<u8>,
        clients: &Arc<RwLock<HashMap<u16, ClientSession>>>,
    ) {
        // Attempt to deserialize the message
        if let Ok(wire_msg) = bincode::deserialize::<WireMessage>(&data) {
            let clients_lock = clients.read().await;

            match wire_msg.receiver {
                // P2P message
                Some(receiver_id) => {
                    if let Some(session) = clients_lock.get(&receiver_id) {
                        let _ = session.sender.send(Message::Binary(data));
                    } else {
                        warn!("Recipient {} not found for P2P message", receiver_id);
                    }
                },
                // Broadcast message
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

/// Example usage
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio_tungstenite::connect_async;
    use futures::SinkExt;

    #[tokio::test]
    async fn test_server_startup() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = WsServer::new(addr);

        tokio::spawn(async move {
            server.run().await.expect("Server failed to run");
        });
    }

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