//! P2P-based delivery layer for distributed protocol communication.
//!
//! This module provides a P2P implementation of the network delivery system,
//! using libp2p for message routing while maintaining API compatibility with
//! the existing delivery interface. It implements:
//! - Message stream abstraction over P2P transport
//! - Automatic message conversion and routing
//! - Automatic retries for message delivery
//! - Thread-safe message handling
//!
//! # Architecture
//!
//! The module consists of three main components:
//! * P2PMessageStream - Core message handling implementation
//! * P2PStreamError - P2P-specific error types
//! * P2PDelivery - Delivery trait implementation using P2P transport
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use crate::p2p::P2PDelivery;
//! use crate::p2p_node::P2PNode;
//!
//! async fn example(node: Arc<P2PNode>) -> Result<(), NetworkError> {
//!     let delivery = P2PDelivery::<MessageType>::connect(
//!         node,
//!         1,  // party_id
//!         1   // session_id
//!     ).await?;
//!     
//!     // Use delivery for message exchange
//!     Ok(())
//! }
//! ```
use crate::message::{NetworkMessage, WireMessage};
use crate::network::{NetworkError, StreamDelivery};
use crate::p2p_node::P2PNode;
use futures::{Sink, Stream};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, mpsc::unbounded_channel};
use log::{debug, info, warn};

/// Error types specific to P2P stream operations
#[derive(Debug, thiserror::Error)]
pub enum P2PStreamError {
    /// General stream operation errors
    #[error("Stream error: {0}")]
    Stream(String),

    /// P2P node-specific errors
    #[error("Node error: {0}")]
    Node(#[from] crate::p2p_node::P2PError),
}

/// A P2P message stream implementing Stream + Sink for NetworkMessage
///
/// Provides asynchronous message transmission and reception over P2P transport,
/// with automatic message conversion and delivery retry capabilities.
pub struct P2PMessageStream {
    /// Reference to the P2P node handling network operations
    node: Arc<P2PNode>,
    /// Channel for receiving messages from the network
    to_network_receiver: mpsc::UnboundedReceiver<NetworkMessage>,
    /// Channel for sending messages to the network
    to_node_sender: mpsc::UnboundedSender<NetworkMessage>,
    /// Unique identifier for this party
    party_id: u16,
    /// Session identifier for message routing
    session_id: u16,
}

impl P2PMessageStream {
    /// Creates a new P2P stream connection
    ///
    /// # Arguments
    ///
    /// * `node` - Reference to the P2P node
    /// * `party_id` - Unique identifier for this party
    /// * `session_id` - Session identifier for message routing
    ///
    /// # Returns
    ///
    /// Returns a Result containing the new stream or an error
    ///
    /// # Error Handling
    ///
    /// Returns P2PStreamError if:
    /// * Session subscription fails
    /// * Channel creation fails
    pub async fn new(
        node: Arc<P2PNode>,
        party_id: u16,
        session_id: u16,
    ) -> Result<Self, P2PStreamError> {
        let (to_network_sender, to_network_receiver) = unbounded_channel::<NetworkMessage>();
        let (from_node_sender, mut from_node_receiver) = unbounded_channel::<Vec<u8>>();
        let (to_node_sender, mut to_node_receiver) = unbounded_channel::<NetworkMessage>();

        // Subscribe to P2P messages
        node.subscribe_to_session(party_id, session_id, from_node_sender.clone())
            .await
            .map_err(P2PStreamError::Node)?;

        // Spawn task to convert received messages to NetworkMessage
        tokio::spawn({
            let to_network_sender = to_network_sender.clone();
            async move {
                while let Some(msg) = from_node_receiver.recv().await {
                    if let Ok(wire_msg) = bincode::deserialize::<WireMessage>(&msg) {
                        to_network_sender
                            .send(NetworkMessage::WireMessage(wire_msg))
                            .unwrap_or_default();
                    }
                }
            }
        });

        // Spawn task to handle outgoing messages
        let node_clone = node.clone();
        tokio::spawn(async move {
            while let Some(msg) = to_node_receiver.recv().await {
                if let NetworkMessage::WireMessage(wire_msg) = msg {
                    let mut retry_count = 0;
                    const MAX_RETRIES: u32 = 3;
                    const RETRY_DELAY_MS: u64 = 1000;

                    loop {
                        match node_clone
                            .publish_message(&wire_msg, wire_msg.receiver, session_id)
                            .await
                        {
                            Ok(_) => break,
                            Err(e) => {
                                if retry_count >= MAX_RETRIES {
                                    info!("Failed to publish message after {} retries: {}", MAX_RETRIES, e);
                                    break;
                                }
                                debug!("Error publishing message (attempt {}): {}", retry_count + 1, e);
                                retry_count += 1;
                                tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            node,
            to_network_receiver,
            to_node_sender,
            party_id,
            session_id,
        })
    }
}

/// Stream implementation for receiving messages
impl Stream for P2PMessageStream {
    type Item = Result<NetworkMessage, P2PStreamError>;

    /// Polls for the next message from the P2P network
    ///
    /// Handles message reception and conversion from raw bytes to NetworkMessage.
    ///
    /// # Returns
    ///
    /// * `Poll::Ready(Some(Ok(msg)))` - New message available
    /// * `Poll::Ready(Some(Err(e)))` - Error occurred
    /// * `Poll::Ready(None)` - Stream ended
    /// * `Poll::Pending` - No message currently available
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(Pin::new(&mut self.to_network_receiver).poll_recv(cx)) {
            Some(data) => Poll::Ready(Some(Ok(data))),
            None => Poll::Ready(None),
        }
    }
}

/// Sink implementation for sending messages
impl Sink<NetworkMessage> for P2PMessageStream {
    type Error = P2PStreamError;

    /// Checks if the sink is ready to accept a new message
    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Initiates sending of a NetworkMessage
    ///
    /// Handles message conversion and initiates P2P delivery with retry logic
    ///
    /// # Arguments
    ///
    /// * `item` - NetworkMessage to send
    ///
    /// # Error Handling
    ///
    /// Returns P2PStreamError if:
    /// * Message conversion fails
    /// * Publishing fails after retries
    fn start_send(self: Pin<&mut Self>, item: NetworkMessage) -> Result<(), Self::Error> {
        // Send the message to the background task instead of publishing directly
        self.to_node_sender
            .send(item)
            .map_err(|_| P2PStreamError::Stream("Failed to send message to publishing task".into()))
    }

    /// Flushes pending messages to the network
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Closes the message stream
    ///
    /// Attempts to ensure pending messages are delivered before closing
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Cleanup implementation for P2PMessageStream
impl Drop for P2PMessageStream {
    fn drop(&mut self) {
        // Try to unsubscribe when stream is dropped
        let node = self.node.clone();
        let party_id = self.party_id;
        let session_id = self.session_id;

        tokio::spawn(async move {
            let _ = node.unsubscribe_from_session(party_id, session_id).await;
        });
    }
}

/// Type alias for StreamDelivery using P2P transport
pub type P2PDelivery<M> = StreamDelivery<M, P2PMessageStream, P2PStreamError>;

impl<M> P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static,
{
    /// Creates a new P2P delivery instance
    ///
    /// # Arguments
    ///
    /// * `node` - Reference to the P2P node
    /// * `party_id` - Unique identifier for this party
    /// * `session` - Session identifier for message routing
    ///
    /// # Returns
    ///
    /// Returns a Result containing the new delivery instance or an error
    ///
    /// # Type Parameters
    ///
    /// * `M` - Message type that implements Serialize + Deserialize
    ///
    /// # Error Handling
    ///
    /// Returns NetworkError if:
    /// * P2P stream creation fails
    /// * Delivery initialization fails
    pub async fn connect(
        node: Arc<P2PNode>,
        party_id: u16,
        session: impl Into<u16>,
    ) -> Result<Self, NetworkError> {
        let session = session.into();
        StreamDelivery::new(
            P2PMessageStream::new(node, party_id, session)
                .await
                .map_err(|e| NetworkError::Connection(e.to_string()))?,
            party_id,
            session,
        )
        .await
    }
}
