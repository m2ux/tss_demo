//! WebSocket transport layer for network message delivery.
//!
//! This module provides WebSocket-based communication capabilities that implement
//! the Stream and Sink traits for NetworkMessage types. It includes automatic
//! serialization/deserialization of messages and error handling.
//!
//! # Architecture
//!
//! The module is structured around three main components:
//! * WebSocketMessageStream - Core WebSocket message handling
//! * WebSocketError - WebSocket-specific error types
//! * WsDelivery - Delivery implementation using WebSocket transport
//!
//! # Example
//!
//! ```rust,no_run
//! use crate::websocket::WsDelivery;
//!
//! async fn example() -> Result<(), Error> {
//!     let delivery = WsDelivery::connect(
//!         "ws://localhost:8080",
//!         1,  // party_id
//!         1   // session_id
//!     ).await?;
//!
//!     // Use delivery for message exchange
//!     Ok(())
//! }
//! ```
use crate::error::Error;
use crate::message::NetworkMessage;
use crate::network::{NetworkError, StreamDelivery};
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

/// Custom error types specific to WebSocket operations.
///
/// Provides detailed error context for WebSocket-related failures,
/// including connection, serialization, and protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    /// Underlying WebSocket connection errors
    #[error("Connection error: {0}")]
    Connection(#[from] tokio_tungstenite::tungstenite::Error),

    /// Message serialization/deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    /// Protocol-level errors (invalid message format, etc.)
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Connection closed by peer or network failure
    #[error("Connection closed")]
    Closed,
}

/// A WebSocket stream implementation that handles NetworkMessage conversion.
///
/// Wraps a tokio-tungstenite WebSocket stream and provides automatic
/// serialization/deserialization of NetworkMessage types. Implements both
/// Stream and Sink traits for message processing.
pub struct WebSocketMessageStream {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WebSocketMessageStream {
    /// Creates a new WebSocket connection to the specified URL.
    ///
    /// # Arguments
    /// * `url` - WebSocket server URL to connect to
    ///
    /// # Returns
    /// A Result containing the new WebSocketMessageStream or an error
    ///
    /// # Errors
    /// Returns WebSocketError if:
    /// * Connection fails
    /// * TLS handshake fails (if using wss://)
    /// * WebSocket handshake fails
    pub async fn connect(url: &str) -> Result<Self, WebSocketError> {
        let (ws_stream, _) = connect_async(url).await?;
        Ok(Self { inner: ws_stream })
    }

    /// Processes an incoming WebSocket message.
    ///
    /// Handles binary and text messages, converting them to NetworkMessage.
    /// Control messages (ping/pong) are filtered out.
    ///
    /// # Arguments
    /// * `msg` - Raw WebSocket message to process
    ///
    /// # Returns
    /// * `Ok(Some(NetworkMessage))` - Successfully converted message
    /// * `Ok(None)` - Control message that should be skipped
    /// * `Err(WebSocketError)` - Conversion error
    fn handle_message(msg: Message) -> Result<Option<NetworkMessage>, WebSocketError> {
        match msg {
            Message::Binary(data) => bincode::deserialize(&data)
                .map(Some)
                .map_err(WebSocketError::Serialization),
            Message::Text(text) => bincode::deserialize(text.as_bytes())
                .map(Some)
                .map_err(WebSocketError::Serialization),
            Message::Close(_) => Ok(None),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Ok(None),
        }
    }
}

/// Stream implementation for WebSocketMessageStream.
///
/// Provides asynchronous iteration over incoming NetworkMessages.
/// Automatically handles message conversion and error propagation.
impl Stream for WebSocketMessageStream {
    type Item = Result<NetworkMessage, WebSocketError>;

    /// Polls for the next message from the WebSocket connection.
    ///
    /// Handles message conversion and filters control messages.
    ///
    /// # Returns
    /// * `Poll::Ready(Some(Ok(msg)))` - New message available
    /// * `Poll::Ready(Some(Err(e)))` - Error occurred
    /// * `Poll::Ready(None)` - Connection closed
    /// * `Poll::Pending` - No message currently available
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.inner.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    match Self::handle_message(msg) {
                        Ok(Some(network_msg)) => return Poll::Ready(Some(Ok(network_msg))),
                        Ok(None) => continue, // Skip control messages
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(WebSocketError::Connection(e))))
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Sink implementation for WebSocketMessageStream.
///
/// Enables sending NetworkMessages over the WebSocket connection
/// with automatic serialization.
impl Sink<NetworkMessage> for WebSocketMessageStream {
    type Error = WebSocketError;

    /// Checks if the sink is ready to accept a new message.
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready_unpin(cx)
            .map_err(WebSocketError::Connection)
    }

    /// Initiates sending of a NetworkMessage.
    ///
    /// Serializes the message and converts it to a WebSocket binary message.
    ///
    /// # Arguments
    /// * `item` - NetworkMessage to send
    ///
    /// # Errors
    /// Returns WebSocketError if:
    /// * Serialization fails
    /// * Connection is closed
    /// * Send buffer is full
    fn start_send(mut self: Pin<&mut Self>, item: NetworkMessage) -> Result<(), Self::Error> {
        let data = bincode::serialize(&item)?;
        self.inner
            .start_send_unpin(Message::Binary(data))
            .map_err(WebSocketError::Connection)
    }

    /// Attempts to flush pending messages to the network.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_flush_unpin(cx)
            .map_err(WebSocketError::Connection)
    }

    /// Attempts to close the sink with graceful shutdown.
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_close_unpin(cx)
            .map_err(WebSocketError::Connection)
    }
}

/// Type alias for StreamDelivery using WebSocket transport.
///
/// Provides a WebSocket-based implementation of the StreamDelivery trait
/// for network message exchange.
pub type WsDelivery<M> = StreamDelivery<M, WebSocketMessageStream, WebSocketError>;

impl<M> WsDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static,
{
    /// Creates a new WebSocket delivery instance.
    ///
    /// Establishes a WebSocket connection and initializes the delivery
    /// system for the specified party and session.
    ///
    /// # Arguments
    /// * `server_addr` - WebSocket server address
    /// * `party_id` - Unique identifier for this party
    /// * `session` - Session identifier
    ///
    /// # Returns
    /// A Result containing the new WsDelivery instance or an error
    ///
    /// # Errors
    /// Returns Error if:
    /// * WebSocket connection fails
    /// * Message delivery initialization fails
    pub async fn connect(
        server_addr: &str,
        party_id: u16,
        session: impl Into<u16>,
    ) -> Result<Self, Error> {
        let session_id = session.into();
        let stream = WebSocketMessageStream::connect(server_addr)
            .await
            .map_err(|e| NetworkError::Connection(e.to_string()))?;

        StreamDelivery::new(stream, party_id, session_id)
            .await
            .map_err(Error::Network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use tokio_test::block_on;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    // Helper function to create a test NetworkMessage
    fn create_test_message() -> NetworkMessage {
        // Note: You'll need to implement this based on your NetworkMessage structure
        unimplemented!("Implement based on your NetworkMessage type")
    }

    #[test]
    fn test_websocket_error_display() {
        let conn_err = WebSocketError::Connection(
            tungstenite::Error::ConnectionClosed
        );
        assert!(format!("{}", conn_err).contains("Connection error"));

        let proto_err = WebSocketError::Protocol("Invalid message".to_string());
        assert!(format!("{}", proto_err).contains("Protocol error"));
    }

    #[tokio::test]
    async fn test_handle_message_binary() {
        let test_msg = create_test_message();
        let binary_data = bincode::serialize(&test_msg).unwrap();
        let ws_msg = WsMessage::Binary(binary_data);

        match WebSocketMessageStream::handle_message(ws_msg) {
            Ok(Some(msg)) => {
                // Compare msg with test_msg
                // You'll need to implement comparison based on your NetworkMessage type
            }
            _ => panic!("Expected Some(NetworkMessage)"),
        }
    }

    #[tokio::test]
    async fn test_handle_message_control() {
        let ping = WsMessage::Ping(vec![]);
        assert!(matches!(
            WebSocketMessageStream::handle_message(ping),
            Ok(None)
        ));

        let pong = WsMessage::Pong(vec![]);
        assert!(matches!(
            WebSocketMessageStream::handle_message(pong),
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn test_handle_message_close() {
        let close = WsMessage::Close(None);
        assert!(matches!(
            WebSocketMessageStream::handle_message(close),
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn test_handle_message_invalid() {
        let invalid_data = vec![1, 2, 3]; // Invalid serialized data
        let ws_msg = WsMessage::Binary(invalid_data);

        match WebSocketMessageStream::handle_message(ws_msg) {
            Err(WebSocketError::Serialization(_)) => (),
            _ => panic!("Expected serialization error"),
        }
    }

    // Mock WebSocket Stream for testing
    struct MockWebSocket {
        messages: Vec<Result<WsMessage, tokio_tungstenite::tungstenite::Error>>,
    }

    impl MockWebSocket {
        fn new(messages: Vec<Result<WsMessage, tokio_tungstenite::tungstenite::Error>>) -> Self {
            Self { messages }
        }
    }

    impl Stream for MockWebSocket {
        type Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.messages.pop())
        }
    }

    #[tokio::test]
    async fn test_stream_implementation() {
        // Test implementation here using MockWebSocket
    }

    #[tokio::test]
    async fn test_sink_implementation() {
        // Test implementation here using MockWebSocket
    }

    #[tokio::test]
    async fn test_delivery_connect() {
        // Test WsDelivery connect method
        // Note: This will require mocking the WebSocket connection
    }
}