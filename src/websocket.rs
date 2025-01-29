//! WebSocket-based stream implementation for network communication.
//!
//! This module provides WebSocket-specific functionality for the delivery system,
//! implementing the necessary Stream and Sink traits for WebSocket connections.
//! It handles binary and text message conversion, connection management, and
//! integration with the wider delivery framework.
use futures::{Stream, Sink, StreamExt, SinkExt};
use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream, MaybeTlsStream};
use tokio::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use serde::{Deserialize, Serialize};
use crate::network::StreamDelivery;
use crate::error::Error;

/// A wrapper around WebSocket stream that implements Stream + Sink for Vec<u8>.
///
/// Provides a binary-focused interface over the WebSocket protocol, automatically
/// handling conversion between WebSocket messages and raw bytes. This allows
/// the WebSocket connection to be used with the generic delivery system.
pub struct WebSocketBinaryStream {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WebSocketBinaryStream {
    /// Creates a new WebSocket stream connection.
    ///
    /// Establishes a connection to a WebSocket server and wraps it in a
    /// WebSocketBinaryStream for use with the delivery system.
    ///
    /// # Arguments
    ///
    /// * `url` - WebSocket server URL (e.g., "ws://localhost:8080")
    ///
    /// # Returns
    ///
    /// Returns a Result containing the new WebSocketBinaryStream or a WebSocket error.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use your_crate::WebSocketBinaryStream;
    ///
    /// async fn example() {
    ///     let stream = WebSocketBinaryStream::connect("ws://localhost:8080")
    ///         .await
    ///         .expect("Failed to connect");
    /// }
    /// ```
    pub async fn connect(url: &str) -> Result<Self, tokio_tungstenite::tungstenite::Error> {
        let (ws_stream, _) = connect_async(url).await?;
        Ok(Self { inner: ws_stream })
    }
}

/// Stream implementation for WebSocketBinaryStream.
///
/// Converts WebSocket messages to Vec<u8>, handling both binary and text messages.
/// Non-data messages (ping, pong, close) are handled appropriately in the message
/// stream.
impl Stream for WebSocketBinaryStream {
    type Item = Result<Vec<u8>, tokio_tungstenite::tungstenite::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                match msg {
                    Message::Binary(data) => Poll::Ready(Some(Ok(data))),
                    Message::Text(text) => Poll::Ready(Some(Ok(text.into_bytes()))),
                    Message::Close(_) => Poll::Ready(None),
                    _ => self.poll_next(cx), // Skip other message types
                }
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Sink implementation for WebSocketBinaryStream.
///
/// Converts Vec<u8> to WebSocket binary messages for transmission.
/// Handles the WebSocket protocol details while presenting a simple
/// binary interface to the delivery system.
impl Sink<Vec<u8>> for WebSocketBinaryStream {
    type Error = tokio_tungstenite::tungstenite::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(Message::Binary(item))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}

/// Type alias for websocket message delivery with generic message type.
///
/// Combines the StreamDelivery system with WebSocketBinaryStream to provide
/// a WebSocket-specific delivery implementation.
///
/// # Type Parameters
///
/// * `M` - The message type that will be serialized and sent over the WebSocket
pub type WsDelivery<M> =
StreamDelivery<M, WebSocketBinaryStream, tokio_tungstenite::tungstenite::Error>;

impl<M> WsDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static,
{
    /// Creates a new message delivery instance using WebSocket transport.
    ///
    /// Establishes a WebSocket connection and initializes the delivery system
    /// for the specified party and session.
    ///
    /// # Arguments
    ///
    /// * `server_addr` - WebSocket server address (e.g., "ws://localhost:8080")
    /// * `party_id` - Unique identifier for this party
    /// * `session` - Session identifier or type
    ///
    /// # Returns
    ///
    /// Returns a Result containing the new WsDelivery instance or an error.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use your_crate::WsDelivery;
    ///
    /// async fn example() {
    ///     let delivery = WsDelivery::<MyMessage>::connect(
    ///         "ws://localhost:8080",
    ///         1,
    ///         1
    ///     ).await.expect("Failed to create delivery");
    /// }
    /// ```
    pub async fn connect(
        server_addr: &str,
        party_id: u16,
        session: impl Into<u16>,
    ) -> Result<Self, Error> {
        Ok(StreamDelivery::new(
            WebSocketBinaryStream::connect(server_addr).await?,
            party_id,
            session,
        )
            .await?)
    }
}