// In websocket.rs

use crate::error::Error;
use crate::message::NetworkMessage;
use crate::network::StreamDelivery;
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

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
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Implement Sink trait directly
impl Sink<Vec<u8>> for WebSocketBinaryStream {
    type Error = tokio_tungstenite::tungstenite::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(Message::Binary(item))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Wrapper around WebSocketBinaryStream that handles NetworkMessage conversion
pub struct MessageStream {
    inner: WebSocketBinaryStream,
}

impl MessageStream {
    /// Creates a new MessageStream
    pub async fn connect(url: &str) -> Result<Self, tokio_tungstenite::tungstenite::Error> {
        Ok(Self {
            inner: WebSocketBinaryStream::connect(url).await?,
        })
    }
}

impl Stream for MessageStream {
    type Item = Result<NetworkMessage, tokio_tungstenite::tungstenite::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                match bincode::deserialize(&bytes) {
                    Ok(msg) => Poll::Ready(Some(Ok(msg))),
                    Err(_) => Poll::Ready(Some(Err(tungstenite::Error::Protocol(
                        tungstenite::error::ProtocolError::ResetWithoutClosingHandshake, // Use appropriate error
                    )))),
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<NetworkMessage> for MessageStream {
    type Error = tokio_tungstenite::tungstenite::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: NetworkMessage) -> Result<(), Self::Error> {
        let bytes = bincode::serialize(&item).map_err(|_| {
            tungstenite::Error::Protocol(
                tungstenite::error::ProtocolError::ResetWithoutClosingHandshake, // Use appropriate error
            )
        })?;
        self.inner.start_send_unpin(bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}

// Update the WsDelivery type alias to use MessageStream
pub type WsDelivery<M> = StreamDelivery<M, MessageStream, tokio_tungstenite::tungstenite::Error>;

// Update the connect method
impl<M> WsDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static,
{
    pub async fn connect(
        server_addr: &str,
        party_id: u16,
        session: impl Into<u16>,
    ) -> Result<Self, Error> {
        Ok(StreamDelivery::new(
            MessageStream::connect(server_addr).await?,
            party_id,
            session,
        )
        .await?)
    }
}
