use crate::error::Error;
use crate::message::NetworkMessage;
use crate::network::{NetworkError, StreamDelivery};
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

/// Custom error type for WebSocket operations
#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    #[error("Connection error: {0}")]
    Connection(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Connection closed")]
    Closed,
}

/// A WebSocket stream that directly handles NetworkMessage conversion
pub struct WebSocketMessageStream {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WebSocketMessageStream {
    /// Creates a new WebSocket connection
    pub async fn connect(url: &str) -> Result<Self, WebSocketError> {
        let (ws_stream, _) = connect_async(url).await?;
        Ok(Self { inner: ws_stream })
    }

    /// Helper method to handle incoming WebSocket messages
    fn handle_message(msg: Message) -> Result<Option<NetworkMessage>, WebSocketError> {
        match msg {
            Message::Binary(data) => {
                bincode::deserialize(&data)
                    .map(Some)
                    .map_err(WebSocketError::Serialization)
            }
            Message::Text(text) => {
                bincode::deserialize(text.as_bytes())
                    .map(Some)
                    .map_err(WebSocketError::Serialization)
            }
            Message::Close(_) => Ok(None),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Ok(None),
        }
    }
}

impl Stream for WebSocketMessageStream {
    type Item = Result<NetworkMessage, WebSocketError>;

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

impl Sink<NetworkMessage> for WebSocketMessageStream {
    type Error = WebSocketError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready_unpin(cx)
            .map_err(WebSocketError::Connection)
    }

    fn start_send(mut self: Pin<&mut Self>, item: NetworkMessage) -> Result<(), Self::Error> {
        let data = bincode::serialize(&item)?;
        self.inner
            .start_send_unpin(Message::Binary(data))
            .map_err(WebSocketError::Connection)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_flush_unpin(cx)
            .map_err(WebSocketError::Connection)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_close_unpin(cx)
            .map_err(WebSocketError::Connection)
    }
}

/// Type alias for StreamDelivery using WebSocket transport
pub type WsDelivery<M> = StreamDelivery<M, WebSocketMessageStream, WebSocketError>;

impl<M> WsDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static,
{
    /// Creates a new WebSocket delivery instance
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