use futures::{Stream, Sink, StreamExt, SinkExt};
use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream, MaybeTlsStream};
use tokio::net::TcpStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use serde::{Deserialize, Serialize};
use crate::network::StreamDelivery;
use crate::error::Error;

/// A wrapper around WebSocket stream that implements Stream + Sink for Vec<u8>
pub struct WebSocketBinaryStream {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WebSocketBinaryStream {
    /// Creates a new WebSocket stream connection
    ///
    /// # Arguments
    ///
    /// * `url` - WebSocket server URL (e.g., "ws://localhost:8080")
    ///
    /// # Returns
    ///
    /// Returns a new WebSocketBinaryStream ready for use with StreamDelivery
    pub async fn connect(url: &str) -> Result<Self, tokio_tungstenite::tungstenite::Error> {
        let (ws_stream, _) = connect_async(url).await?;
        Ok(Self { inner: ws_stream })
    }
}

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

/// Type alias for websocket message delivery with generic message type
pub type WsDelivery<M> =
StreamDelivery<M, WebSocketBinaryStream, tokio_tungstenite::tungstenite::Error>;

impl<M> WsDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static,
{
    /// Creates a new committee message delivery instance
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