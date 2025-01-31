use crate::message::{NetworkMessage, WireMessage};
use crate::network::{NetworkError, StreamDelivery};
use crate::p2p_node::{MessageType, P2PNode};
use futures::{Sink, Stream, StreamExt};
use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, mpsc::unbounded_channel};

/// Error types specific to P2P stream operations
#[derive(Debug, thiserror::Error)]
pub enum P2PStreamError {
    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Node error: {0}")]
    Node(#[from] crate::p2p_node::P2PError),
}

/// A wrapper around P2P communication that implements Stream + Sink for Vec<u8>
pub struct P2PBinaryStream {
    node: Arc<P2PNode>,
    to_network_receiver: mpsc::UnboundedReceiver<NetworkMessage>,
    from_node_sender: mpsc::UnboundedSender<Vec<u8>>,
    party_id: u16,
    session_id: u16,
}

impl P2PBinaryStream {
    /// Creates a new P2P stream connection
    pub async fn new(
        node: Arc<P2PNode>,
        party_id: u16,
        session_id: u16,
    ) -> Result<Self, P2PStreamError> {
        let (to_network_sender, to_network_receiver) = unbounded_channel::<NetworkMessage>();
        let (from_node_sender, mut from_node_receiver) = unbounded_channel::<Vec<u8>>();

        // Subscribe to P2P messages
        node.subscribe_to_session(party_id, session_id, from_node_sender.clone())
            .await
            .map_err(P2PStreamError::Node)?;

        // Spawn task to convert P2PMessage to NetworkMessage
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

        Ok(Self {
            node,
            to_network_receiver,
            from_node_sender,
            party_id,
            session_id,
        })
    }
}

impl Stream for P2PBinaryStream {
    type Item = Result<NetworkMessage, P2PStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(Pin::new(&mut self.to_network_receiver).poll_recv(cx)) {
            Some(data) => Poll::Ready(Some(Ok(data))),
            None => Poll::Ready(None),
        }
    }
}

impl Sink<NetworkMessage> for P2PBinaryStream {
    type Error = P2PStreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: NetworkMessage) -> Result<(), Self::Error> {
        match item {
            NetworkMessage::WireMessage(wire_msg) => self
                .node
                .publish_message(
                    &wire_msg,
                    wire_msg.receiver,
                    self.session_id,
                )
                .map_err(P2PStreamError::Node),
            NetworkMessage::SessionMessage(_) => Ok(()),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for P2PBinaryStream {
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

/// Wrapper around P2PBinaryStream that handles NetworkMessage conversion
pub struct MessageStream {
    inner: P2PBinaryStream,
}

impl MessageStream {
    pub async fn new(
        node: Arc<P2PNode>,
        party_id: u16,
        session_id: u16,
    ) -> Result<Self, P2PStreamError> {
        Ok(Self {
            inner: P2PBinaryStream::new(node, party_id, session_id).await?,
        })
    }
}

impl Stream for MessageStream {
    type Item = Result<NetworkMessage, P2PStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => Poll::Ready(Some(Ok(msg))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<NetworkMessage> for MessageStream {
    type Error = P2PStreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready_unpin(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, msg: NetworkMessage) -> Result<(), Self::Error> {
        self.inner.start_send_unpin(msg)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush_unpin(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close_unpin(cx)
    }
}

/// Type alias for StreamDelivery using P2P transport
pub type P2PDelivery<M> = StreamDelivery<M, MessageStream, P2PStreamError>;

impl<M> P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static,
{
    pub async fn connect(
        node: Arc<P2PNode>,
        party_id: u16,
        session: impl Into<u16>,
    ) -> Result<Self, NetworkError> {
        let session = session.into();
        StreamDelivery::new(
            MessageStream::new(node, party_id, session)
                .await
                .map_err(|e| NetworkError::Connection(e.to_string()))?,
            party_id,
            session,
        )
        .await
    }
}
