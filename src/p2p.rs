use crate::message::NetworkMessage;
use crate::network::{NetworkError, StreamDelivery};
use crate::p2p_node::{MessageType, P2PMessage, P2PNode};
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
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    message_sender: mpsc::UnboundedSender<P2PMessage>,
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
        let (sender, receiver) = unbounded_channel();
        let (message_sender, mut message_receiver) = unbounded_channel();

        // Subscribe to P2P messages
        node.subscribe_to_session(party_id, session_id, message_sender.clone())
            .await
            .map_err(P2PStreamError::Node)?;

        // Spawn task to convert NetworkMessage to Vec<u8>
        tokio::spawn({
            let sender = sender.clone();
            async move {
                while let Some(msg) = message_receiver.recv().await {
                    let _ = sender.send(msg.data);
                }
            }
        });

        Ok(Self {
            node,
            receiver,
            message_sender,
            party_id,
            session_id,
        })
    }
}

impl Stream for P2PBinaryStream {
    type Item = Result<Vec<u8>, P2PStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(Pin::new(&mut self.receiver).poll_recv(cx)) {
            Some(data) => Poll::Ready(Some(Ok(data))),
            None => Poll::Ready(None),
        }
    }
}

impl Sink<Vec<u8>> for P2PBinaryStream {
    type Error = P2PStreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        // Wrap Vec<u8> in NetworkMessage and publish
        let msg = P2PMessage {
            data: item,
            msg_type: MessageType::Broadcast, // Default to broadcast, can be adjusted based on needs
        };

        self.node
            .publish_message(&msg, None, self.session_id)
            .map_err(P2PStreamError::Node)
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
            Poll::Ready(Some(Ok(bytes))) => match bincode::deserialize(&bytes) {
                Ok(msg) => Poll::Ready(Some(Ok(msg))),
                Err(_) => Poll::Ready(Some(Err(P2PStreamError::Stream(
                    "Failed to deserialize message".into(),
                )))),
            },
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

    fn start_send(mut self: Pin<&mut Self>, item: NetworkMessage) -> Result<(), Self::Error> {
        let bytes = bincode::serialize(&item)
            .map_err(|_| P2PStreamError::Stream("Failed to serialize message".into()))?;
        self.inner.start_send_unpin(bytes)
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
