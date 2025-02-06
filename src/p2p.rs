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
    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Node error: {0}")]
    Node(#[from] crate::p2p_node::P2PError),
}

/// A P2P message stream implementing Stream + Sink for NetworkMessage
pub struct P2PMessageStream {
    node: Arc<P2PNode>,
    to_network_receiver: mpsc::UnboundedReceiver<NetworkMessage>,
    to_node_sender: mpsc::UnboundedSender<NetworkMessage>,
    party_id: u16,
    session_id: u16,
}

impl P2PMessageStream {
    /// Creates a new P2P stream connection
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

impl Stream for P2PMessageStream {
    type Item = Result<NetworkMessage, P2PStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(Pin::new(&mut self.to_network_receiver).poll_recv(cx)) {
            Some(data) => Poll::Ready(Some(Ok(data))),
            None => Poll::Ready(None),
        }
    }
}

impl Sink<NetworkMessage> for P2PMessageStream {
    type Error = P2PStreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: NetworkMessage) -> Result<(), Self::Error> {
        // Send the message to the background task instead of publishing directly
        self.to_node_sender
            .send(item)
            .map_err(|_| P2PStreamError::Stream("Failed to send message to publishing task".into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

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
