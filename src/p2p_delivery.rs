use crate::network::WireMessage;
use crate::p2p_node::{P2PError, P2PNode};
use futures::{Sink, Stream};
use round_based::{Delivery, Incoming, MessageDestination, Outgoing};
use serde::{Deserialize, Serialize};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub struct P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
{
    node: Arc<P2PNode>,
    session_id: u16,
    party_id: u16,
    receiver: UnboundedReceiver<Incoming<M>>,
    sender: UnboundedSender<Incoming<M>>,
}

impl<M> P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
{
    pub async fn new<T>(node: &Arc<P2PNode>, party_id: u16, session_id: T) -> Result<Self, P2PError>
    where
        T: Into<u16> + Clone,
    {
        let node = Arc::clone(node);
        let (sender, receiver) = unbounded_channel();

        // Subscribe and register session
        node.subscribe_and_register(party_id, session_id.clone().into(), sender.clone())
            .await?;

        Ok(Self {
            node,
            session_id: session_id.into(),
            party_id,
            receiver,
            sender,
        })
    }
}

impl<M> Unpin for P2PDelivery<M> where M: Serialize + for<'de> Deserialize<'de> + Send + 'static {}

impl<M> Stream for P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
{
    type Item = Result<Incoming<M>, P2PError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(incoming)) => Poll::Ready(Some(Ok(incoming))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<M> Sink<Outgoing<M>> for P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
{
    type Error = P2PError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Outgoing<M>) -> Result<(), Self::Error> {
        let wire_msg = WireMessage {
            id: crate::network::MESSAGE_ID_GEN.next_id(),
            sender: self.party_id,
            receiver: match item.recipient {
                MessageDestination::OneParty(id) => Some(id),
                MessageDestination::AllParties => None,
            },
            payload: bincode::serialize(&item.msg)
                .map_err(|e| P2PError::Protocol(format!("Serialization error: {}", e)))?,
        };

        let encoded = bincode::serialize(&wire_msg)
            .map_err(|e| P2PError::Protocol(format!("Wire message serialization error: {}", e)))?;

        let topic = P2PNode::get_topic(self.party_id, self.session_id);
        self.node.publish(&topic, encoded)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl<M> Clone for P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
{
    fn clone(&self) -> Self {
        let (_sender, receiver) = unbounded_channel();
        Self {
            node: Arc::clone(&self.node),
            session_id: self.session_id,
            party_id: self.party_id,
            receiver,
            sender: self.sender.clone(),
        }
    }
}

impl<M> Delivery<M> for P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static,
{
    type Send = Self;
    type Receive = Self;
    type SendError = P2PError;
    type ReceiveError = P2PError;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.clone(), self)
    }
}
