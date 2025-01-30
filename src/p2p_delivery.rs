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
    party_id: u16,
    session_id: u16,
    receiver: UnboundedReceiver<Incoming<M>>,
    sender: UnboundedSender<Incoming<M>>,
}

impl<M> P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static + Clone,
{
    pub async fn new(
        node: &Arc<P2PNode>,
        party_id: u16,
        session_id: impl Into<u16>,
    ) -> Result<Self, P2PError> {
        let session_id = session_id.into();
        let (sender, receiver) = unbounded_channel();

        // Subscribe to both broadcast and P2P topics
        node.subscribe_to_session(party_id, session_id, sender.clone()).await?;

        Ok(Self {
            node: Arc::clone(node),
            party_id,
            session_id,
            receiver,
            sender,
        })
    }
}

impl<M> Delivery<M> for P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin + Send + 'static + Clone,
{
    type Send = Self;
    type Receive = Self;
    type SendError = P2PError;
    type ReceiveError = P2PError;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.clone(), self)
    }
}

// Implement Stream trait
impl<M> Stream for P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + Clone + 'static,
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

// Implement Unpin to make Stream implementation simpler
impl<M> Unpin for P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + Clone + 'static,
{
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

impl<M> Sink<Outgoing<M>> for P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Send + 'static,
{
    type Error = P2PError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Outgoing<M>) -> Result<(), Self::Error> {
        let recipient = match item.recipient {
            MessageDestination::OneParty(id) => Some(id),
            MessageDestination::AllParties => None,
        };

        self.node.publish_message(&item.msg, recipient, self.session_id)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}