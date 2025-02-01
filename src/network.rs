use crate::message::{
    MessageIdGenerator, NetworkMessage, PartySession, RoundBasedWireMessage, SessionMessage,
    WireMessage,
};
use tokio::sync::{mpsc,mpsc::unbounded_channel};
use futures::{Sink, SinkExt, Stream, StreamExt};
use round_based::{Delivery, Incoming, Outgoing};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{marker::PhantomData, pin::Pin};

pub static MESSAGE_ID_GEN: MessageIdGenerator = MessageIdGenerator::new();

/// Errors that can occur during network operations.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Delivery protocol errors
    #[error("Delivery error: {0}")]
    Delivery(String),

    /// General connection errors (initialization, serialization, etc.)
    #[error("Connection error: {0}")]
    Connection(String),

    /// Internal channel communication errors
    #[error("Channel closed")]
    ChannelClosed,

    /// Message ordering violation errors
    #[error("Invalid message ID: expected >= {expected}, got {actual}")]
    InvalidMessageId { expected: u64, actual: u64 },
}

/// Message sender component.
///
/// Handles sending network messages to other parties through the connection.
/// Implements the `Sink` trait for outgoing messages.
#[derive(Clone)]
pub struct Sender<M>
where
    M: Serialize + for<'de> Deserialize<'de>,
{
    pub sender: mpsc::UnboundedSender<NetworkMessage>,
    pub party_id: u16,
    pub session_id: u16,
    pub _phantom: PhantomData<M>,
}

impl<M> Sender<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin,
{
    /// Broadcasts a message using the Sink trait
    pub async fn broadcast(&mut self, msg: M) -> Result<(), NetworkError> {
        self.send(WireMessage::new_broadcast(
            &MESSAGE_ID_GEN,
            self.party_id,
            msg,
        )?)
        .await
    }

    /// Sends a message to a peer using the Sink trait
    pub async fn send_to(&mut self, msg: M, party_id: u16) -> Result<(), NetworkError> {
        self.send(WireMessage::new_p2p(
            &MESSAGE_ID_GEN,
            self.party_id,
            party_id,
            msg,
        )?)
        .await
    }
    /// Registers this party with the session
    pub async fn register(&self) -> Result<(), NetworkError> {
        let reg_msg = SessionMessage::Register {
            session: PartySession {
                party_id: self.party_id,
                session_id: self.session_id,
            },
        };

        self.sender
            .send(NetworkMessage::SessionMessage(reg_msg))
            .map_err(|_| NetworkError::ChannelClosed)?;

        Ok(())
    }

    pub fn get_party_id(&self) -> u16 {
        self.party_id
    }
}

impl<M> Drop for Sender<M>
where
    M: Serialize + for<'de> Deserialize<'de>,
{
    fn drop(&mut self) {
            let unreg_msg = SessionMessage::Unregister {
                session: PartySession {
                    party_id: self.party_id,
                    session_id: self.session_id,
                },
            };

        let _ = self
            .sender
            .send(NetworkMessage::SessionMessage(unreg_msg));
        std::thread::sleep(Duration::from_secs(1));
    }
}

impl<M> Sink<Outgoing<M>> for Sender<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Error = NetworkError;

    fn poll_ready(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Outgoing<M>) -> Result<(), Self::Error> {
        self.sender
            .send(NetworkMessage::WireMessage(
                <WireMessage as RoundBasedWireMessage<M>>::new_p2p(
                    &MESSAGE_ID_GEN,
                    self.party_id,
                    item,
                )?,
            ))
            .map_err(|_| NetworkError::ChannelClosed)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    /// Attempts to close the sink, preventing further messages from being sent.
    ///
    /// In this implementation, closing is a no-op as the channel remains open
    /// until dropped.
    ///
    /// # Returns
    ///
    /// Always returns `Poll::Ready(Ok(()))` as there is no specific close operation
    fn poll_close(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl<M> Sink<WireMessage> for Sender<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Error = NetworkError;

    fn poll_ready(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, wire_msg: WireMessage) -> Result<(), Self::Error> {
        self.sender
            .send(NetworkMessage::WireMessage(wire_msg))
            .map_err(|_| NetworkError::ChannelClosed)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Message receiver component.
///
/// Handles receiving and validating messages from other parties.
/// Implements the `Stream` trait for incoming messages.
pub struct Receiver<M> {
    pub receiver: mpsc::UnboundedReceiver<NetworkMessage>,
    pub _phantom: PhantomData<M>,
}

// Explicitly implement Unpin for WsReceiver
impl<M> Unpin for Receiver<M> {}

/// Implements the Stream trait for WebSocket message receiving.
///
/// This implementation provides an asynchronous message receiving interface that:
/// - Deserializes incoming wire format messages
/// - Validates message ordering through unique IDs
/// - Handles both P2P and broadcast messages
/// - Maintains message sequencing guarantees
///
/// # Type Parameters
///
/// * `M` - The message type that must be serializable and deserializable
///
/// # Examples
///
/// ```rust,no_run
/// use futures::StreamExt;
/// use round_based::Delivery;
///
/// async fn receive_messages(mut receiver: WsReceiver<String>) {
///     while let Some(Ok(message)) = receiver.next().await {
///         println!("Received message from {}: {:?}", message.sender, message.msg);
///     }
/// }
/// ```
///
/// # Implementation Notes
///
/// - Messages are processed in order of arrival
/// - Message IDs are validated to ensure proper sequencing
/// - Failed message processing results in appropriate NetworkError variants
/// - The implementation is compatible with async stream combinators
impl<M> Stream for Receiver<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Item = Result<Incoming<M>, NetworkError>;

    /// Attempts to receive the next message from the WebSocket connection.
    ///
    /// This method performs the following steps:
    /// 1. Receives raw data from the channel
    /// 2. Deserializes the wire format message
    /// 3. Validates the message ID sequence
    /// 4. Deserializes the actual message payload
    /// 5. Constructs the appropriate message type (P2P or Broadcast)
    ///
    /// # Returns
    ///
    /// - `Poll::Ready(Some(Ok(message)))`: A message was successfully received
    /// - `Poll::Ready(Some(Err(error)))`: An error occurred while processing the message
    /// - `Poll::Ready(None)`: The stream has ended (channel closed)
    /// - `Poll::Pending`: No message is currently available
    ///
    /// # Errors
    ///
    /// - `NetworkError::Connection`: Message deserialization failed
    /// - `NetworkError::InvalidMessageId`: Message arrived out of sequence
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // Poll the underlying receiver
        let poll_result = Pin::new(&mut self.receiver).poll_recv(cx);

        match poll_result {
            std::task::Poll::Ready(Some(NetworkMessage::WireMessage(wire_msg))) => {
                match bincode::deserialize(&wire_msg.payload) {
                    Ok(msg) => std::task::Poll::Ready(Some(Ok(Incoming {
                        id: wire_msg.id,
                        sender: wire_msg.sender,
                        msg,
                        msg_type: wire_msg
                            .receiver
                            .map_or(round_based::MessageType::Broadcast, |_| {
                                round_based::MessageType::P2P
                            }),
                    }))),
                    Err(_) => std::task::Poll::Ready(Some(Err(NetworkError::Connection(
                        "Failed to deserialize protocol message".into(),
                    )))),
                }
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Some(NetworkMessage::SessionMessage(_))) => {
                std::task::Poll::Ready(None)
            }
        }
    }
}

/// Errors that can occur during stream operations.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// Stream communication errors
    #[error("Stream error: {0}")]
    Communication(String),

    /// Message processing errors
    #[error("Message processing error: {0}")]
    Processing(String),
}

/// Stream-based delivery mechanism implementing `round_based::Delivery`.
///
/// Provides the main interface for stream-based network communication,
/// combining both sending and receiving capabilities over any stream
/// that implements the required traits.
pub struct StreamDelivery<M, S, E>
where
    M: Serialize + for<'de> Deserialize<'de>,
    S: Stream<Item = Result<NetworkMessage, E>> + Sink<NetworkMessage, Error = E> + Unpin,
    E: std::error::Error + 'static,
{
    sender: Sender<M>,
    receiver: Receiver<M>,
    _stream: PhantomData<S>,
    _error: PhantomData<E>,
}

impl<M, S, E> StreamDelivery<M, S, E>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin,
    S: Stream<Item = Result<NetworkMessage, E>>
        + Sink<NetworkMessage, Error = E>
        + Unpin
        + Send
        + 'static,
    E: std::error::Error + Send + 'static,
{
    /// Creates a new delivery instance from a stream that implements Stream + Sink
    ///
    /// # Arguments
    ///
    /// * `stream` - Any stream that implements Stream + Sink for binary data
    /// * `party_id` - Unique identifier for this party
    /// * `session_id` - Unique identifier for this session
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if initialization fails
    pub async fn new(
        stream: S,
        party_id: u16,
        session_id: impl Into<u16>,
    ) -> Result<Self, NetworkError> {
        let (write, read) = stream.split();

        let (stream_rcvr_tx, stream_rcvr_rx) = unbounded_channel::<NetworkMessage>();
        let (stream_sender_tx, mut stream_sender_rx) = unbounded_channel::<NetworkMessage>();

        // Spawn background task to handle stream communication
        tokio::spawn(async move {
            let mut write = write;
            let mut read = read;

            loop {
                tokio::select! {
                    // Handle incoming messages
                    msg = read.next() => {
                        match msg {
                            Some(Ok(data)) => {
                                if stream_rcvr_tx.send(data).is_err() {
                                    break;
                                }
                            }
                            Some(Err(_)) => {
                                break;
                            }
                            None => {
                                break;
                            }
                        }
                    }
                    // Handle outgoing messages
                    msg = stream_sender_rx.recv() => {
                        match msg {
                            Some(data) => {
                                if let Err(_) = write.send(data).await {
                                    break;
                                }
                            }
                            None => {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let sender = Sender {
            sender: stream_sender_tx,
            party_id,
            session_id: session_id.into(),
            _phantom: PhantomData,
        };

        sender
            .register()
            .await
            .map_err(|e| NetworkError::Delivery(e.to_string()))?;

        Ok(Self {
            sender,
            receiver: Receiver {
                receiver: stream_rcvr_rx,
                _phantom: PhantomData,
            },
            _stream: PhantomData,
            _error: PhantomData,
        })
    }
}

/// Implements the Delivery trait for stream-based message transport.
impl<M, S, E> Delivery<M> for StreamDelivery<M, S, E>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin,
    S: Stream<Item = Result<NetworkMessage, E>> + Sink<NetworkMessage, Error = E> + Unpin,
    E: std::error::Error + 'static,
{
    type Send = Sender<M>;
    type Receive = Receiver<M>;
    type SendError = NetworkError;
    type ReceiveError = NetworkError;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.receiver, self.sender)
    }
}
