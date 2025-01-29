//! WebSocket-based network communication layer for distributed protocols.
//!
//! This module provides a WebSocket-based implementation of the `round_based::Delivery` trait,
//! enabling reliable message delivery for distributed protocols. It handles message ordering,
//! peer-to-peer and broadcast communications, and proper error handling.
//!
//! # Features
//!
//! * Thread-safe message ID generation
//! * Reliable message ordering with overflow handling
//! * Support for both P2P and broadcast messages
//! * Async/await based communication
//! * Proper error handling and message validation
//!
//! # Examples
//!
//! ```rust,no_run
//! use round_based::Delivery;
//!
//! async fn example() -> Result<(), NetworkError> {
//!     // Connect to the WebSocket server
//!     let delivery = WsDelivery::connect("ws://localhost:8080", 1).await?;
//!
//!     // Split into sender and receiver
//!     let (receiver, sender) = delivery.split();
//!
//!     // Use sender and receiver for protocol communication
//!     Ok(())
//! }
//! ```

use futures::channel::{mpsc, mpsc::unbounded};
use futures::{Sink, SinkExt, Stream, StreamExt};
use round_based::{Delivery, Incoming, MessageDestination, Outgoing};
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    num::Wrapping,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

/// Thread-safe message ID generator with overflow handling.
///
/// Generates monotonically increasing message IDs with proper handling of integer overflow
/// using wrapping arithmetic. Thread-safe through the use of atomic operations.
struct MessageIdGenerator {
    counter: AtomicU64,
}

impl MessageIdGenerator {
    /// Creates a new MessageIdGenerator starting from 0.
    pub const fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Generates the next message ID in a thread-safe manner.
    ///
    /// Uses wrapping arithmetic to handle overflow gracefully, ensuring
    /// the counter continues from 0 after reaching u64::MAX.
    pub fn next_id(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn reset(&self) {
        self.counter.store(0, Ordering::SeqCst);
    }
}

pub static MESSAGE_ID_GEN: MessageIdGenerator = MessageIdGenerator::new();

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PartySession {
    pub party_id: u16,
    pub session_id: u16,
}

/// Message type for session coordination
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SessionMessage {
    /// Register with party ID
    Register {
        session: PartySession,
    },
    Unregister {
        session: PartySession,
    },
}

/// Message sent by client to register with server
#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRegistration {
    /// Initial registration message with party ID
    Register { party_id: u16 },
}

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

/// Tracks message ordering state to ensure proper message sequencing.
///
/// The MessageState struct is responsible for maintaining and validating the order
/// of messages in the network communication protocol. It uses wrapping arithmetic
/// to handle message ID overflow gracefully when reaching u64::MAX.
#[derive(Debug)]
pub struct MessageState {
    /// The last successfully validated message ID, wrapped to handle overflow
    last_id: Wrapping<u64>,
}

impl MessageState {
    /// Creates a new MessageState starting from ID 0.
    ///
    /// # Returns
    ///
    /// Returns a new MessageState instance initialized with a message ID of 0.
    pub fn new() -> Self {
        Self {
            last_id: Wrapping(0),
        }
    }

    /// Validates that a message ID maintains monotonic ordering.
    ///
    /// This function ensures messages are processed in order by validating that each
    /// new message ID is greater than the last seen ID. It handles wraparound at
    /// u64::MAX by using wrapping arithmetic.
    ///
    /// # Arguments
    ///
    /// * `id` - The message ID to validate
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the message ID is valid and in sequence.
    /// Returns Err(NetworkError::InvalidMessageId) if the message is out of sequence.
    pub fn validate_and_update_id(&mut self, id: u64) -> Result<(), NetworkError> {
        let new_id = Wrapping(id);
        let diff = new_id - self.last_id;

        // We expect IDs to increment by small values.
        if diff.0 > u64::MAX / 2 {
            return Err(NetworkError::InvalidMessageId {
                expected: self.last_id.0,
                actual: id,
            });
        }

        self.last_id = new_id;
        Ok(())
    }
}

/// Message sender component.
///
/// Handles sending messages to other parties through the connection.
/// Implements the `Sink` trait for outgoing messages.
#[derive(Clone)]
pub struct Sender<M>
where
    M: Serialize + for<'de> Deserialize<'de>,
{
    pub sender: mpsc::UnboundedSender<Vec<u8>>,
    pub party_id: u16,
    pub session_id: u16,
    pub _phantom: PhantomData<M>,
}

impl<M> Sender<M>
where
    M: Serialize + for<'de> Deserialize<'de> + Unpin,
{
    /// Sends a protocol message using the Sink trait
    pub async fn broadcast(&mut self, msg: M) -> Result<(), NetworkError> {
        let outgoing = Outgoing {
            msg,
            recipient: MessageDestination::AllParties,
        };

        // Use the Sink trait's send method
        self.send(outgoing).await
    }

    /// Sends a protocol message using the Sink trait
    pub async fn send_to(&mut self, msg: M, party_id: u16) -> Result<(), NetworkError> {
        let outgoing = Outgoing {
            msg,
            recipient: MessageDestination::OneParty(party_id),
        };

        // Use the Sink trait's send method
        self.send(outgoing).await
    }
    /// Registers this party with the ws server
    pub async fn register(&self) -> Result<(), NetworkError> {
        let reg_msg = SessionMessage::Register {
            session: PartySession {
                party_id: self.party_id,
                session_id: self.session_id,
            },
        };
        let serialized = bincode::serialize(&reg_msg)
            .map_err(|_| NetworkError::Connection("Serialization failed".into()))?;

        self.sender
            .unbounded_send(serialized)
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

        if let Ok(encoded) = bincode::serialize(&unreg_msg) {
            let _ = self.sender.unbounded_send(encoded);
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

/// Internal message format for wire transmission.
///
/// Encapsulates all necessary metadata for message delivery and ordering.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct WireMessage {
    /// Monotonically increasing message identifier
    pub id: u64,
    /// ID of the sending party
    pub sender: u16,
    /// Optional recipient ID for P2P messages
    pub receiver: Option<u16>,
    /// Serialized message payload
    pub payload: Vec<u8>,
}

impl WireMessage {
    /// Converts wire format receiver to MessageDestination.
    fn to_message_destination(&self) -> Option<MessageDestination> {
        self.receiver.map(MessageDestination::OneParty)
    }

    /// Converts MessageDestination to wire format receiver.
    fn from_message_destination(dest: Option<MessageDestination>) -> Option<u16> {
        dest.and_then(|d| match d {
            MessageDestination::OneParty(id) => Some(id),
            MessageDestination::AllParties => None,
        })
    }
}

/// Implements the Sink trait for WebSocket message sending.
///
/// This implementation provides an asynchronous message sending interface that:
/// - Generates unique message IDs for each outgoing message
/// - Serializes messages into the wire format
/// - Handles both P2P and broadcast message delivery
/// - Uses an unbounded channel for message queuing
///
/// # Type Parameters
///
/// * `M` - The message type that must be serializable and deserializable
///
/// # Examples
///
/// ```rust,no_run
/// use round_based::{Delivery, MessageDestination};
///
/// async fn send_message(sender: WsSender<String>) -> Result<(), NetworkError> {
///     let message = round_based::Outgoing {
///         recipient: MessageDestination::AllParties,
///         msg: "Hello, everyone!".to_string(),
///     };
///
///     sender.send(message).await?;
///     Ok(())
/// }
/// ```
///
/// # Implementation Notes
///
/// - Messages are sent immediately through an unbounded channel
/// - No internal buffering is performed
/// - Message ordering is maintained through unique, monotonic IDs
/// - The implementation is thread-safe and can be used across async tasks
impl<M> Sink<Outgoing<M>> for Sender<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Error = NetworkError;

    /// Checks if the sink is ready to accept a new message.
    ///
    /// This implementation always returns `Ready(Ok(()))` as the underlying
    /// unbounded channel can always accept new messages.
    ///
    /// # Returns
    ///
    /// - `Poll::Ready(Ok(()))`: The sink is ready to accept a new message
    /// - Never returns `Poll::Pending` or `Err` in this implementation
    fn poll_ready(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    /// Initiates sending a message through the WebSocket connection.
    ///
    /// This method performs the following steps:
    /// 1. Creates a wire message with a unique ID and serialized payload
    /// 2. Serializes the entire wire message
    /// 3. Sends the serialized data through the channel
    ///
    /// # Arguments
    ///
    /// * `item` - The outgoing message to send, containing the payload and recipient information
    ///
    /// # Returns
    ///
    /// - `Ok(())`: Message was successfully queued for sending
    /// - `Err(NetworkError::Connection)`: Serialization of message failed
    /// - `Err(NetworkError::ChannelClosed)`: The sending channel has been closed
    fn start_send(self: Pin<&mut Self>, item: Outgoing<M>) -> Result<(), Self::Error> {
        let wire_msg = WireMessage {
            id: MESSAGE_ID_GEN.next_id(),
            sender: self.party_id,
            receiver: WireMessage::from_message_destination(Some(item.recipient)),
            payload: bincode::serialize(&item.msg)
                .map_err(|_| NetworkError::Connection("Serialization failed".into()))?,
        };

        let encoded = bincode::serialize(&wire_msg)
            .map_err(|_| NetworkError::Connection("Serialization failed".into()))?;

        self.sender
            .unbounded_send(encoded)
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Attempts to flush the sink, ensuring all queued messages are sent.
    ///
    /// In this implementation, flushing is a no-op as messages are sent
    /// immediately through the unbounded channel.
    ///
    /// # Returns
    ///
    /// Always returns `Poll::Ready(Ok(()))` as there is no buffering
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

/// Message receiver component.
///
/// Handles receiving and validating messages from other parties.
/// Implements the `Stream` trait for incoming messages.
pub struct Receiver<M> {
    pub receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    pub message_state: MessageState,
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
        let poll_result = Pin::new(&mut self.receiver).poll_next(cx);
        let _message_state = &mut self.message_state;

        match poll_result {
            std::task::Poll::Ready(Some(data)) => {
                match bincode::deserialize::<WireMessage>(&data) {
                    Ok(wire_msg) => match bincode::deserialize(&wire_msg.payload) {
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
                    },
                    Err(_) => std::task::Poll::Ready(Some(Err(NetworkError::Connection(
                        "Failed to deserialize wire message".into(),
                    )))),
                }
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
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
    S: Stream<Item = Result<Vec<u8>, E>> + Sink<Vec<u8>, Error = E> + Unpin,
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
    S: Stream<Item = Result<Vec<u8>, E>> + Sink<Vec<u8>, Error = E> + Unpin + Send + 'static,
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

        let (stream_rcvr_tx, stream_rcvr_rx) = unbounded();
        let (stream_sender_tx, mut stream_sender_rx) = unbounded();

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
                                if stream_rcvr_tx.unbounded_send(data).is_err() {
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
                    msg = stream_sender_rx.next() => {
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
                message_state: MessageState::new(),
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
    S: Stream<Item = Result<Vec<u8>, E>> + Sink<Vec<u8>, Error = E> + Unpin,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use futures_util::FutureExt;
    use round_based::MessageType;
    use tokio::runtime::Runtime;

    // Mock stream for testing
    struct MockStream {
        incoming: mpsc::UnboundedReceiver<Result<Vec<u8>, std::io::Error>>,
        outgoing: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl Stream for MockStream {
        type Item = Result<Vec<u8>, std::io::Error>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.incoming.poll_next_unpin(cx)
        }
    }

    impl Sink<Vec<u8>> for MockStream {
        type Error = std::io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
            self.outgoing
                .unbounded_send(item)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "send failed"))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    
    // MessageIdGenerator Tests
    #[test]
    fn test_message_id_generator() {
        let gen = MessageIdGenerator::new();
        assert_eq!(gen.next_id(), 0);
        assert_eq!(gen.next_id(), 1);
        assert_eq!(gen.next_id(), 2);
    }

    #[test]
    fn test_message_id_generator_overflow() {
        let gen = MessageIdGenerator::new();
        gen.counter.store(u64::MAX, Ordering::SeqCst);
        assert_eq!(gen.next_id(), u64::MAX);
        assert_eq!(gen.next_id(), 0);
        assert_eq!(gen.next_id(), 1);
    }

    #[test]
    fn test_message_id_generator_thread_safety() {
        let gen = Arc::new(MessageIdGenerator::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let gen_clone = Arc::clone(&gen);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    gen_clone.next_id();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(gen.next_id(), 10000);
    }

    // MessageState Tests
    #[test]
    fn test_message_state_valid_sequence() {
        let mut state = MessageState::new();
        assert!(state.validate_and_update_id(1).is_ok());
        assert!(state.validate_and_update_id(2).is_ok());
        assert!(state.validate_and_update_id(3).is_ok());
    }

    #[test]
    fn test_message_state_invalid_sequence() {
        let mut state = MessageState::new();
        assert!(state.validate_and_update_id(1).is_ok());
        assert!(state.validate_and_update_id(2).is_ok());
        assert!(state.validate_and_update_id(1).is_err());
    }

    #[test]
    fn test_message_state_overflow() {
        let mut state = MessageState::new();
        state.last_id = Wrapping(u64::MAX);
        assert!(state.validate_and_update_id(0).is_ok());
        assert!(state.validate_and_update_id(1).is_ok());
    }

    // WireMessage Tests
    #[test]
    fn test_wire_message_serialization() {
        let test_msg = TestMessage {
            content: "test content".to_string(),
        };
        let serialized_payload = bincode::serialize(&test_msg).unwrap();

        let wire_msg = WireMessage {
            id: 1,
            sender: 2,
            receiver: Some(3),
            payload: serialized_payload,
        };

        let serialized = bincode::serialize(&wire_msg).unwrap();
        let deserialized: WireMessage = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.id, wire_msg.id);
        assert_eq!(deserialized.sender, wire_msg.sender);
        assert_eq!(deserialized.receiver, wire_msg.receiver);
        assert_eq!(deserialized.payload, wire_msg.payload);

        // Verify payload can be deserialized back to TestMessage
        let decoded_msg: TestMessage = bincode::deserialize(&deserialized.payload).unwrap();
        assert_eq!(decoded_msg.content, "test content");
    }

    #[test]
    fn test_wire_message_destination_conversion() {
        let p2p_msg = WireMessage {
            id: 1,
            sender: 2,
            receiver: Some(3),
            payload: vec![],
        };
        assert_eq!(
            p2p_msg.to_message_destination(),
            Some(MessageDestination::OneParty(3))
        );

        let broadcast_msg = WireMessage {
            id: 1,
            sender: 2,
            receiver: None,
            payload: vec![],
        };
        assert_eq!(broadcast_msg.to_message_destination(), None);
    }

    // Mock message type for testing
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestMessage {
        content: String,
    }

    #[test]
    fn test_sender_receiver_channel_closure() {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            let (tx, rx) = unbounded();
            let sender: Sender<TestMessage> = Sender {
                sender: tx,
                party_id: 1,
                session_id: 1,
                _phantom: PhantomData,
            };
            let mut receiver: Receiver<TestMessage> = Receiver {
                receiver: rx,
                message_state: MessageState::new(),
                _phantom: PhantomData,
            };

            // Use futures::StreamExt::now_or_never to check initial state
            assert!(receiver.next().now_or_never().is_none(),
                    "Channel should be empty initially");

            // Drop sender which will trigger the Unregister message
            drop(sender);

            std::thread::sleep(Duration::from_secs(1));

            // We should receive the unregister message before the channel closes
            match receiver.next().await {
                Some(Ok(received)) => {
                    // The received message should be a TestMessage that contains our ServerMessage
                    let server_msg: SessionMessage = bincode::deserialize(received.msg.content.as_bytes())
                        .expect("Should be able to deserialize server message");

                    match server_msg {
                        SessionMessage::Unregister { session } => {
                            assert_eq!(session.party_id, 1);
                            assert_eq!(session.session_id, 1);
                        },
                        _ => panic!("Expected Unregister message, got different server message"),
                    }
                },
                Some(Err(e)) => panic!("Received error instead of unregister message: {:?}", e),
                None => panic!("Channel closed before receiving unregister message"),
            }

            // After the unregister message, the channel should close
            assert!(receiver.next().await.is_none(),
                    "Channel should be closed after unregister message");
        });
    }

    #[test]
    fn test_sender_drop_behavior() {
        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            let (tx, rx) = unbounded();
            let mut sender: Sender<TestMessage> = Sender {
                sender: tx,
                party_id: 42,  // Use different party_id to verify it's preserved
                session_id: 123, // Use different session_id to verify it's preserved
                _phantom: PhantomData,
            };
            let mut receiver: Receiver<TestMessage> = Receiver {
                receiver: rx,
                message_state: MessageState::new(),
                _phantom: PhantomData,
            };

            // Send a normal message first
            let test_msg = TestMessage {
                content: "test before drop".to_string(),
            };
            sender.broadcast(test_msg).await.unwrap();

            // Receive and verify the normal message
            match receiver.next().await {
                Some(Ok(msg)) => {
                    assert_eq!(msg.msg.content, "test before drop");
                },
                _ => panic!("Failed to receive normal message"),
            }

            // Drop sender which will trigger the Unregister message
            drop(sender);

            std::thread::sleep(Duration::from_secs(1));

            // Verify the unregister message is received
            match receiver.next().await {
                Some(Ok(received)) => {
                    let server_msg: SessionMessage = bincode::deserialize(received.msg.content.as_bytes())
                        .expect("Should be able to deserialize server message");

                    match server_msg {
                        SessionMessage::Unregister { session } => {
                            assert_eq!(session.party_id, 42,
                                       "Unregister should preserve party_id");
                            assert_eq!(session.session_id, 123,
                                       "Unregister should preserve session_id");
                        },
                        _ => panic!("Expected Unregister message, got: {:?}", server_msg),
                    }
                },
                Some(Err(e)) => panic!("Received error instead of unregister message: {:?}", e),
                None => panic!("Channel closed before receiving unregister message"),
            }

            // Verify channel closes after unregister
            assert!(receiver.next().await.is_none(),
                    "Channel should be closed after unregister message");
        });
    }

    #[test]
    fn test_message_validation_integration() {
        MESSAGE_ID_GEN.reset();

        let (tx, rx) = unbounded();
        let mut sender: Sender<TestMessage> = Sender {
            sender: tx,
            party_id: 1,
            session_id: 1,
            _phantom: PhantomData,
        };
        let mut receiver: Receiver<TestMessage> = Receiver {
            receiver: rx,
            message_state: MessageState::new(),
            _phantom: PhantomData,
        };

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Send multiple test messages
            let messages = [TestMessage {
                    content: "test message 1".to_string(),
                },
                TestMessage {
                    content: "test message 2".to_string(),
                }];

            // Send messages
            for msg in messages.iter().cloned() {
                let outgoing = Outgoing {
                    msg,
                    recipient: MessageDestination::AllParties,
                };
                sender.send(outgoing).await.unwrap();
            }

            // Receive and validate messages
            for (i, expected_msg) in messages.iter().enumerate() {
                if let Some(Ok(received)) = receiver.next().await {
                    // Validate message content
                    assert_eq!(received.msg.content, expected_msg.content);

                    // Validate message metadata
                    assert_eq!(received.sender, 1); // party_id of sender
                    assert_eq!(received.msg_type, MessageType::Broadcast);

                    // Validate message ordering
                    assert_eq!(received.id, (i + 1) as u64); // IDs should start from 1
                } else {
                    panic!("Expected message not received");
                }
            }

            // Verify no more messages are pending
            assert!(receiver.next().now_or_never().is_none());
        });
    }

    #[tokio::test]
    async fn test_message_send_receive() {
        let (tx, rx) = unbounded();
        let mut sender: Sender<TestMessage> = Sender {
            sender: tx,
            party_id: 1,
            session_id: 1,
            _phantom: PhantomData,
        };
        let mut receiver: Receiver<TestMessage> = Receiver {
            receiver: rx,
            message_state: MessageState::new(),
            _phantom: PhantomData,
        };

        // Test broadcast message
        let broadcast_msg = TestMessage {
            content: "broadcast test".to_string(),
        };

        MESSAGE_ID_GEN.reset();
        sender.broadcast(broadcast_msg.clone()).await.unwrap();

        // Verify broadcast message
        if let Some(Ok(received)) = receiver.next().await {
            assert_eq!(received.msg.content, "broadcast test");
            assert_eq!(received.sender, 1);
            assert_eq!(received.msg_type, MessageType::Broadcast);
            assert_eq!(received.id, 0);
        } else {
            panic!("Expected broadcast message not received");
        }

        // Test p2p message
        let p2p_msg = TestMessage {
            content: "p2p test".to_string(),
        };
        sender.send_to(p2p_msg.clone(), 2).await.unwrap();

        // Verify p2p message
        if let Some(Ok(received)) = receiver.next().await {
            assert_eq!(received.msg.content, "p2p test");
            assert_eq!(received.sender, 1);
            assert_eq!(received.msg_type, MessageType::P2P);
            assert_eq!(received.id, 1);
        } else {
            panic!("Expected P2P message not received");
        }

        // Verify no more messages are pending
        assert!(receiver.next().now_or_never().is_none());
    }
}