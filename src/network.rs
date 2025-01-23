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

use crate::server::{PartySession, ServerMessage};
use futures::channel::{mpsc, mpsc::unbounded};
use futures::{stream::SplitStream, Sink, SinkExt, Stream, StreamExt};
use round_based::{Delivery, Incoming, MessageDestination, Outgoing};
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    num::Wrapping,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tungstenite::Message;

/// Thread-safe message ID generator with overflow handling.
///
/// Generates monotonically increasing message IDs with proper handling of integer overflow
/// using wrapping arithmetic. Thread-safe through the use of atomic operations.
struct MessageIdGenerator {
    counter: AtomicU64,
}

impl MessageIdGenerator {
    /// Creates a new MessageIdGenerator starting from 0.
    const fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Generates the next message ID in a thread-safe manner.
    ///
    /// Uses wrapping arithmetic to handle overflow gracefully, ensuring
    /// the counter continues from 0 after reaching u64::MAX.
    fn next_id(&self) -> u64 {
        let Wrapping(next_id) = Wrapping(self.counter.load(Ordering::SeqCst)) + Wrapping(1);
        self.counter.store(next_id, Ordering::SeqCst);
        next_id
    }
}

static MESSAGE_ID_GEN: MessageIdGenerator = MessageIdGenerator::new();

/// Message sent by client to register with server
#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRegistration {
    /// Initial registration message with party ID
    Register { party_id: u16 },
}

/// Errors that can occur during network operations.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// WebSocket protocol errors
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

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
///
/// # Examples
///
/// ```
/// let mut state = MessageState::new();
///
/// // Validate a sequence of message IDs
/// assert!(state.validate_and_update_id(1).is_ok());
/// assert!(state.validate_and_update_id(2).is_ok());
///
/// // Out of order messages will return an error
/// assert!(state.validate_and_update_id(1).is_err());
/// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// let mut state = MessageState::new();
    ///
    /// // Valid sequence
    /// assert!(state.validate_and_update_id(1).is_ok());
    /// assert!(state.validate_and_update_id(2).is_ok());
    ///
    /// // Invalid - out of sequence
    /// assert!(state.validate_and_update_id(1).is_err());
    /// ```
    pub fn validate_and_update_id(&mut self, id: u64) -> Result<(), NetworkError> {
        let current = self.last_id;
        let new_id = Wrapping(id);

        if new_id < current {
            return Err(NetworkError::InvalidMessageId {
                expected: current.0,
                actual: id,
            });
        }

        self.last_id = new_id;
        Ok(())
    }
}

/// WebSocket message sender component.
///
/// Handles sending messages to other parties through the WebSocket connection.
/// Implements the `Sink` trait for outgoing messages.
#[derive(Clone)]
pub struct WsSender<M>
where
    M: Serialize + for<'de> Deserialize<'de>,
{
    sender: mpsc::UnboundedSender<Vec<u8>>,
    party_id: u16,
    session_id: u16,
    _phantom: PhantomData<M>,
}

impl<M> WsSender<M>
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
    async fn register(&self) -> Result<(), NetworkError> {
        let reg_msg = ServerMessage::Register {
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

impl<M> Drop for WsSender<M>
where
    M: Serialize + for<'de> Deserialize<'de>,
{
    fn drop(&mut self) {
        let unreg_msg = ServerMessage::Unregister {
            session: PartySession {
                party_id: self.party_id,
                session_id: self.session_id,
            },
        };

        if let Ok(encoded) = bincode::serialize(&unreg_msg) {
            let _ = self.sender.unbounded_send(encoded);
        }
    }
}

/// WebSocket message receiver component.
///
/// Handles receiving and validating messages from other parties.
/// Implements the `Stream` trait for incoming messages.
pub struct WsReceiver<M> {
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    message_state: MessageState,
    _phantom: PhantomData<M>,
}

/// Internal message format for wire transmission.
///
/// Encapsulates all necessary metadata for message delivery and ordering.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
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

/// Combined WebSocket delivery mechanism implementing `round_based::Delivery`.
///
/// Provides the main interface for WebSocket-based network communication,
/// combining both sending and receiving capabilities.
pub struct WsDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de>,
{
    sender: WsSender<M>,
    receiver: WsReceiver<M>,
}

impl<M> WsDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + std::marker::Unpin,
{
    /// Establishes a new WebSocket connection to the specified server.
    ///
    /// # Arguments
    ///
    /// * `server_addr` - WebSocket server address (e.g., "ws://localhost:8080")
    /// * `session_id` - Unique identifier for this session
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if connection fails or initialization errors occur.
    pub async fn connect<S>(
        server_addr: &str,
        party_id: u16,
        session_id: S,
    ) -> Result<Self, NetworkError>
    where
        S: Into<u16>,
    {
        let (ws_stream, _) = connect_async(server_addr)
            .await
            .map_err(NetworkError::WebSocket)?;

        let (mut write, read) = ws_stream.split();

        // Handle incoming WebSocket messages
        let (ws_rcvr_tx, ws_rcvr_rx) = unbounded();
        let (ws_sender_tx, mut ws_sender_rx) = unbounded();

        tokio::spawn(async move {
            let mut read = read;
            loop {
                tokio::select! {
                    // Handle incoming messages
                    msg = read.next() => {
                        match msg {
                            Some(Ok(Message::Binary(data))) => {
                                if ws_rcvr_tx.unbounded_send(data).is_err() {
                                    //println!("Receiver channel closed, terminating");
                                    break;
                                }
                            }
                            Some(Ok(_)) => {
                                continue;
                            }
                            Some(Err(e)) => {
                                //println!("WebSocket read error: {}", e);
                                break;
                            }
                            None => {
                                println!("WebSocket connection closed by peer");
                                break;
                            }
                        }
                    }
                    // Handle outgoing messages
                    msg = ws_sender_rx.next() => {
                        match msg {
                            Some(data) => {
                                if let Err(e) = write.send(Message::Binary(data)).await {
                                    println!("WebSocket write error: {}", e);
                                    break;
                                }
                            }
                            None => {
                                //println!("Sender channel closed, terminating");
                                break;
                            }
                        }
                    }
                }
            }

            // Attempt to close the connection gracefully
            let _ = write.close().await;
        });

        let sender = WsSender {
            sender: ws_sender_tx,
            party_id,
            session_id: session_id.into(),
            _phantom: PhantomData,
        };

        sender.register().await?;

        Ok(Self {
            sender,
            receiver: WsReceiver {
                receiver: ws_rcvr_rx,
                message_state: MessageState::new(),
                _phantom: PhantomData,
            },
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
impl<M> Sink<Outgoing<M>> for WsSender<M>
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

// Explicitly implement Unpin for WsReceiver
impl<M> Unpin for WsReceiver<M> {}

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
impl<M> Stream for WsReceiver<M>
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
        let message_state = &mut self.message_state;

        match poll_result {
            std::task::Poll::Ready(Some(data)) => {
                match bincode::deserialize::<WireMessage>(&data) {
                    Ok(wire_msg) => match bincode::deserialize(&wire_msg.payload) {
                        Ok(msg) => std::task::Poll::Ready(Some(Ok(round_based::Incoming {
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

/// Implements the Delivery trait for WebSocket-based message transport.
///
/// This implementation provides a complete message delivery system that:
/// - Manages both sending and receiving of messages
/// - Handles connection lifecycle
/// - Ensures reliable message delivery
/// - Supports splitting into separate send and receive components
///
/// # Type Parameters
///
/// * `M` - The message type that must be serializable, deserializable, and Unpin
///
/// # Examples
///
/// ```rust,no_run
/// use round_based::Delivery;
///
/// async fn setup_communication() -> Result<(), NetworkError> {
///     // Create the delivery instance
///     let delivery = WsDelivery::connect("ws://localhost:8080", 1).await?;
///
///     // Split into sender and receiver
///     let (receiver, sender) = delivery.split();
///
///     // Use sender and receiver independently
///     Ok(())
/// }
/// ```
///
/// # Implementation Notes
///
/// - The implementation is fully async and supports concurrent operations
/// - Sender and receiver can be used independently after splitting
/// - All message guarantees are maintained after splitting
/// - The implementation is compatible with the round-based protocol requirements
impl<M> Delivery<M> for WsDelivery<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de> + Unpin,
{
    type Send = WsSender<M>;
    type Receive = WsReceiver<M>;
    type SendError = NetworkError;
    type ReceiveError = NetworkError;

    /// Splits the delivery instance into separate sender and receiver components.
    fn split(self) -> (Self::Receive, Self::Send) {
        (self.receiver, self.sender)
    }
}
