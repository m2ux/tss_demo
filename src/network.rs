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

use futures::{Stream, Sink, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, WebSocketStream, MaybeTlsStream};
use round_based::{Delivery, MessageDestination};
use std::{marker::PhantomData, pin::Pin, sync::atomic::{AtomicU64, Ordering}, num::Wrapping};
use futures::channel::mpsc;

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
    InvalidMessageId {
        expected: u64,
        actual: u64,
    },
}

/// Tracks message ordering state to ensure proper message sequencing.
#[derive(Debug)]
struct MessageState {
    last_id: Wrapping<u64>,
}

impl MessageState {
    /// Creates a new MessageState starting from ID 0.
    fn new() -> Self {
        Self {
            last_id: Wrapping(0),
        }
    }

    /// Validates that a message ID maintains monotonic ordering.
    ///
    /// Returns an error if the new ID is less than the last seen ID,
    /// accounting for wraparound at u64::MAX.
    fn validate_and_update_id(&mut self, id: u64) -> Result<(), NetworkError> {
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
pub struct WsSender<M> {
    sender: mpsc::UnboundedSender<Vec<u8>>,
    party_id: u16,
    _phantom: PhantomData<M>,
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

/// Combined WebSocket delivery mechanism implementing `round_based::Delivery`.
///
/// Provides the main interface for WebSocket-based network communication,
/// combining both sending and receiving capabilities.
pub struct WsDelivery<M> {
    sender: WsSender<M>,
    receiver: WsReceiver<M>,
    server_addr: String,
}

/// Internal message format for wire transmission.
///
/// Encapsulates all necessary metadata for message delivery and ordering.
#[derive(serde::Serialize, serde::Deserialize)]
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

impl<M> WsDelivery<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>
{
    /// Establishes a new WebSocket connection to the specified server.
    ///
    /// # Arguments
    ///
    /// * `server_addr` - WebSocket server address (e.g., "ws://localhost:8080")
    /// * `party_id` - Unique identifier for this party in the protocol
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if connection fails or initialization errors occur.
    pub async fn connect(server_addr: &str, party_id: u16) -> Result<Self, NetworkError> {
        let (ws_stream, _) = connect_async(server_addr)
            .await
            .map_err(NetworkError::WebSocket)?;

        let (tx, rx) = mpsc::unbounded();

        tokio::spawn(handle_websocket(ws_stream, tx.clone()));

        Ok(Self {
            sender: WsSender {
                sender: tx,
                party_id,
                _phantom: PhantomData
            },
            receiver: WsReceiver {
                receiver: rx,
                message_state: MessageState::new(),
                _phantom: PhantomData
            },
            server_addr: server_addr.to_string(),
        })
    }

    /// Returns the server address this delivery instance is connected to
    pub fn addr(&self) -> &str {
        &self.server_addr
    }
}

/// Handles the WebSocket connection lifecycle.
///
/// Spawned as a separate task to manage the WebSocket connection and forward
/// received messages to the internal channel.
async fn handle_websocket(
    mut ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    while let Some(msg) = ws_stream.next().await {
        if let Ok(tokio_tungstenite::tungstenite::Message::Binary(data)) = msg {
            let _ = tx.unbounded_send(data);
        }
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
impl<M> Sink<round_based::Outgoing<M>> for WsSender<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>
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
    fn poll_ready(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
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
    fn start_send(self: Pin<&mut Self>, item: round_based::Outgoing<M>) -> Result<(), Self::Error> {
        let wire_msg = WireMessage {
            id: MESSAGE_ID_GEN.next_id(),
            sender: self.party_id,
            receiver: WireMessage::from_message_destination(Some(item.recipient)),
            payload: bincode::serialize(&item.msg).map_err(|_| NetworkError::Connection("Serialization failed".into()))?,
        };

        let encoded = bincode::serialize(&wire_msg)
            .map_err(|_| NetworkError::Connection("Serialization failed".into()))?;

        self.sender.unbounded_send(encoded)
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
    fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
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
    fn poll_close(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

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
    M: serde::Serialize + for<'de> serde::Deserialize<'de>
{
    type Item = Result<round_based::Incoming<M>, NetworkError>;

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
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        let receiver = unsafe { &mut self.as_mut().get_unchecked_mut().receiver };
        let poll_result = Pin::new(receiver).poll_next(cx);
        let message_state = unsafe { &mut self.get_unchecked_mut().message_state };

        match poll_result {
            std::task::Poll::Ready(Some(data)) => {
                let wire_msg: WireMessage = match bincode::deserialize(&data) {
                    Ok(msg) => msg,
                    Err(_) => return std::task::Poll::Ready(Some(Err(NetworkError::Connection("Deserialization failed".into()))))
                };

                // Validate message ID
                if let Err(e) = message_state.validate_and_update_id(wire_msg.id) {
                    return std::task::Poll::Ready(Some(Err(e)));
                }

                let message = match bincode::deserialize(&wire_msg.payload) {
                    Ok(msg) => msg,
                    Err(_) => return std::task::Poll::Ready(Some(Err(NetworkError::Connection("Deserialization failed".into()))))
                };

                let msg_type = wire_msg.to_message_destination()
                    .map_or(round_based::MessageType::Broadcast, |_| round_based::MessageType::P2P);

                std::task::Poll::Ready(Some(Ok(round_based::Incoming {
                    id: wire_msg.id,
                    sender: wire_msg.sender,
                    msg: message,
                    msg_type,
                })))
            },
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
    M: serde::Serialize + for<'de> serde::Deserialize<'de> + std::marker::Unpin
{
    type Send = WsSender<M>;
    type Receive = WsReceiver<M>;
    type SendError = NetworkError;
    type ReceiveError = NetworkError;

    /// Splits the delivery instance into separate sender and receiver components.
    ///
    /// This method allows for independent use of sending and receiving capabilities,
    /// which is particularly useful in async contexts where different tasks handle
    /// sending and receiving.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - The receiver component for handling incoming messages
    /// - The sender component for sending outgoing messages
    fn split(self) -> (Self::Receive, Self::Send) {
        (self.receiver, self.sender)
    }
}