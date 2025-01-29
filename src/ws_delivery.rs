use crate::network::{MessageState, NetworkError, Receiver, Sender};
use futures::channel::mpsc::unbounded;
use futures::{SinkExt, StreamExt};
use round_based::Delivery;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use tokio_tungstenite::connect_async;
use tungstenite::Message;

/// Errors that can occur during network operations.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// WebSocket protocol errors
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
}

/// Combined WebSocket delivery mechanism implementing `round_based::Delivery`.
///
/// Provides the main interface for WebSocket-based network communication,
/// combining both sending and receiving capabilities.
pub struct WsDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de>,
{
    sender: Sender<M>,
    receiver: Receiver<M>,
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
            .map_err(|e| NetworkError::Delivery(e.to_string()))?;

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
                            Some(Err(_)) => {
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

        let sender = Sender {
            sender: ws_sender_tx,
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
                receiver: ws_rcvr_rx,
                message_state: MessageState::new(),
                _phantom: PhantomData,
            },
        })
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
    type Send = Sender<M>;
    type Receive = Receiver<M>;
    type SendError = NetworkError;
    type ReceiveError = NetworkError;

    /// Splits the delivery instance into separate sender and receiver components.
    fn split(self) -> (Self::Receive, Self::Send) {
        (self.receiver, self.sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MESSAGE_ID_GEN;
    use futures_util::FutureExt;
    use round_based::MessageType;

    // Mock message type for testing
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestMessage {
        content: String,
    }

    // Integration Tests
    #[tokio::test]
    async fn test_ws_delivery_connect_error() {
        let result = WsDelivery::<String>::connect("ws://invalid-address", 1, 1u16).await;
        assert!(result.is_err());
    }

    // Test message delivery split
    #[tokio::test]
    async fn test_delivery_split() {
        let (tx, rx) = unbounded();
        let delivery = WsDelivery {
            sender: Sender {
                sender: tx,
                party_id: 1,
                session_id: 1,
                _phantom: PhantomData,
            },
            receiver: Receiver {
                receiver: rx,
                message_state: MessageState::new(),
                _phantom: PhantomData,
            },
        };

        let (mut receiver, mut sender): (Receiver<TestMessage>, Sender<TestMessage>) =
            delivery.split();

        // Verify sender metadata is preserved
        assert_eq!(sender.party_id, 1);
        assert_eq!(sender.session_id, 1);

        // Test that split components can still communicate
        let test_msg = TestMessage {
            content: "split test".to_string(),
        };

        MESSAGE_ID_GEN.reset();

        // Send a message using the split sender
        sender.broadcast(test_msg.clone()).await.unwrap();

        // Verify the split receiver can receive the message
        if let Some(Ok(received)) = receiver.next().await {
            assert_eq!(received.msg.content, "split test");
            assert_eq!(received.sender, 1);
            assert_eq!(received.msg_type, MessageType::Broadcast);
            assert_eq!(received.id, 0);
        } else {
            panic!("Expected message not received after split");
        }

        // Test P2P message after split
        let p2p_msg = TestMessage {
            content: "p2p after split".to_string(),
        };
        sender.send_to(p2p_msg.clone(), 2).await.unwrap();

        // Verify P2P message
        if let Some(Ok(received)) = receiver.next().await {
            assert_eq!(received.msg.content, "p2p after split");
            assert_eq!(received.sender, 1);
            assert_eq!(received.msg_type, MessageType::P2P);
            assert_eq!(received.id, 1);
        } else {
            panic!("Expected P2P message not received after split");
        }

        // Verify no more messages are pending
        assert!(receiver.next().now_or_never().is_none());
    }
}
