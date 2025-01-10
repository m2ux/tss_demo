use futures::{Stream, Sink, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, WebSocketStream, MaybeTlsStream};
use round_based::{Delivery, MessageDestination};
use std::{marker::PhantomData, pin::Pin, sync::atomic::{AtomicU64, Ordering}, num::Wrapping};
use futures::channel::mpsc;

/// Thread-safe message ID generator with overflow handling
struct MessageIdGenerator {
    counter: AtomicU64,
}

impl MessageIdGenerator {
    const fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    fn next_id(&self) -> u64 {
        // Use wrapping add via Wrapping to handle overflow gracefully
        let Wrapping(next_id) = Wrapping(self.counter.load(Ordering::SeqCst)) + Wrapping(1);
        self.counter.store(next_id, Ordering::SeqCst);
        next_id
    }
}

static MESSAGE_ID_GEN: MessageIdGenerator = MessageIdGenerator::new();

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Invalid message ID: expected >= {expected}, got {actual}")]
    InvalidMessageId {
        expected: u64,
        actual: u64,
    },
}

#[derive(Debug)]
struct MessageState {
    last_id: Wrapping<u64>,
}

impl MessageState {
    fn new() -> Self {
        Self {
            last_id: Wrapping(0),
        }
    }

    fn validate_and_update_id(&mut self, id: u64) -> Result<(), NetworkError> {
        let current = self.last_id;
        let new_id = Wrapping(id);

        // Allow wraparound but ensure monotonic increase
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

pub struct WsSender<M> {
    sender: mpsc::UnboundedSender<Vec<u8>>,
    party_id: u16,
    _phantom: PhantomData<M>,
}

pub struct WsReceiver<M> {
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    message_state: MessageState,
    _phantom: PhantomData<M>,
}

pub struct WsDelivery<M> {
    sender: WsSender<M>,
    receiver: WsReceiver<M>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WireMessage {
    id: u64,
    sender: u16,
    receiver: Option<u16>,
    payload: Vec<u8>,
}

impl WireMessage {
    fn to_message_destination(&self) -> Option<MessageDestination> {
        self.receiver.map(MessageDestination::OneParty)
    }

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
        })
    }
}

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

impl<M> Sink<round_based::Outgoing<M>> for WsSender<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>
{
    type Error = NetworkError;

    fn poll_ready(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

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

    fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl<M> Stream for WsReceiver<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de>
{
    type Item = Result<round_based::Incoming<M>, NetworkError>;

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

impl<M> Delivery<M> for WsDelivery<M>
where
    M: serde::Serialize + for<'de> serde::Deserialize<'de> + std::marker::Unpin
{
    type Send = WsSender<M>;
    type Receive = WsReceiver<M>;
    type SendError = NetworkError;
    type ReceiveError = NetworkError;

    fn split(self) -> (Self::Receive, Self::Send) {
        (self.receiver, self.sender)
    }
}