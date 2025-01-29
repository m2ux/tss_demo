use std::sync::Arc;
use crate::network::{MessageState, NetworkError, P2PMessage, Receiver, Sender};
use futures::channel::mpsc::unbounded;
use futures::{SinkExt, StreamExt};
use libp2p_swarm::SwarmEvent;
use round_based::{Delivery, Incoming, MessageType};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::connect_async;
use crate::p2p::CggmpBehaviourEvent;

/// Errors that can occur during network operations.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// WebSocket protocol errors
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
}

pub struct P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de>,
{
    sender: Sender<M>,
    receiver: Receiver<M>,
}

impl<M> P2PDelivery<M>
where
    M: Serialize + for<'de> Deserialize<'de> + std::marker::Unpin,
{
    pub async fn connect<S>(
        server_addr: &str,
        party_id: u16,
        session_id: S,
    ) -> Result<Self, NetworkError>
    where
        S: Into<u16>,
    {

        // Clone required data for the delivery handlers
        let swarm = Arc::clone(&self.swarm);
        let peers = Arc::clone(&self.peers);
        let local_session = self.local_session.clone();
        
        let (ws_stream, _) = connect_async(server_addr)
            .await
            .map_err(|e| NetworkError::Delivery(e.to_string()))?;

        let (mut write, read) = ws_stream.split();

        // Handle incoming WebSocket messages
        let (ws_rcvr_tx, ws_rcvr_rx) = unbounded();
        let (ws_sender_tx, mut ws_sender_rx) = unbounded();

        // Spawn message handling task
        tokio::spawn(async move {
            loop {
                // Get swarm lock and poll for next event
                if let Some(event) = {
                    let mut swarm = swarm.lock().unwrap();
                    swarm.next().now_or_never()
                } {
                    match event {
                        Some(SwarmEvent::Behaviour(CggmpBehaviourEvent::RequestResponse(event))) => {
                            match event {
                                RequestResponseEvent::Message {
                                    peer,
                                    message: RequestMessage::Request {
                                        request: P2PMessage::Protocol(wire_msg),
                                        channel, ..
                                    }, ..
                                } => {
                                    // Convert wire message to protocol message and forward
                                    if let Ok(msg) = bincode::deserialize(&wire_msg.payload) {
                                        let incoming = Incoming {
                                            id: wire_msg.id,
                                            sender: wire_msg.sender,
                                            msg,
                                            msg_type: if wire_msg.receiver.is_some() {
                                                MessageType::P2P
                                            } else {
                                                MessageType::Broadcast
                                            },
                                        };

                                        if let Err(e) = receiver_tx.unbounded_send(incoming) {
                                            println!("Failed to forward message: {}", e);
                                            break;
                                        }
                                    }

                                    // Send empty response
                                    let mut swarm = swarm.lock().unwrap();
                                    if let Err(e) = swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_response(channel, ())
                                    {
                                        println!("Failed to send response: {:?}", e);
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        });
    }
}

impl<M> Delivery<M> for P2PDelivery<M>
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