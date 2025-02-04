//! Service module for handling signing request operations.
//!
//! This module implements a state machine-based service that manages the signing request process.
//! The service waits for the committee to be ready (indicated by receiving a ReadyToSign message
//! and waiting 10 seconds), then sends the signing request and exits.
//!
//! # State Machine Flow
//!
//! ```plaintext
//! Initial ---(CommitteeReady)---> SendingRequest ---(RequestSent)---> Exit
//!     |                               |
//!     |                               |
//!     +------------(Failed)------------+---------(Failed)-----------> Exit
//! ```
//!
//! # Example
//! ```no_run
//! use cggmp21_demo::service::run_service_mode;
//!
//! #[tokio::main]
//! async fn main() {
//!     let server_addr = "ws://localhost:8080".to_string();
//!     let party_id = 1;
//!     let message = "Message to sign".to_string();
//!
//!     if let Err(e) = run_service_mode(server_addr, party_id, message).await {
//!         eprintln!("Service error: {}", e);
//!     }
//! }
//! ```

use crate::committee::{CommitteeSession, ControlMessage};
use crate::error::Error;
use crate::network::{Receiver, Sender};
use crate::signing::Message;
use futures_util::StreamExt;
use round_based::Delivery;
use rust_fsm::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

// State machine definition
state_machine! {
    /// State machine for the signing service.
    ///
    /// # States
    /// - SendingRequest: Committee is ready, sending signing request
    /// - Exit: Terminal state, service operation complete
    ///
    /// # Transitions
    /// - RequestSent: Triggers transition from SendingRequest to Exit
    /// - Failed: Triggers transition to Exit from any state
    #[derive(Debug)]
    service(SendingRequest)

    SendingRequest => {
        RequestSent => Exit,
        Failed => Exit
    }
}

use crate::p2p::P2PDelivery;
use crate::p2p_node::P2PNode;
use crate::websocket::WsDelivery;
use service::Input;

/// Environment data for the service state machine.
///
/// Contains all the contextual data needed for service operation.
struct ServiceEnv {
    /// Message to be signed
    message: String,
    /// Timestamp of when the first ReadyToSign message was received
    ready_sign_received: Option<Instant>,
    /// Last event processed by the state machine
    last_event: Option<Input>,
    /// Maximum duration the service will run before timing out
    timeout: Duration,
    /// Service start time
    start_time: Instant,
}

impl ServiceEnv {
    /// Creates a new service environment.
    ///
    /// # Arguments
    /// * `message` - The message to be signed
    fn new(message: String) -> Self {
        Self {
            message,
            ready_sign_received: None,
            last_event: None,
            timeout: Duration::from_secs(60),
            start_time: Instant::now(),
        }
    }

    /// Records a new event in the environment.
    ///
    /// # Arguments
    /// * `event` - The event to record
    fn event(&mut self, event: Input) {
        self.last_event = Some(event);
    }

    /// Checks if the service has exceeded its timeout duration.
    fn is_timeout(&self) -> bool {
        Instant::now().duration_since(self.start_time) > self.timeout
    }

    /// Records when the first ReadyToSign message is received.
    fn mark_ready_sign_received(&mut self) {
        if self.ready_sign_received.is_none() {
            self.ready_sign_received = Some(Instant::now());
        }
    }
}

/// Main service structure managing the signing request process.
pub(crate) struct Service {
    /// State machine instance
    fsm: StateMachine<service::Impl>,
    /// Shared service environment
    context: Arc<RwLock<ServiceEnv>>,
    p2p_node: Arc<P2PNode>,
    party_id: u16,
}

impl Service {
    /// Creates a new service instance.
    ///
    /// # Arguments
    /// * `message` - The message to be signed
    pub async fn new(
        party_id: u16,
        p2p_node: Arc<P2PNode>,
        message: String,
    ) -> Result<Self, Error> {
        Ok(Self {
            fsm: StateMachine::new(),
            context: Arc::new(RwLock::new(ServiceEnv::new(message))),
            p2p_node,
            party_id,
        })
    }

    /// Runs the service, managing WebSocket connections and message handling.
    ///
    /// # Arguments
    /// * `server_addr` - WebSocket server address
    /// * `party_id` - ID of this party in the signing protocol
    ///
    /// # Returns
    /// * `Result<(), Error>` - Success or error status
    pub async fn run(&mut self) -> Result<(), Error> {
        // Initialize P2P delivery for control messages
        let control_delivery = P2PDelivery::<ControlMessage>::connect(
            Arc::clone(&self.p2p_node),
            self.party_id,
            CommitteeSession::Control,
        )
        .await?;

        let (control_receiver, _) = control_delivery.split();

        // Create delivery instance for signing messages
        let signing_delivery = P2PDelivery::<Message>::connect(
            Arc::clone(&self.p2p_node),
            self.party_id,
            CommitteeSession::SigningControl,
        )
        .await?;

        let (_, signing_sender) = signing_delivery.split();

        // Spawn message monitoring task
        let context_clone = Arc::clone(&self.context);
        let monitor_handle = tokio::spawn(async move {
            monitor_ready_sign_messages(context_clone, control_receiver).await
        });

        // Run the main service loop
        let result = self.run_machine(signing_sender).await;

        // Clean up
        monitor_handle.abort();

        result
    }

    /// Runs the state machine, processing events and managing state transitions.
    ///
    /// # Arguments
    /// * `sender` - WebSocket sender for signing protocol messages
    ///
    /// # Returns
    /// * `Result<(), Error>` - Success or error status
    async fn run_machine(&mut self, mut sender: Sender<Message>) -> Result<(), Error> {
        loop {
            let mut context = self.context.write().await;

            match (&self.fsm.state(), context.last_event.take()) {
                (service::State::SendingRequest, _) => {
                    println!("Sending signature request");
                    // Create and send the sign request
                    let request = Message::SignRequest {
                        message: context.message.as_bytes().to_vec(),
                    };

                    // Broadcast the request
                    if let Err(e) = sender.broadcast(request).await {
                        context.event(Input::Failed);
                        return Err(Error::Network(e));
                    }
                    context.event(Input::RequestSent);
                }
                (service::State::Exit, _) => {
                    return Ok(());
                }
            }

            // Perform state transition and perform output actions
            if let Some(last_event) = context.last_event.take() {
                if let Ok(_output_event) = self.fsm.consume(&last_event) {
                    // Post-transition actions
                }
            }

            // Prevent tight loop
            drop(context);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Monitors for ReadyToSign messages from the committee.
///
/// # Arguments
/// * `context` - Shared service environment
/// * `receiver` - WebSocket receiver for control messages
async fn monitor_ready_sign_messages(
    context: Arc<RwLock<ServiceEnv>>,
    mut receiver: Receiver<ControlMessage>,
) {
    while let Some(Ok(message)) = receiver.next().await {
        if matches!(message.msg, ControlMessage::ReadyToSign) {
            let mut context = context.write().await;
            context.mark_ready_sign_received();
        }
    }
}
