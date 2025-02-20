//! Service module for handling signing request operations.
//!
//! This module implements a state machine-based service that manages the signing request process.
//! The service prompts for a message to sign, sends the signing request, and then returns to
//! waiting for the next message.
//!
//! # State Machine Flow
//!
//! ```plaintext
//! Initial ---> WaitingForMessage ---(MessageReceived)---> SendingRequest
//!                    ^                                          |
//!                    |                                         |
//!                    +--------------(RequestSent)--------------+
//!                    |                                         |
//!                    +---------------(Failed)------------------+
//! ```

use crate::committee::{CommitteeSession, ControlMessage};
use crate::error::Error;
use crate::network::Receiver;
use crate::signing::Message;
use futures_util::StreamExt;
use round_based::Delivery;
use rust_fsm::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tokio::io::{self, AsyncBufReadExt, BufReader};

// State machine definition
state_machine! {
    /// State machine for the signing service.
    ///
    /// # States
    /// - WaitingForMessage: Waiting for user to input a message to sign
    /// - SendingRequest: Committee is ready, sending signing request
    /// - Exit: Terminal state, service operation complete
    ///
    /// # Transitions
    /// - MessageReceived: Triggers transition from WaitingForMessage to SendingRequest
    /// - RequestSent: Triggers transition from SendingRequest to WaitingForMessage
    /// - Failed: Triggers transition to Exit from any state
    #[derive(Debug)]
    service(WaitingForMessage)

    WaitingForMessage => {
        MessageReceived => SendingRequest,
        Failed => Exit
    },
    SendingRequest => {
        RequestSent => WaitingForMessage,
        Failed => Exit
    }
}

use crate::p2p::P2PDelivery;
use crate::p2p_node::P2PNode;
use service::Input;

/// Environment data for the service state machine.
///
/// Contains all the contextual data needed for service operation.
struct ServiceEnv {
    /// Timestamp of when the first ReadyToSign message was received
    ready_sign_received: Option<Instant>,
    /// Last event processed by the state machine
    last_event: Option<Input>,
    /// Maximum duration the service will run before timing out
    timeout: Duration,
    /// Service start time
    start_time: Instant,
    /// Current message to be signed
    current_message: Option<String>,
}

impl ServiceEnv {
    /// Creates a new service environment.
    fn new() -> Self {
        Self {
            ready_sign_received: None,
            last_event: None,
            timeout: Duration::from_secs(60),
            start_time: Instant::now(),
            current_message: None,
        }
    }

    /// Records a new event in the environment.
    ///
    /// # Arguments
    /// * `event` - The event to record
    fn event(&mut self, event: Input) {
        self.last_event = Some(event);
    }

    /// Sets the current message to be signed
    fn set_message(&mut self, message: String) {
        self.current_message = Some(message);
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
    pub async fn new(
        party_id: u16,
        p2p_node: Arc<P2PNode>,
    ) -> Result<Self, Error> {
        Ok(Self {
            fsm: StateMachine::new(),
            context: Arc::new(RwLock::new(ServiceEnv::new())),
            p2p_node,
            party_id,
        })
    }

    /// Runs the service, managing WebSocket connections and message handling.
    pub async fn run(&mut self) -> Result<(), Error> {
        // Initialize P2P delivery for control messages
        let control_delivery = P2PDelivery::<ControlMessage>::connect(
            Arc::clone(&self.p2p_node),
            self.party_id,
            CommitteeSession::Control,
        )
            .await?;

        let (control_receiver, _) = control_delivery.split();


        // Spawn message monitoring task
        let context_clone = Arc::clone(&self.context);
        let monitor_handle = tokio::spawn(async move {
            monitor_ready_sign_messages(context_clone, control_receiver).await
        });

        // Run the main service loop
        let result = self.run_machine().await;

        // Clean up
        monitor_handle.abort();

        result
    }

    /// Runs the state machine, processing events and managing state transitions.
    async fn run_machine(&mut self) -> Result<(), Error> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();
        
        loop {
            let mut context = self.context.write().await;

            match (&self.fsm.state(), context.last_event.take()) {
                (service::State::WaitingForMessage, _) => {
                    println!("Enter a message to sign (or 'exit' to quit):");

                    // Read line will return when enter is pressed
                    if reader.read_line(&mut line).await.is_ok() {
                        // Only trim for exit check
                        if line.trim().to_lowercase() == "exit" {
                            self.fsm.consume(&Input::Failed).unwrap_or_default();
                            continue;
                        }
                        // Create a new string for storage to avoid move issues
                        context.set_message(line.to_string());
                        // Clear the screen using ANSI escape codes
                        print!("\x1B[2J\x1B[1;1H");
                        // Immediately transition to SendingRequest
                        self.fsm.consume(&Input::MessageReceived).unwrap_or_default();
                    }
                }
                (service::State::SendingRequest, _) => {
                    if let Some(message) = &context.current_message {
                        println!("Sending signature request for message: {}", message);
                        // Create and send the sign request
                        let request = Message::SignRequest {
                            message: message.as_bytes().to_vec(),
                        };

                        // Create delivery instance for signing messages
                        let signing_delivery = P2PDelivery::<Message>::connect(
                            Arc::clone(&self.p2p_node),
                            self.party_id,
                            CommitteeSession::SigningControl,
                        ).await?;

                        let (_, mut sender) = signing_delivery.split();
                        
                        // Broadcast the request
                        if let Err(e) = sender.broadcast(request).await {
                            context.event(Input::Failed);
                            return Err(Error::Network(e));
                        }
                        context.event(Input::RequestSent);
                    } else {
                        context.event(Input::Failed);
                    }
                }
                (service::State::Exit, _) => {
                    println!("Service shutting down...");
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
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Monitors for ReadyToSign messages from the committee.
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