// Copyright © Aptos Foundation

use crate::{
    grpc_network_service::RemoteExecutionServerWrapper,
    network_controller::{Message, MessageType},
};
use aptos_logger::warn;
use crossbeam_channel::Sender;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{runtime::Runtime, sync::oneshot};

pub struct InboundHandler {
    service: String,
    listen_addr: SocketAddr,
    inbound_handlers: Arc<Mutex<HashMap<MessageType, Sender<Message>>>>,
}

impl InboundHandler {
    pub fn new(service: String, listen_addr: SocketAddr, _: u64) -> Self {
        Self {
            service: service.clone(),
            listen_addr,
            inbound_handlers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_handler(&self, message_type: String, sender: Sender<Message>) {
        assert!(!self
            .inbound_handlers
            .lock()
            .unwrap()
            .contains_key(&MessageType::new(message_type.clone())));
        let mut inbound_handlers = self.inbound_handlers.lock().unwrap();
        inbound_handlers.insert(MessageType::new(message_type), sender);
    }

    pub fn start(&self, rt: &Runtime) -> Option<oneshot::Sender<()>> {
        if self.inbound_handlers.lock().unwrap().is_empty() {
            return None;
        }

        let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
        // The server is started in a separate task
        RemoteExecutionServerWrapper::new(self.inbound_handlers.clone()).start(
            rt,
            self.service.clone(),
            self.listen_addr,
            server_shutdown_rx,
        );
        Some(server_shutdown_tx)
    }

    // Helper function to short-circuit the network message not to be sent over the network for self messages
    pub fn send_incoming_message_to_handler(&self, message_type: &MessageType, message: Message) {
        // Check if there is a registered handler for the sender
        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(message_type) {
            // Send the message to the registered handler
            handler.send(message).unwrap();
        } else {
            warn!("No handler registered for message type: {:?}", message_type);
        }
    }
}
