//! Event Subscriber
//!
//! Subscribe to security events from the event bus.

use super::types::SecurityEvent;
use tokio::sync::broadcast;

/// Trait for event subscribers
pub trait EventSubscriber: Send + Sync {
    /// Handle an incoming security event
    fn on_event(&self, event: SecurityEvent) -> anyhow::Result<()>;

    /// Get the team identifier for this subscriber
    fn team(&self) -> &str;
}

/// Subscription handle for event bus
pub struct Subscription {
    rx: broadcast::Receiver<SecurityEvent>,
}

impl Subscription {
    /// Create a new subscription from a broadcast receiver
    pub fn new(rx: broadcast::Receiver<SecurityEvent>) -> Self {
        Self { rx }
    }

    /// Receive the next event (blocking)
    pub async fn recv(&mut self) -> Result<SecurityEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }

    /// Try to receive an event (non-blocking)
    pub fn try_recv(&mut self) -> Result<SecurityEvent, broadcast::error::TryRecvError> {
        self.rx.try_recv()
    }
}
