//! SBC event bus — broadcast channel feeding the SSE API endpoint.
//!
//! Publishers never block: with no subscriber the event is dropped, and a
//! slow subscriber skips events (tokio broadcast lag semantics).

use serde::Serialize;
use tokio::sync::broadcast;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SbcEvent {
    CallStarted {
        uuid: String,
        call_id: String,
        caller: String,
        callee: Option<String>,
        ts: u64,
    },
    CallAnswered {
        uuid: String,
        ts: u64,
    },
    CallEnded {
        uuid: String,
        duration_secs: u64,
        reason: String,
        ts: u64,
    },
    Registered {
        aor: String,
        contact: String,
        expires: u32,
        ts: u64,
    },
    Unregistered {
        aor: String,
        ts: u64,
    },
    TrunkHealth {
        trunk: String,
        status: String,
        consecutive_failures: u32,
        ts: u64,
    },
    Alert {
        level: String,
        kind: String,
        detail: String,
        ts: u64,
    },
    ConfigChanged {
        entity: String,
        action: String,
        id: String,
        ts: u64,
    },
}

impl SbcEvent {
    /// Event category used for SSE filtering (`?types=call,registration,…`).
    pub fn category(&self) -> &'static str {
        match self {
            Self::CallStarted { .. } | Self::CallAnswered { .. } | Self::CallEnded { .. } => "call",
            Self::Registered { .. } | Self::Unregistered { .. } => "registration",
            Self::TrunkHealth { .. } => "trunk",
            Self::Alert { .. } => "alert",
            Self::ConfigChanged { .. } => "config",
        }
    }
}

/// Unix timestamp helper for event constructors.
pub fn event_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug)]
pub struct EventBus {
    tx: broadcast::Sender<SbcEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self { tx }
    }

    /// Publish an event; silently dropped when nobody is subscribed.
    pub fn publish(&self, event: SbcEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SbcEvent> {
        self.tx.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_and_receive() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        bus.publish(SbcEvent::CallAnswered {
            uuid: "u1".into(),
            ts: 1,
        });
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.category(), "call");
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""type":"call_answered""#));
    }

    #[test]
    fn publish_without_subscribers_is_noop() {
        let bus = EventBus::new();
        bus.publish(SbcEvent::Alert {
            level: "warning".into(),
            kind: "test".into(),
            detail: "d".into(),
            ts: 1,
        });
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn categories() {
        assert_eq!(
            SbcEvent::Registered {
                aor: "a".into(),
                contact: "c".into(),
                expires: 60,
                ts: 1
            }
            .category(),
            "registration"
        );
        assert_eq!(
            SbcEvent::ConfigChanged {
                entity: "user".into(),
                action: "create".into(),
                id: "alice".into(),
                ts: 1
            }
            .category(),
            "config"
        );
    }
}
