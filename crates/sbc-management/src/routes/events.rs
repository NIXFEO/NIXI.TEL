//! GET /api/v1/events — Server-Sent Events stream of SBC events.
//!
//! `?types=call,registration,trunk,alert,config` filters by category
//! (default: all). Slow consumers skip events (broadcast lag semantics).

use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use serde::Deserialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    /// Comma-separated categories; absent = all.
    pub types: Option<String>,
}

pub async fn sse_events(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let filter: Option<Vec<String>> = q.types.map(|t| {
        t.split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    });

    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(event) => {
            let category = event.category();
            if let Some(f) = &filter {
                if !f.iter().any(|t| t == category) {
                    return None;
                }
            }
            let data = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
            Some(Ok(Event::default().event(category).data(data)))
        }
        // Consumer lagged: tell it how many events it missed, keep going.
        Err(BroadcastStreamRecvError::Lagged(n)) => Some(Ok(Event::default()
            .event("lagged")
            .data(format!("{{\"skipped\":{}}}", n)))),
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}
