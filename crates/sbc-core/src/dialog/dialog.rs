//! Dialog Management (RFC 3261 Section 12)
//!
//! Implements SIP dialog tracking for established sessions

use crate::{Error, Result};
use rsip::prelude::*;
use rsip::{Request, Response};
use std::time::Instant;

/// Dialog identifier (Call-ID + local tag + remote tag)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

impl DialogId {
    /// Create a new dialog ID
    pub fn new(call_id: String, local_tag: String, remote_tag: String) -> Self {
        Self {
            call_id,
            local_tag,
            remote_tag,
        }
    }

    /// Create from INVITE request and 2xx response (UAC side)
    pub fn from_invite_uac(request: &Request, response: &Response) -> Result<Self> {
        // Extract Call-ID
        let call_id = extract_call_id_from_headers(request.headers())?;

        // Extract local tag (From header in request)
        let from_header = request
            .headers()
            .iter()
            .find(|h| matches!(h, rsip::Header::From(_)))
            .ok_or_else(|| Error::Parse("Missing From header".to_string()))?;

        let local_tag = extract_tag_from_header_str(&from_header.to_string())?;

        // Extract remote tag (To header in response)
        let to_header = response
            .headers()
            .iter()
            .find(|h| matches!(h, rsip::Header::To(_)))
            .ok_or_else(|| Error::Parse("Missing To header".to_string()))?;

        let remote_tag = extract_tag_from_header_str(&to_header.to_string())?;

        Ok(Self::new(call_id, local_tag, remote_tag))
    }

    /// Create from INVITE request and 2xx response (UAS side)
    pub fn from_invite_uas(request: &Request, response: &Response) -> Result<Self> {
        // Extract Call-ID
        let call_id = extract_call_id_from_headers(request.headers())?;

        // Extract remote tag (From header in request)
        let from_header = request
            .headers()
            .iter()
            .find(|h| matches!(h, rsip::Header::From(_)))
            .ok_or_else(|| Error::Parse("Missing From header".to_string()))?;

        let remote_tag = extract_tag_from_header_str(&from_header.to_string())?;

        // Extract local tag (To header in response)
        let to_header = response
            .headers()
            .iter()
            .find(|h| matches!(h, rsip::Header::To(_)))
            .ok_or_else(|| Error::Parse("Missing To header".to_string()))?;

        let local_tag = extract_tag_from_header_str(&to_header.to_string())?;

        Ok(Self::new(call_id, local_tag, remote_tag))
    }

    /// Get a string representation
    pub fn as_string(&self) -> String {
        format!("{}:{}:{}", self.call_id, self.local_tag, self.remote_tag)
    }
}

/// Dialog state (RFC 3261 Section 12)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DialogState {
    /// Dialog in early state (1xx received)
    Early,

    /// Dialog confirmed (2xx received/sent)
    Confirmed,

    /// Dialog terminated (BYE sent/received)
    Terminated,
}

/// Dialog information
#[derive(Debug, Clone)]
pub struct Dialog {
    /// Dialog identifier
    pub id: DialogId,

    /// Current state
    pub state: DialogState,

    /// Local sequence number (CSeq)
    pub local_seq: u32,

    /// Remote sequence number (last received CSeq)
    pub remote_seq: u32,

    /// Local URI
    pub local_uri: String,

    /// Remote URI
    pub remote_uri: String,

    /// Remote target (Contact from remote)
    pub remote_target: String,

    /// Route set (from Record-Route)
    pub route_set: Vec<String>,

    /// Secure flag
    pub secure: bool,

    /// Creation time
    pub created_at: Instant,

    /// Last activity time
    pub last_activity: Instant,
}

impl Dialog {
    /// Create a new dialog from INVITE/200 OK (UAC side)
    pub fn new_uac(request: &Request, response: &Response, initial_seq: u32) -> Result<Self> {
        let id = DialogId::from_invite_uac(request, response)?;

        // Extract URIs
        let local_uri = extract_uri_from_header(request.headers(), "From")?;
        let remote_uri = extract_uri_from_header(response.headers(), "To")?;

        // Extract Contact (remote target)
        let remote_target = extract_contact(response.headers())?;

        // Extract route set from Record-Route (reverse order for UAC)
        let route_set = extract_route_set(response.headers(), true)?;

        Ok(Self {
            id,
            state: DialogState::Confirmed,
            local_seq: initial_seq,
            remote_seq: 0,
            local_uri,
            remote_uri,
            remote_target,
            route_set,
            secure: false, // TODO: detect from URI scheme
            created_at: Instant::now(),
            last_activity: Instant::now(),
        })
    }

    /// Create a new dialog from INVITE/200 OK (UAS side)
    pub fn new_uas(request: &Request, response: &Response) -> Result<Self> {
        let id = DialogId::from_invite_uas(request, response)?;

        // Extract CSeq from request
        let remote_seq = extract_cseq(request.headers())?;

        // Extract URIs
        let local_uri = extract_uri_from_header(response.headers(), "To")?;
        let remote_uri = extract_uri_from_header(request.headers(), "From")?;

        // Extract Contact (remote target)
        let remote_target = extract_contact(request.headers())?;

        // Extract route set from Record-Route (normal order for UAS)
        let route_set = extract_route_set(request.headers(), false)?;

        Ok(Self {
            id,
            state: DialogState::Confirmed,
            local_seq: 0, // Will be set when sending first in-dialog request
            remote_seq,
            local_uri,
            remote_uri,
            remote_target,
            route_set,
            secure: false,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        })
    }

    /// Update dialog state
    pub fn set_state(&mut self, state: DialogState) {
        self.state = state;
        self.last_activity = Instant::now();
    }

    /// Increment local sequence number
    pub fn increment_local_seq(&mut self) -> u32 {
        self.local_seq += 1;
        self.local_seq
    }

    /// Update remote sequence number
    pub fn update_remote_seq(&mut self, seq: u32) -> Result<()> {
        if seq < self.remote_seq {
            return Err(Error::Dialog(format!(
                "CSeq out of order: {} < {}",
                seq, self.remote_seq
            )));
        }
        self.remote_seq = seq;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Check if dialog is terminated
    pub fn is_terminated(&self) -> bool {
        self.state == DialogState::Terminated
    }

    /// Get dialog age
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> std::time::Duration {
        self.last_activity.elapsed()
    }
}

// Helper functions

fn extract_call_id_from_headers(headers: &rsip::Headers) -> Result<String> {
    let call_id_header = headers
        .iter()
        .find(|h| matches!(h, rsip::Header::CallId(_)))
        .ok_or_else(|| Error::Parse("Missing Call-ID header".to_string()))?;

    let call_id_str = call_id_header.to_string();
    // Format: "Call-ID: value"
    Ok(call_id_str
        .split(':')
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string())
}

fn extract_tag_from_header_str(header_str: &str) -> Result<String> {
    // Look for tag parameter
    if let Some(tag_start) = header_str.find("tag=") {
        let tag = &header_str[tag_start + 4..];
        let tag = tag.split(';').next().unwrap_or(tag).trim();
        Ok(tag.to_string())
    } else {
        Err(Error::Parse("Missing tag parameter".to_string()))
    }
}

fn extract_uri_from_header(headers: &rsip::Headers, header_name: &str) -> Result<String> {
    let header = headers
        .iter()
        .find(|h| h.to_string().starts_with(header_name))
        .ok_or_else(|| Error::Parse(format!("Missing {} header", header_name)))?;

    let header_str = header.to_string();
    // Extract URI from "<sip:...>"
    if let Some(start) = header_str.find('<') {
        if let Some(end) = header_str.find('>') {
            return Ok(header_str[start + 1..end].to_string());
        }
    }

    Err(Error::Parse(format!(
        "Could not extract URI from {}",
        header_name
    )))
}

fn extract_contact(headers: &rsip::Headers) -> Result<String> {
    let contact_header = headers
        .iter()
        .find(|h| matches!(h, rsip::Header::Contact(_)))
        .ok_or_else(|| Error::Parse("Missing Contact header".to_string()))?;

    let contact_str = contact_header.to_string();
    // Extract URI from Contact header
    if let Some(start) = contact_str.find('<') {
        if let Some(end) = contact_str.find('>') {
            return Ok(contact_str[start + 1..end].to_string());
        }
    }

    // Fallback: use value after "Contact: "
    Ok(contact_str
        .split(':')
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string())
}

fn extract_route_set(headers: &rsip::Headers, reverse: bool) -> Result<Vec<String>> {
    let mut routes = Vec::new();

    for header in headers.iter() {
        if matches!(header, rsip::Header::RecordRoute(_)) {
            let route_str = header.to_string();
            // Extract URI from Record-Route
            if let Some(start) = route_str.find('<') {
                if let Some(end) = route_str.find('>') {
                    routes.push(route_str[start + 1..end].to_string());
                }
            }
        }
    }

    // UAC reverses the order
    if reverse {
        routes.reverse();
    }

    Ok(routes)
}

fn extract_cseq(headers: &rsip::Headers) -> Result<u32> {
    let cseq_header = headers
        .iter()
        .find(|h| matches!(h, rsip::Header::CSeq(_)))
        .ok_or_else(|| Error::Parse("Missing CSeq header".to_string()))?;

    let cseq_str = cseq_header.to_string();
    // Format: "CSeq: 12345 INVITE"
    let parts: Vec<&str> = cseq_str.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1]
            .parse::<u32>()
            .map_err(|_| Error::Parse("Invalid CSeq number".to_string()))
    } else {
        Err(Error::Parse("Could not parse CSeq".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialog_id_creation() {
        let id = DialogId::new(
            "test-call@example.com".to_string(),
            "local-123".to_string(),
            "remote-456".to_string(),
        );

        assert_eq!(id.call_id, "test-call@example.com");
        assert_eq!(id.local_tag, "local-123");
        assert_eq!(id.remote_tag, "remote-456");
    }

    #[test]
    fn test_dialog_id_string() {
        let id = DialogId::new(
            "test-call@example.com".to_string(),
            "local-123".to_string(),
            "remote-456".to_string(),
        );

        assert_eq!(
            id.as_string(),
            "test-call@example.com:local-123:remote-456"
        );
    }

    #[test]
    fn test_dialog_state_transitions() {
        let id = DialogId::new(
            "test".to_string(),
            "local".to_string(),
            "remote".to_string(),
        );

        let mut dialog = Dialog {
            id,
            state: DialogState::Early,
            local_seq: 1,
            remote_seq: 0,
            local_uri: "sip:alice@example.com".to_string(),
            remote_uri: "sip:bob@example.com".to_string(),
            remote_target: "sip:bob@192.168.1.1".to_string(),
            route_set: vec![],
            secure: false,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };

        assert_eq!(dialog.state, DialogState::Early);

        dialog.set_state(DialogState::Confirmed);
        assert_eq!(dialog.state, DialogState::Confirmed);

        dialog.set_state(DialogState::Terminated);
        assert!(dialog.is_terminated());
    }

    #[test]
    fn test_dialog_sequence_numbers() {
        let id = DialogId::new(
            "test".to_string(),
            "local".to_string(),
            "remote".to_string(),
        );

        let mut dialog = Dialog {
            id,
            state: DialogState::Confirmed,
            local_seq: 1,
            remote_seq: 0,
            local_uri: "sip:alice@example.com".to_string(),
            remote_uri: "sip:bob@example.com".to_string(),
            remote_target: "sip:bob@192.168.1.1".to_string(),
            route_set: vec![],
            secure: false,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Increment local seq
        let seq = dialog.increment_local_seq();
        assert_eq!(seq, 2);
        assert_eq!(dialog.local_seq, 2);

        // Update remote seq
        assert!(dialog.update_remote_seq(100).is_ok());
        assert_eq!(dialog.remote_seq, 100);

        // Out of order should fail
        assert!(dialog.update_remote_seq(50).is_err());
    }
}
