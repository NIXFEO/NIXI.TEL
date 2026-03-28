//! Outbound REGISTER helpers for trunk registration
//!
//! Provides utility functions for parsing SIP responses in the
//! outbound REGISTER flow. The actual registration loop is in sbc.rs.

/// Parse the status code from a raw SIP response (e.g. "SIP/2.0 200 OK\r\n..." → 200)
pub fn parse_status(raw: &str) -> u16 {
    let first_line = raw.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().unwrap_or(0)
    } else {
        0
    }
}

/// Parse the Expires value from a SIP response
pub fn parse_expires(raw: &str) -> Option<u32> {
    for line in raw.lines() {
        if line.to_lowercase().starts_with("expires:") {
            let val = line.split(':').nth(1)?.trim();
            return val.parse().ok();
        }
        // Also check Contact header for expires param
        if line.to_lowercase().starts_with("contact:") {
            if let Some(pos) = line.to_lowercase().find("expires=") {
                let rest = &line[pos + 8..];
                let val = rest.split(|c: char| !c.is_ascii_digit()).next()?;
                return val.parse().ok();
            }
        }
    }
    None
}

/// Extract a header value from raw SIP message by header name (case-insensitive)
pub fn extract_header(raw: &str, header_name: &str) -> Option<String> {
    let header_lower = header_name.to_lowercase();
    for line in raw.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with(&format!("{}:", header_lower)) {
            if let Some(colon_pos) = line.find(':') {
                return Some(line[colon_pos + 1..].trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status() {
        assert_eq!(parse_status("SIP/2.0 200 OK\r\n"), 200);
        assert_eq!(parse_status("SIP/2.0 401 Unauthorized\r\n"), 401);
        assert_eq!(parse_status("SIP/2.0 407 Proxy Authentication Required\r\n"), 407);
        assert_eq!(parse_status(""), 0);
    }

    #[test]
    fn test_parse_expires() {
        let raw = "SIP/2.0 200 OK\r\nExpires: 3600\r\n\r\n";
        assert_eq!(parse_expires(raw), Some(3600));

        let raw2 = "SIP/2.0 200 OK\r\nContact: <sip:foo@bar>;expires=300\r\n\r\n";
        assert_eq!(parse_expires(raw2), Some(300));
    }

    #[test]
    fn test_extract_header() {
        let raw = "SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"trunk.example.com\", nonce=\"abc123\"\r\n\r\n";
        let val = extract_header(raw, "www-authenticate");
        assert!(val.is_some());
        assert!(val.unwrap().contains("Digest"));
    }
}
