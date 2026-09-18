//! Calls, registrations and CDR endpoints.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use super::{ApiError, ApiResult};
use crate::state::AppState;

pub async fn list_calls(State(state): State<AppState>) -> impl IntoResponse {
    let calls = state.b2bua.active_calls().await;
    let items: Vec<serde_json::Value> = calls
        .iter()
        .map(|c| {
            json!({
                "uuid": c.uuid,
                "state": c.state,
                "call_id": c.inbound_call_id,
                "caller": c.caller_addr,
                "callee": c.callee_addr,
                "duration_secs": c.duration_secs,
                "webrtc": c.is_webrtc,
                "media_session": c.media_session_id,
            })
        })
        .collect();
    Json(serde_json::Value::Array(items))
}

/// DELETE /api/v1/calls/{uuid} — administrative teardown. The SIP engine
/// ends the call (BYE/CANCEL on both legs, CDR "admin-kick") within its
/// next loop iteration; the call disappears from `GET /api/v1/calls` then.
pub async fn kick_call(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let active = state.b2bua.active_calls().await;
    if !active.iter().any(|c| c.uuid == uuid) {
        return Err(ApiError::not_found(format!("call '{}' not found", uuid)));
    }
    state.kicks.request(uuid.clone());
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "uuid": uuid, "terminating": true })),
    ))
}

pub async fn list_registrations(
    State(state): State<AppState>,
) -> ApiResult<Json<serde_json::Value>> {
    let regs = state
        .registrar
        .all_registrations()
        .await
        .map_err(ApiError::internal)?;
    let items: Vec<serde_json::Value> = regs
        .iter()
        .map(|r| {
            json!({
                "aor": r.aor,
                "contact": r.contact,
                "expires_in": r.remaining_secs(),
                "transport": r.transport,
                "received_ip": r.received_ip,
                "received_port": r.received_port,
                "user_agent": r.user_agent,
                "instance_id": r.instance_id,
                "reg_id": r.reg_id,
                "registered_at": r.registered_at,
            })
        })
        .collect();
    Ok(Json(serde_json::Value::Array(items)))
}

/// `GET /api/v1/cdrs` query: every field is a string so a bad value gets
/// the uniform `bad_request` JSON (a typed field would be rejected by
/// axum with a plain-text 400).
#[derive(Debug, Default, Deserialize)]
pub struct CdrQuery {
    pub limit: Option<String>,
    pub offset: Option<String>,
    pub cursor: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub direction: Option<String>,
    pub trunk: Option<String>,
    pub caller: Option<String>,
    pub callee: Option<String>,
    pub sip_code: Option<String>,
    pub answered: Option<String>,
    pub uuid: Option<String>,
    pub call_id: Option<String>,
    pub format: Option<String>,
}

fn default_limit() -> usize {
    100
}

/// RFC 3339 or bare unix seconds.
fn parse_time(name: &str, value: &str) -> ApiResult<i64> {
    if let Ok(secs) = value.trim().parse::<i64>() {
        return Ok(secs);
    }
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .map(|t| t.timestamp())
        .map_err(|_| ApiError::bad_request(format!("{}: expected RFC 3339 or unix seconds", name)))
}

struct ParsedQuery {
    filter: sbc_storage::CdrFilter,
    /// Any filter, cursor or explicit ordering beyond plain paging.
    filtered: bool,
    /// The caller's `limit`, when given (caps a CSV export).
    explicit_limit: Option<usize>,
    csv: bool,
}

fn parse_query(q: &CdrQuery, accept: Option<&str>) -> ApiResult<ParsedQuery> {
    let mut filter = sbc_storage::CdrFilter::default();
    let mut filtered = false;
    let explicit_limit = match &q.limit {
        Some(l) => {
            let n: usize = l
                .parse()
                .map_err(|_| ApiError::bad_request("limit: expected an integer"))?;
            if n == 0 {
                return Err(ApiError::bad_request("limit: must be at least 1"));
            }
            Some(n.min(1000))
        }
        None => None,
    };
    filter.limit = explicit_limit.unwrap_or_else(default_limit);
    if let Some(o) = &q.offset {
        filter.offset = o
            .parse()
            .map_err(|_| ApiError::bad_request("offset: expected an integer"))?;
    }
    if let Some(c) = &q.cursor {
        if q.offset.is_some() {
            return Err(ApiError::bad_request("offset and cursor are exclusive"));
        }
        let (started, rowid) = c
            .split_once(':')
            .and_then(|(a, b)| Some((a.parse::<i64>().ok()?, b.parse::<i64>().ok()?)))
            .ok_or_else(|| {
                ApiError::bad_request("cursor: use the next_cursor of a previous page")
            })?;
        filter.before = Some((started, rowid));
        filtered = true;
    }
    if let Some(f) = &q.from {
        filter.from = Some(parse_time("from", f)?);
        filtered = true;
    }
    if let Some(t) = &q.to {
        filter.to = Some(parse_time("to", t)?);
        filtered = true;
    }
    if let (Some(f), Some(t)) = (filter.from, filter.to) {
        if t <= f {
            return Err(ApiError::bad_request("to: must be after from"));
        }
    }
    if let Some(d) = &q.direction {
        if !matches!(d.as_str(), "inbound" | "outbound" | "local") {
            return Err(ApiError::bad_request(
                "direction: inbound, outbound or local",
            ));
        }
        filter.direction = Some(d.clone());
        filtered = true;
    }
    for (name, value, slot) in [
        ("caller", &q.caller, &mut filter.caller_prefix),
        ("callee", &q.callee, &mut filter.callee_prefix),
    ] {
        if let Some(v) = value {
            if v.is_empty() || v.chars().count() > 64 {
                return Err(ApiError::bad_request(format!(
                    "{}: 1 to 64 characters",
                    name
                )));
            }
            *slot = Some(v.clone());
            filtered = true;
        }
    }
    if let Some(t) = &q.trunk {
        filter.trunk = Some(t.clone());
        filtered = true;
    }
    if let Some(u) = &q.uuid {
        filter.uuid = Some(u.clone());
        filtered = true;
    }
    if let Some(cid) = &q.call_id {
        filter.call_id = Some(cid.clone());
        filtered = true;
    }
    if let Some(code) = &q.sip_code {
        let code: i64 = code
            .parse()
            .ok()
            .filter(|c| (100..700).contains(c))
            .ok_or_else(|| ApiError::bad_request("sip_code: a status code 100-699"))?;
        filter.sip_code = Some(code);
        filtered = true;
    }
    if let Some(a) = &q.answered {
        filter.answered = Some(match a.as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(ApiError::bad_request("answered: true or false")),
        });
        filtered = true;
    }
    let csv = match q.format.as_deref() {
        Some("csv") => true,
        Some("json") => false,
        Some(_) => return Err(ApiError::bad_request("format: json or csv")),
        None => accept.is_some_and(|a| a.contains("text/csv")),
    };
    Ok(ParsedQuery {
        filter,
        filtered,
        explicit_limit,
        csv,
    })
}

const CSV_HEADER: &str = "id,call_id,caller,callee,trunk_id,duration_secs,codec,is_webrtc,disconnect_reason,started_at,ended_at,v,uuid,direction,sip_code,answered_at,billable_secs,source_ip,reason,hangup_by";

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn csv_line(r: &sbc_storage::CdrRow) -> String {
    let opt = |o: &Option<String>| o.as_deref().map(csv_field).unwrap_or_default();
    let num = |o: Option<i64>| o.map(|n| n.to_string()).unwrap_or_default();
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\r\n",
        csv_field(&r.id),
        csv_field(&r.call_id),
        csv_field(&r.caller),
        csv_field(&r.callee),
        opt(&r.trunk_id),
        r.duration_secs,
        opt(&r.codec),
        r.is_webrtc,
        csv_field(&r.disconnect_reason),
        r.started_at,
        r.ended_at,
        r.v,
        csv_field(&r.uuid),
        csv_field(&r.direction),
        num(r.sip_code),
        num(r.answered_at),
        r.billable_secs,
        csv_field(&r.source_ip),
        opt(&r.reason),
        csv_field(&r.hangup_by),
    )
}

/// CDRs newest first. Without a store only plain paging of the in-memory
/// cache is served (filters and CSV need the store → 503).
pub async fn list_cdrs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<CdrQuery>,
) -> ApiResult<axum::response::Response> {
    let accept = headers.get("accept").and_then(|v| v.to_str().ok());
    let parsed = parse_query(&q, accept)?;
    if !state.cdr.has_store() {
        if parsed.filtered || parsed.csv {
            return Err(ApiError::store_unavailable());
        }
        let limit = parsed.filter.limit;
        let offset = parsed.filter.offset;
        let (page, fetched) = state
            .cdr
            .get_page(limit, offset)
            .await
            .map_err(ApiError::internal)?;
        let items: Vec<String> = page.iter().map(|c| c.to_json()).collect();
        let body = format!(
            r#"{{"items":[{}],"count":{},"limit":{},"offset":{},"has_more":{},"next_cursor":null}}"#,
            items.join(","),
            items.len(),
            limit,
            offset,
            fetched == offset + limit,
        );
        return Ok(([("content-type", "application/json")], body).into_response());
    }
    if parsed.csv {
        return Ok(csv_stream(state, parsed));
    }
    let (rows, has_more) = state
        .cdr
        .page(&parsed.filter)
        .await
        .map_err(ApiError::internal)?;
    let next_cursor = if has_more {
        rows.last()
            .map(|r| format!("\"{}:{}\"", r.started_at, r.rowid))
            .unwrap_or_else(|| "null".into())
    } else {
        "null".into()
    };
    let items: Vec<String> = rows
        .iter()
        .map(|r| sbc_core::storage::CdrRecord::from(r.clone()).to_json())
        .collect();
    let body = format!(
        r#"{{"items":[{}],"count":{},"limit":{},"offset":{},"has_more":{},"next_cursor":{}}}"#,
        items.join(","),
        items.len(),
        parsed.filter.limit,
        parsed.filter.offset,
        has_more,
        next_cursor,
    );
    Ok(([("content-type", "application/json")], body).into_response())
}

/// Stream every matching row as CSV, paging the store by keyset so no
/// connection is held for the whole download.
fn csv_stream(state: AppState, parsed: ParsedQuery) -> axum::response::Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(8);
    let cap = parsed.explicit_limit;
    let mut filter = parsed.filter;
    filter.offset = 0;
    filter.limit = 1000;
    tokio::spawn(async move {
        if tx
            .send(Ok(axum::body::Bytes::from(format!("{}\r\n", CSV_HEADER))))
            .await
            .is_err()
        {
            return;
        }
        let mut sent = 0usize;
        loop {
            if let Some(cap) = cap {
                let left = cap - sent;
                if left == 0 {
                    break;
                }
                filter.limit = left.min(1000);
            }
            let (rows, more) = match state.cdr.page(&filter).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("CDR CSV export interrupted: {}", e);
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    return;
                }
            };
            let chunk: String = rows.iter().map(csv_line).collect();
            if !chunk.is_empty() && tx.send(Ok(axum::body::Bytes::from(chunk))).await.is_err() {
                return;
            }
            sent += rows.len();
            match rows.last() {
                Some(last) if more => filter.before = Some((last.started_at, last.rowid)),
                _ => break,
            }
        }
    });
    let body = axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    (
        StatusCode::OK,
        [
            ("content-type", "text/csv; charset=utf-8"),
            ("content-disposition", "attachment; filename=\"cdrs.csv\""),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response()
}
