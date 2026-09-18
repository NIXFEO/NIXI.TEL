//! Per-trunk background tasks that follow the trunk table.
//!
//! One OPTIONS health-check loop and, for trunks with `register_with_trunk`,
//! one outbound REGISTER loop per *enabled* trunk. [`TrunkTasks::sync`]
//! diffs the running tasks against the [`TrunkManager`]: a trunk created,
//! enabled, disabled or deleted through the API or a reload gets its tasks
//! started or stopped, and a change of host, port, transport, credentials
//! or registration interval restarts them. `sync` never blocks (a std
//! mutex, a cancellation token and `tokio::spawn`), so it is safe from an
//! API handler and from the SIP event loop.
//!
//! Both loops send over the shared UDP socket the SIP listener uses (the
//! trunk must see the same source address for REGISTER, OPTIONS and
//! INVITE); the event loop routes the answers by their `reg-` / `hc-`
//! Call-ID through [`PendingResponses`].
//!
//! REGISTER: a `423 Interval Too Brief` is retried once with the trunk's
//! `Min-Expires`, which is remembered for the following refreshes; a
//! refused or unanswered REGISTER backs off exponentially (30 s → 15 min,
//! reset on success) instead of hammering the trunk every minute; an
//! OPTIONS down→up transition wakes a backed-off loop immediately.
use crate::auth::{generate_digest_response, DigestChallenge};
use crate::events::{event_ts, EventBus, SbcEvent};
use crate::metrics::SbcMetrics;
use crate::routing::{TransportType, TrunkConfig, TrunkId, TrunkManager};
use crate::topology::SbcIdentity;
use crate::trunk_register::{extract_header, parse_expires, parse_status};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Call-ID → the task waiting for that response (filled by the tasks,
/// drained by the event loop's response handler).
pub type PendingResponses = Arc<DashMap<String, oneshot::Sender<String>>>;

/// What a trunk's tasks were started with. Any difference restarts them;
/// fields that do not affect probing or registration (priority, prefixes,
/// codecs, limits…) are deliberately absent. `enabled` is not part of it:
/// a disabled trunk simply has no entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TaskSpec {
    pub id: TrunkId,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub transport: TransportType,
    pub dest: Option<SocketAddr>,
    pub register: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub realm: Option<String>,
    pub registration_interval: Duration,
}

impl TaskSpec {
    pub fn from_config(t: &TrunkConfig) -> Self {
        Self {
            id: t.id,
            name: t.name.clone(),
            host: t.host.clone(),
            port: t.port,
            transport: t.transport,
            dest: t.destination(),
            register: t.register_with_trunk,
            username: t.username.clone(),
            password: t.password.clone(),
            realm: t.realm.clone(),
            registration_interval: t.registration_interval,
        }
    }
}

/// Timings of the loops (`[trunk_health]` in the TOML; boot-only).
#[derive(Clone, Debug)]
pub struct TrunkTasksConfig {
    /// Delay before the first OPTIONS probe (lets the listeners settle).
    pub initial_delay: Duration,
    pub options_interval: Duration,
    pub options_timeout: Duration,
    pub register_timeout: Duration,
    /// Floor of the refresh period (0.8 × granted Expires is clamped to it).
    pub refresh_min: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl Default for TrunkTasksConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(5),
            options_interval: Duration::from_secs(30),
            options_timeout: Duration::from_secs(5),
            register_timeout: Duration::from_secs(10),
            refresh_min: Duration::from_secs(30),
            backoff_min: Duration::from_secs(30),
            backoff_max: Duration::from_secs(900),
        }
    }
}

impl From<&crate::config::TrunkHealthConfig> for TrunkTasksConfig {
    fn from(c: &crate::config::TrunkHealthConfig) -> Self {
        let d = Self::default();
        Self {
            options_interval: Duration::from_secs(c.options_interval.max(1)),
            options_timeout: Duration::from_secs(c.options_timeout.max(1)),
            backoff_max: Duration::from_secs(c.register_backoff_max.max(1)),
            ..d
        }
    }
}

/// Exponential backoff: `next_wait()` returns the current wait and doubles it
/// up to `max`; `reset()` goes back to `min`.
#[derive(Debug)]
pub struct Backoff {
    cur: Duration,
    min: Duration,
    max: Duration,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        let max = max.max(min);
        Self { cur: min, min, max }
    }

    pub fn next_wait(&mut self) -> Duration {
        let wait = self.cur;
        self.cur = (self.cur * 2).min(self.max);
        wait
    }

    pub fn reset(&mut self) {
        self.cur = self.min;
    }
}

/// Why a REGISTER cycle did not register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    Registered { granted: u32 },
    IntervalTooBrief { min_expires: u32 },
    Refused { status: u16 },
    Timeout,
    SendFailed(String),
    Malformed(String),
    Cancelled,
}

impl RegisterOutcome {
    /// Short reason for logs and the `trunk_unregistered` event.
    pub fn reason(&self) -> String {
        match self {
            Self::Registered { .. } => "registered".into(),
            Self::IntervalTooBrief { min_expires } => format!("423 (Min-Expires {})", min_expires),
            Self::Refused { status } => status.to_string(),
            Self::Timeout => "timeout".into(),
            Self::SendFailed(e) => format!("send-failed: {}", e),
            Self::Malformed(e) => format!("malformed: {}", e),
            Self::Cancelled => "cancelled".into(),
        }
    }
}

struct Ctx {
    trunks: Arc<TrunkManager>,
    pending: PendingResponses,
    identity: Option<SbcIdentity>,
    metrics: Arc<SbcMetrics>,
    events: EventBus,
    config: TrunkTasksConfig,
    socket: Arc<UdpSocket>,
}

impl Ctx {
    /// The address the trunk sees us at: the public IP, else loopback.
    fn local_ip(&self) -> String {
        self.identity
            .as_ref()
            .map(|id| id.public_ip.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    }
}

struct Running {
    spec: TaskSpec,
    generation: u64,
    cancel: CancellationToken,
    health: JoinHandle<()>,
    register: Option<JoinHandle<()>>,
}

/// One running trunk, for the API and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningInfo {
    pub name: String,
    pub generation: u64,
    pub registers: bool,
}

/// The registry of per-trunk tasks.
pub struct TrunkTasks {
    trunks: Arc<TrunkManager>,
    pending: PendingResponses,
    identity: Option<SbcIdentity>,
    metrics: Arc<SbcMetrics>,
    events: EventBus,
    config: TrunkTasksConfig,
    socket: OnceLock<Arc<UdpSocket>>,
    running: Mutex<HashMap<String, Running>>,
    generation: AtomicU64,
}

impl TrunkTasks {
    pub fn new(
        trunks: Arc<TrunkManager>,
        pending: PendingResponses,
        identity: Option<SbcIdentity>,
        metrics: Arc<SbcMetrics>,
        events: EventBus,
        config: TrunkTasksConfig,
    ) -> Self {
        Self {
            trunks,
            pending,
            identity,
            metrics,
            events,
            config,
            socket: OnceLock::new(),
            running: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
        }
    }

    /// The UDP socket the tasks send from (the SIP listener's). Until it is
    /// attached, `sync` does nothing. False when one was already attached.
    pub fn attach_socket(&self, sock: Arc<UdpSocket>) -> bool {
        self.socket.set(sock).is_ok()
    }

    pub fn has_socket(&self) -> bool {
        self.socket.get().is_some()
    }

    /// Bring the running tasks in line with the trunk table: stop the
    /// tasks of trunks that vanished, were disabled or changed; start the
    /// missing ones. Non-blocking.
    pub fn sync(&self) {
        let Some(socket) = self.socket.get() else {
            debug!("Trunk tasks: no UDP socket yet — nothing started");
            return;
        };
        let desired: HashMap<String, TaskSpec> = self
            .trunks
            .list_trunks()
            .iter()
            .filter(|t| t.enabled)
            .map(|t| (t.name.clone(), TaskSpec::from_config(t)))
            .collect();

        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);

        let stale: Vec<String> = running
            .iter()
            .filter(|(name, r)| desired.get(*name) != Some(&r.spec))
            .map(|(name, _)| name.clone())
            .collect();
        for name in stale {
            let Some(r) = running.remove(&name) else {
                continue;
            };
            let why = if desired.contains_key(&name) {
                "changed — restarting its tasks"
            } else {
                "removed or disabled — stopping its tasks"
            };
            info!("Trunk '{}' {}", name, why);
            r.cancel.cancel();
            self.trunks
                .update_state(&r.spec.id, |s| s.registered = false);
            self.metrics.set_trunk_up(&name, None);
            self.metrics.set_trunk_registered(&name, None);
        }

        let mut to_start: Vec<(String, TaskSpec)> = desired
            .into_iter()
            .filter(|(name, _)| !running.contains_key(name))
            .collect();
        to_start.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, spec) in to_start {
            let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
            let cancel = CancellationToken::new();
            let wake = Arc::new(Notify::new());
            let ctx = Arc::new(Ctx {
                trunks: self.trunks.clone(),
                pending: self.pending.clone(),
                identity: self.identity.clone(),
                metrics: self.metrics.clone(),
                events: self.events.clone(),
                config: self.config.clone(),
                socket: socket.clone(),
            });
            info!(
                "Trunk '{}': starting OPTIONS health check{} ({}:{})",
                name,
                if spec.register {
                    " and outbound REGISTER"
                } else {
                    ""
                },
                spec.host,
                spec.port
            );
            let health = tokio::spawn(health_loop(
                ctx.clone(),
                spec.clone(),
                cancel.child_token(),
                wake.clone(),
            ));
            let register = spec.register.then(|| {
                tokio::spawn(register_loop(
                    ctx.clone(),
                    spec.clone(),
                    cancel.child_token(),
                    wake.clone(),
                ))
            });
            running.insert(
                name,
                Running {
                    spec,
                    generation,
                    cancel,
                    health,
                    register,
                },
            );
        }
    }

    /// The trunks with running tasks, sorted by name.
    pub fn running(&self) -> Vec<RunningInfo> {
        let running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out: Vec<RunningInfo> = running
            .iter()
            .map(|(name, r)| RunningInfo {
                name: name.clone(),
                generation: r.generation,
                registers: r.register.is_some(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Stop every task; registered trunks get a best-effort `Expires: 0`
    /// (bounded: the SIP loop may already be gone at process shutdown).
    pub async fn shutdown(&self) {
        let handles: Vec<(JoinHandle<()>, Option<JoinHandle<()>>)> = {
            let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
            running
                .drain()
                .map(|(_, r)| {
                    r.cancel.cancel();
                    (r.health, r.register)
                })
                .collect()
        };
        let wait = async {
            for (health, register) in handles {
                let _ = health.await;
                if let Some(r) = register {
                    let _ = r.await;
                }
            }
        };
        if tokio::time::timeout(Duration::from_secs(3), wait)
            .await
            .is_err()
        {
            debug!("Trunk tasks: shutdown wait elapsed — leaving the rest to the runtime");
        }
    }
}

fn rand8() -> String {
    uuid::Uuid::new_v4().to_string()[..8].to_string()
}

fn branch() -> String {
    format!(
        "z9hG4bK{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..16]
    )
}

/// True when cancelled during the sleep.
async fn sleep_or_cancel(d: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = cancel.cancelled() => true,
    }
}

// ── OPTIONS health check ─────────────────────────────────────────────────────

async fn health_loop(
    ctx: Arc<Ctx>,
    spec: TaskSpec,
    cancel: CancellationToken,
    wake_register: Arc<Notify>,
) {
    let name = spec.name.clone();
    let mut was_up = true;
    let mut ever_responded = false;
    if sleep_or_cancel(ctx.config.initial_delay, &cancel).await {
        return;
    }
    loop {
        let Some(dest) = spec.dest else {
            warn!("Trunk '{}': no destination for health check (DNS)", name);
            if sleep_or_cancel(ctx.config.options_interval, &cancel).await {
                return;
            }
            continue;
        };
        let call_id = format!("hc-{}-{}", name, rand8());
        let local_ip = ctx.local_ip();
        let msg = format!(
            "OPTIONS sip:{host}:{port} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {ip}:5060;branch={branch};rport\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:healthcheck@{ip}>;tag={tag}\r\n\
             To: <sip:{host}:{port}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: 1 OPTIONS\r\n\
             User-Agent: NIXI-SBC/1.0\r\n\
             Content-Length: 0\r\n\r\n",
            host = spec.host,
            port = spec.port,
            ip = local_ip,
            branch = branch(),
            tag = rand8(),
            call_id = call_id,
        );
        let (tx, rx) = oneshot::channel::<String>();
        ctx.pending.insert(call_id.clone(), tx);
        let is_up = match ctx.socket.send_to(msg.as_bytes(), dest).await {
            Ok(_) => tokio::select! {
                r = tokio::time::timeout(ctx.config.options_timeout, rx) => match r {
                    Ok(Ok(raw)) => (200..500).contains(&parse_status(&raw)),
                    _ => {
                        ctx.pending.remove(&call_id);
                        false
                    }
                },
                _ = cancel.cancelled() => {
                    ctx.pending.remove(&call_id);
                    return;
                }
            },
            Err(e) => {
                ctx.pending.remove(&call_id);
                debug!("Trunk '{}': OPTIONS send failed: {}", name, e);
                false
            }
        };

        // sbc_trunk_up once the trunk has answered at least once; a trunk
        // that ignores OPTIONS is monitored passively and not exported.
        if is_up {
            ctx.metrics.set_trunk_up(&name, Some(true));
        } else if ever_responded {
            ctx.metrics.set_trunk_up(&name, Some(false));
        }

        if is_up {
            ever_responded = true;
            if !was_up {
                info!("Trunk '{}' is UP — responding to OPTIONS", name);
                ctx.trunks.update_state(&spec.id, |s| s.record_success());
                ctx.events.publish(SbcEvent::TrunkHealth {
                    trunk: name.clone(),
                    status: "up".to_string(),
                    consecutive_failures: 0,
                    ts: event_ts(),
                });
                wake_register.notify_one();
            }
        } else if ever_responded {
            ctx.trunks
                .update_state(&spec.id, |s| s.record_trunk_failure());
            if was_up {
                warn!(
                    "Trunk '{}' is DOWN — no response to OPTIONS ({:?})",
                    name, ctx.config.options_timeout
                );
                let failures = ctx
                    .trunks
                    .get_state(&spec.id)
                    .map(|s| s.consecutive_failures)
                    .unwrap_or(1);
                ctx.events.publish(SbcEvent::TrunkHealth {
                    trunk: name.clone(),
                    status: "down".to_string(),
                    consecutive_failures: failures,
                    ts: event_ts(),
                });
            } else {
                debug!("Trunk '{}' still DOWN", name);
            }
        } else if was_up {
            info!(
                "Trunk '{}' does not respond to OPTIONS — health check passive only",
                name
            );
        }
        was_up = is_up;
        if sleep_or_cancel(ctx.config.options_interval, &cancel).await {
            return;
        }
    }
}

// ── Outbound REGISTER ────────────────────────────────────────────────────────

async fn register_loop(
    ctx: Arc<Ctx>,
    spec: TaskSpec,
    cancel: CancellationToken,
    wake: Arc<Notify>,
) {
    let name = spec.name.clone();
    let interval = spec.registration_interval.max(ctx.config.refresh_min);
    let mut expires: u32 = spec
        .registration_interval
        .as_secs()
        .clamp(1, u32::MAX as u64) as u32;
    let mut backoff = Backoff::new(ctx.config.backoff_min, ctx.config.backoff_max);
    let mut registered = false;
    let mut failure_announced = false;

    loop {
        info!("Trunk '{}': sending REGISTER (Expires {})", name, expires);
        let mut outcome = send_register(&ctx, &spec, expires, &cancel).await;
        if let RegisterOutcome::IntervalTooBrief { min_expires } = outcome {
            if min_expires > expires {
                info!(
                    "Trunk '{}': 423 Interval Too Brief, Min-Expires {} — re-registering with it",
                    name, min_expires
                );
                expires = min_expires;
                outcome = send_register(&ctx, &spec, expires, &cancel).await;
            }
        }
        if outcome == RegisterOutcome::Cancelled {
            break;
        }
        let wait = match outcome {
            RegisterOutcome::Registered { granted } => {
                ctx.trunks.update_state(&spec.id, |s| s.registered = true);
                ctx.metrics.set_trunk_registered(&name, Some(true));
                if !registered {
                    info!("Trunk '{}': registered (expires {}s)", name, granted);
                    ctx.events.publish(SbcEvent::TrunkRegistered {
                        trunk: name.clone(),
                        expires: granted,
                        ts: event_ts(),
                    });
                } else {
                    debug!("Trunk '{}': registration refreshed ({}s)", name, granted);
                }
                registered = true;
                failure_announced = false;
                backoff.reset();
                let refresh = Duration::from_secs((u64::from(granted) * 8 / 10).max(1));
                refresh.clamp(ctx.config.refresh_min, interval)
            }
            failure => {
                let reason = failure.reason();
                ctx.trunks.update_state(&spec.id, |s| s.registered = false);
                ctx.metrics.set_trunk_registered(&name, Some(false));
                if registered || !failure_announced {
                    ctx.events.publish(SbcEvent::TrunkUnregistered {
                        trunk: name.clone(),
                        reason: reason.clone(),
                        ts: event_ts(),
                    });
                }
                registered = false;
                failure_announced = true;
                let wait = backoff.next_wait();
                warn!(
                    "Trunk '{}': REGISTER failed ({}) — retrying in {:?}",
                    name, reason, wait
                );
                wait
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = wake.notified() => debug!("Trunk '{}': health up — registering now", name),
            _ = cancel.cancelled() => break,
        }
    }

    // Stopped (trunk removed, disabled, changed, or shutdown): best-effort
    // un-register so the trunk does not keep a dead binding.
    if registered {
        let _ = tokio::time::timeout(
            ctx.config.register_timeout,
            send_register(&ctx, &spec, 0, &CancellationToken::new()),
        )
        .await;
    }
    ctx.trunks.update_state(&spec.id, |s| s.registered = false);
}

/// Send the request, wait for the answer routed by the event loop.
async fn send_and_wait(
    ctx: &Ctx,
    call_id: &str,
    msg: String,
    dest: SocketAddr,
    cancel: &CancellationToken,
) -> Result<String, RegisterOutcome> {
    let (tx, rx) = oneshot::channel::<String>();
    ctx.pending.insert(call_id.to_string(), tx);
    if let Err(e) = ctx.socket.send_to(msg.as_bytes(), dest).await {
        ctx.pending.remove(call_id);
        return Err(RegisterOutcome::SendFailed(e.to_string()));
    }
    tokio::select! {
        r = tokio::time::timeout(ctx.config.register_timeout, rx) => match r {
            Ok(Ok(raw)) => Ok(raw),
            Ok(Err(_)) => {
                ctx.pending.remove(call_id);
                Err(RegisterOutcome::Malformed("response channel closed".into()))
            }
            Err(_) => {
                ctx.pending.remove(call_id);
                Err(RegisterOutcome::Timeout)
            }
        },
        _ = cancel.cancelled() => {
            ctx.pending.remove(call_id);
            Err(RegisterOutcome::Cancelled)
        }
    }
}

fn build_register(
    spec: &TaskSpec,
    local_ip: &str,
    call_id: &str,
    cseq: u32,
    from: &str,
    expires: u32,
    auth: Option<(&str, &str)>,
) -> String {
    let username = spec.username.as_deref().unwrap_or("anonymous");
    let auth_line = auth
        .map(|(h, v)| format!("{}: {}\r\n", h, v))
        .unwrap_or_default();
    format!(
        "REGISTER sip:{host} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {ip}:5060;branch={branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: {from}\r\n\
         To: <sip:{user}@{host}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <sip:{user}@{ip}:5060;transport=udp>\r\n\
         {auth}Expires: {expires}\r\n\
         User-Agent: NIXI-SBC/1.0\r\n\
         Content-Length: 0\r\n\r\n",
        host = spec.host,
        ip = local_ip,
        branch = branch(),
        from = from,
        user = username,
        call_id = call_id,
        cseq = cseq,
        auth = auth_line,
        expires = expires,
    )
}

/// One REGISTER cycle: request, one Digest retry on 401/407, outcome.
async fn send_register(
    ctx: &Ctx,
    spec: &TaskSpec,
    expires: u32,
    cancel: &CancellationToken,
) -> RegisterOutcome {
    let Some(dest) = spec.dest else {
        return RegisterOutcome::SendFailed("no destination (DNS)".into());
    };
    let call_id = format!("reg-{}-{}", spec.name, rand8());
    let local_ip = ctx.local_ip();
    let username = spec.username.as_deref().unwrap_or("anonymous");
    let from = format!("<sip:{}@{}>;tag={}", username, spec.host, rand8());
    let request_uri = format!("sip:{}", spec.host);

    let first = build_register(spec, &local_ip, &call_id, 1, &from, expires, None);
    let raw = match send_and_wait(ctx, &call_id, first, dest, cancel).await {
        Ok(raw) => raw,
        Err(outcome) => return outcome,
    };
    match parse_status(&raw) {
        200 => RegisterOutcome::Registered {
            granted: parse_expires(&raw).unwrap_or(expires),
        },
        423 => min_expires_of(&raw),
        status @ (401 | 407) => {
            let header = if status == 401 {
                "www-authenticate"
            } else {
                "proxy-authenticate"
            };
            let Some(challenge_str) = extract_header(&raw, header) else {
                return RegisterOutcome::Malformed(format!("no {} in {}", header, status));
            };
            let challenge = match DigestChallenge::from_header(&challenge_str) {
                Ok(c) => c,
                Err(e) => return RegisterOutcome::Malformed(format!("bad challenge: {}", e)),
            };
            let auth_value = generate_digest_response(
                username,
                spec.password.as_deref().unwrap_or(""),
                &challenge,
                "REGISTER",
                &request_uri,
            );
            debug!(
                "Trunk '{}': {} challenge (realm '{}'), retrying with credentials",
                spec.name, status, challenge.realm
            );
            let auth_header = if status == 401 {
                "Authorization"
            } else {
                "Proxy-Authorization"
            };
            let second = build_register(
                spec,
                &local_ip,
                &call_id,
                2,
                &from,
                expires,
                Some((auth_header, &auth_value)),
            );
            let raw2 = match send_and_wait(ctx, &call_id, second, dest, cancel).await {
                Ok(raw) => raw,
                Err(outcome) => return outcome,
            };
            match parse_status(&raw2) {
                200 => RegisterOutcome::Registered {
                    granted: parse_expires(&raw2).unwrap_or(expires),
                },
                423 => min_expires_of(&raw2),
                s => RegisterOutcome::Refused { status: s },
            }
        }
        s => RegisterOutcome::Refused { status: s },
    }
}

fn min_expires_of(raw: &str) -> RegisterOutcome {
    match extract_header(raw, "min-expires").and_then(|v| v.trim().parse::<u32>().ok()) {
        Some(min_expires) if min_expires > 0 => RegisterOutcome::IntervalTooBrief { min_expires },
        _ => RegisterOutcome::Malformed("423 without a usable Min-Expires".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    fn fast_config() -> TrunkTasksConfig {
        TrunkTasksConfig {
            initial_delay: Duration::from_millis(5),
            options_interval: Duration::from_millis(30),
            options_timeout: Duration::from_millis(60),
            register_timeout: Duration::from_millis(200),
            refresh_min: Duration::from_millis(20),
            backoff_min: Duration::from_millis(20),
            backoff_max: Duration::from_millis(80),
        }
    }

    /// A fake trunk on loopback: answers with `reply(request) -> Option<status line + extra headers>`.
    struct Peer {
        sock: Arc<UdpSocket>,
        addr: SocketAddr,
    }

    impl Peer {
        async fn new() -> Self {
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let addr = sock.local_addr().unwrap();
            Self { sock, addr }
        }

        /// Receive one request (with a deadline), return its text.
        async fn recv(&self) -> Option<String> {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_secs(2), self.sock.recv_from(&mut buf)).await
            {
                Ok(Ok((n, _))) => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
                _ => None,
            }
        }

        /// Answer `request` with `status` and `extra` headers, delivering it
        /// the way the event loop does (by Call-ID through `pending`).
        fn answer(&self, pending: &PendingResponses, request: &str, status: &str, extra: &str) {
            let call_id = extract_header(request, "call-id").unwrap();
            let cseq = extract_header(request, "cseq").unwrap();
            let raw = format!(
                "SIP/2.0 {}\r\nCall-ID: {}\r\nCSeq: {}\r\n{}Content-Length: 0\r\n\r\n",
                status, call_id, cseq, extra
            );
            if let Some((_, tx)) = pending.remove(&call_id) {
                let _ = tx.send(raw);
            }
        }
    }

    fn harness(peer: &Peer, register: bool) -> (Arc<TrunkManager>, TrunkId) {
        let trunks = Arc::new(TrunkManager::new());
        let mut t = TrunkConfig::new("t1".into());
        t.host = "127.0.0.1".into();
        t.port = peer.addr.port();
        t.register_with_trunk = register;
        t.username = Some("u".into());
        t.password = Some("p".into());
        // Short so refreshes come within the test (Expires: 1 on the wire).
        t.registration_interval = Duration::from_secs(1);
        let id = trunks.add_trunk(t);
        (trunks, id)
    }

    async fn tasks(
        trunks: Arc<TrunkManager>,
        metrics: Arc<SbcMetrics>,
        events: EventBus,
    ) -> Arc<TrunkTasks> {
        let tasks = Arc::new(TrunkTasks::new(
            trunks,
            Default::default(),
            None,
            metrics,
            events,
            fast_config(),
        ));
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        assert!(tasks.attach_socket(sock));
        tasks
    }

    async fn next_event(
        rx: &mut broadcast::Receiver<SbcEvent>,
        pred: impl Fn(&SbcEvent) -> bool,
    ) -> SbcEvent {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match rx.recv().await {
                    Ok(e) if pred(&e) => return e,
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => panic!("event bus closed"),
                }
            }
        })
        .await
        .expect("event within 2 s")
    }

    #[test]
    fn backoff_doubles_up_to_max_and_resets() {
        let mut b = Backoff::new(Duration::from_millis(20), Duration::from_millis(80));
        assert_eq!(b.next_wait(), Duration::from_millis(20));
        assert_eq!(b.next_wait(), Duration::from_millis(40));
        assert_eq!(b.next_wait(), Duration::from_millis(80));
        assert_eq!(b.next_wait(), Duration::from_millis(80));
        b.reset();
        assert_eq!(b.next_wait(), Duration::from_millis(20));
    }

    #[test]
    fn min_expires_is_parsed() {
        assert_eq!(
            min_expires_of("SIP/2.0 423 Interval Too Brief\r\nMin-Expires: 3600\r\n\r\n"),
            RegisterOutcome::IntervalTooBrief { min_expires: 3600 }
        );
        assert!(matches!(
            min_expires_of("SIP/2.0 423 Interval Too Brief\r\n\r\n"),
            RegisterOutcome::Malformed(_)
        ));
    }

    #[tokio::test]
    async fn sync_starts_stops_and_restarts_tasks_from_the_manager() {
        let peer = Peer::new().await;
        let (trunks, id) = harness(&peer, true);
        let mut t2 = TrunkConfig::new("t2".into());
        t2.host = "127.0.0.1".into();
        t2.port = peer.addr.port();
        trunks.add_trunk(t2);
        let tasks = tasks(trunks.clone(), Arc::new(SbcMetrics::new()), EventBus::new()).await;

        tasks.sync();
        let r = tasks.running();
        assert_eq!(
            r,
            vec![
                RunningInfo {
                    name: "t1".into(),
                    generation: 1,
                    registers: true
                },
                RunningInfo {
                    name: "t2".into(),
                    generation: 2,
                    registers: false
                }
            ]
        );

        // No change: same generations.
        tasks.sync();
        assert_eq!(tasks.running(), r);

        // Disabled: stopped.
        trunks.disable_trunk(&id);
        tasks.sync();
        assert_eq!(tasks.running().len(), 1);
        assert_eq!(tasks.running()[0].name, "t2");

        // Enabled again with a new password: fresh generation.
        trunks.enable_trunk(&id);
        let mut cfg = trunks.get_trunk(&id).unwrap();
        cfg.password = Some("new".into());
        trunks.update_trunk_by_name("t1", cfg);
        tasks.sync();
        let t1 = tasks
            .running()
            .into_iter()
            .find(|r| r.name == "t1")
            .unwrap();
        assert!(t1.generation > 2);
        let mut cfg = trunks.get_trunk(&id).unwrap();
        cfg.priority = 9;
        trunks.update_trunk_by_name("t1", cfg);
        tasks.sync();
        assert_eq!(
            tasks
                .running()
                .into_iter()
                .find(|r| r.name == "t1")
                .unwrap()
                .generation,
            t1.generation,
            "priority is not part of the task spec"
        );

        // Deleted: gone.
        trunks.remove_by_name("t2");
        tasks.sync();
        assert_eq!(tasks.running().len(), 1);
        tasks.shutdown().await;
        assert!(tasks.running().is_empty());
    }

    #[tokio::test]
    async fn sync_without_socket_is_a_noop() {
        let peer = Peer::new().await;
        let (trunks, _) = harness(&peer, false);
        let tasks = TrunkTasks::new(
            trunks,
            Default::default(),
            None,
            Arc::new(SbcMetrics::new()),
            EventBus::new(),
            fast_config(),
        );
        tasks.sync();
        assert!(tasks.running().is_empty());
        assert!(tasks.attach_socket(Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())));
        tasks.sync();
        assert_eq!(tasks.running().len(), 1);
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn health_probe_transitions_feed_state_metrics_and_events() {
        let peer = Peer::new().await;
        let (trunks, id) = harness(&peer, false);
        let metrics = Arc::new(SbcMetrics::new());
        let events = EventBus::new();
        let mut rx = events.subscribe();
        let tasks = tasks(trunks.clone(), metrics.clone(), events).await;
        let pending = tasks.pending.clone();
        tasks.sync();

        // First probe answered: up, exported.
        let req = peer.recv().await.expect("OPTIONS");
        assert!(req.starts_with("OPTIONS sip:127.0.0.1:"), "{}", req);
        peer.answer(&pending, &req, "200 OK", "");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(metrics.trunk_series("t1").unwrap().up, Some(true));

        // Two unanswered probes: down event, failure recorded, gauge 0.
        let _ = peer.recv().await.expect("second OPTIONS");
        let e = next_event(
            &mut rx,
            |e| matches!(e, SbcEvent::TrunkHealth { status, .. } if status == "down"),
        )
        .await;
        assert!(
            matches!(
                e,
                SbcEvent::TrunkHealth {
                    consecutive_failures: 1,
                    ..
                }
            ),
            "{:?}",
            e
        );
        assert_eq!(metrics.trunk_series("t1").unwrap().up, Some(false));
        assert!(trunks.get_state(&id).unwrap().consecutive_failures >= 1);

        // Answers again: up event, failures reset.
        loop {
            let req = peer.recv().await.expect("OPTIONS while down");
            peer.answer(&pending, &req, "200 OK", "");
            if trunks.get_state(&id).unwrap().consecutive_failures == 0 {
                break;
            }
        }
        next_event(
            &mut rx,
            |e| matches!(e, SbcEvent::TrunkHealth { status, .. } if status == "up"),
        )
        .await;
        assert_eq!(metrics.trunk_series("t1").unwrap().up, Some(true));
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn passive_trunk_that_never_answers_is_not_exported_nor_failed() {
        let peer = Peer::new().await;
        let (trunks, id) = harness(&peer, false);
        let metrics = Arc::new(SbcMetrics::new());
        let tasks = tasks(trunks.clone(), metrics.clone(), EventBus::new()).await;
        tasks.sync();
        let _ = peer.recv().await.expect("OPTIONS");
        let _ = peer.recv().await.expect("OPTIONS");
        let _ = peer.recv().await.expect("OPTIONS");
        assert_eq!(
            metrics.trunk_series("t1").map(|s| s.up).unwrap_or(None),
            None
        );
        assert_eq!(trunks.get_state(&id).unwrap().consecutive_failures, 0);
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn register_401_then_200_marks_registered_and_refreshes() {
        let peer = Peer::new().await;
        let (trunks, id) = harness(&peer, true);
        let metrics = Arc::new(SbcMetrics::new());
        let events = EventBus::new();
        let mut rx = events.subscribe();
        let tasks = tasks(trunks.clone(), metrics.clone(), events).await;
        let pending = tasks.pending.clone();
        tasks.sync();

        // Drain until the REGISTER (OPTIONS probes interleave).
        let req = loop {
            let r = peer.recv().await.expect("request");
            if r.starts_with("REGISTER ") {
                break r;
            }
        };
        assert!(req.contains("CSeq: 1 REGISTER\r\n"), "{}", req);
        assert!(req.contains("Expires: 1\r\n"), "{}", req);
        peer.answer(
            &pending,
            &req,
            "401 Unauthorized",
            "WWW-Authenticate: Digest realm=\"trunk\", nonce=\"abc\", algorithm=MD5\r\n",
        );
        let retry = loop {
            let r = peer.recv().await.expect("auth retry");
            if r.starts_with("REGISTER ") {
                break r;
            }
        };
        assert!(retry.contains("CSeq: 2 REGISTER\r\n"), "{}", retry);
        assert_eq!(
            extract_header(&retry, "call-id"),
            extract_header(&req, "call-id")
        );
        let auth = extract_header(&retry, "authorization").expect("Authorization");
        let challenge =
            DigestChallenge::from_header("Digest realm=\"trunk\", nonce=\"abc\", algorithm=MD5")
                .unwrap();
        let expected = generate_digest_response("u", "p", &challenge, "REGISTER", "sip:127.0.0.1");
        assert_eq!(auth, expected);
        peer.answer(&pending, &retry, "200 OK", "Expires: 300\r\n");

        let e = next_event(&mut rx, |e| matches!(e, SbcEvent::TrunkRegistered { .. })).await;
        assert!(matches!(e, SbcEvent::TrunkRegistered { expires: 300, .. }));
        assert!(trunks.get_state(&id).unwrap().registered);
        assert_eq!(metrics.trunk_series("t1").unwrap().registered, Some(true));

        // A refresh comes (refresh_min is 20 ms in the test config).
        let refresh = loop {
            let r = peer.recv().await.expect("refresh");
            if r.starts_with("REGISTER ") {
                break r;
            }
        };
        assert!(
            refresh.contains("CSeq: 1 REGISTER\r\n"),
            "new Call-ID, new cycle: {}",
            refresh
        );
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn register_423_is_retried_with_min_expires_and_remembered() {
        let peer = Peer::new().await;
        let (trunks, _) = harness(&peer, true);
        let tasks = tasks(trunks.clone(), Arc::new(SbcMetrics::new()), EventBus::new()).await;
        let pending = tasks.pending.clone();
        tasks.sync();
        let recv_register = || async {
            loop {
                let r = peer.recv().await.expect("request");
                if r.starts_with("REGISTER ") {
                    return r;
                }
            }
        };
        let req = recv_register().await;
        assert!(req.contains("Expires: 1\r\n"), "{}", req);
        peer.answer(
            &pending,
            &req,
            "423 Interval Too Brief",
            "Min-Expires: 3600\r\n",
        );
        let retry = recv_register().await;
        assert!(retry.contains("Expires: 3600\r\n"), "{}", retry);
        assert!(
            retry.contains("CSeq: 1 REGISTER\r\n"),
            "a new transaction: {}",
            retry
        );
        peer.answer(&pending, &retry, "200 OK", "Expires: 3600\r\n");
        // Next cycle starts at the remembered value.
        let refresh = recv_register().await;
        assert!(refresh.contains("Expires: 3600\r\n"), "{}", refresh);
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn refused_register_backs_off_and_announces_once() {
        let peer = Peer::new().await;
        let (trunks, id) = harness(&peer, true);
        let metrics = Arc::new(SbcMetrics::new());
        let events = EventBus::new();
        let mut rx = events.subscribe();
        let tasks = tasks(trunks.clone(), metrics.clone(), events).await;
        let pending = tasks.pending.clone();
        tasks.sync();
        let mut gaps = Vec::new();
        let mut last: Option<std::time::Instant> = None;
        for _ in 0..4 {
            let req = loop {
                let r = peer.recv().await.expect("request");
                if r.starts_with("REGISTER ") {
                    break r;
                }
            };
            let now = std::time::Instant::now();
            if let Some(prev) = last {
                gaps.push(now - prev);
            }
            last = Some(now);
            peer.answer(&pending, &req, "403 Forbidden", "");
        }
        assert!(gaps[1] > gaps[0], "backoff grows: {:?}", gaps);
        assert!(gaps[2] >= gaps[1], "{:?}", gaps);
        let e = next_event(&mut rx, |e| matches!(e, SbcEvent::TrunkUnregistered { .. })).await;
        assert!(
            matches!(&e, SbcEvent::TrunkUnregistered { reason, .. } if reason == "403"),
            "{:?}",
            e
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                next_event(&mut rx, |e| matches!(e, SbcEvent::TrunkUnregistered { .. }))
            )
            .await
            .is_err(),
            "announced once"
        );
        assert!(!trunks.get_state(&id).unwrap().registered);
        assert_eq!(metrics.trunk_series("t1").unwrap().registered, Some(false));
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn stopping_a_registered_trunk_unregisters_it() {
        let peer = Peer::new().await;
        let (trunks, id) = harness(&peer, true);
        let tasks = tasks(trunks.clone(), Arc::new(SbcMetrics::new()), EventBus::new()).await;
        let pending = tasks.pending.clone();
        tasks.sync();
        let req = loop {
            let r = peer.recv().await.expect("request");
            if r.starts_with("REGISTER ") {
                break r;
            }
        };
        peer.answer(&pending, &req, "200 OK", "Expires: 300\r\n");
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(trunks.get_state(&id).unwrap().registered);

        trunks.disable_trunk(&id);
        tasks.sync();
        let bye = loop {
            let r = peer.recv().await.expect("un-register");
            if r.starts_with("REGISTER ") && r.contains("Expires: 0\r\n") {
                break r;
            }
        };
        peer.answer(&pending, &bye, "200 OK", "Expires: 0\r\n");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!trunks.get_state(&id).unwrap().registered);
        assert!(pending.is_empty(), "no pending entry left behind");
        tasks.shutdown().await;
    }
}
