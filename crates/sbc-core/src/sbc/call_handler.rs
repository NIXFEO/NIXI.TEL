use super::*;

impl Sbc {
    /// Check for calls that have exceeded `security.max_call_duration` and
    /// terminate them (BYE on both legs, CDR "timeout"). This prevents
    /// phantom sessions when the callee drops without sending BYE. Runs
    /// every 30 s from the event loop.
    pub(crate) async fn check_call_timeouts(&mut self) {
        let max_duration = self.max_call_duration;
        let timed_out: Vec<(crate::b2bua::CallUuid, String, u64)> = {
            let calls = self.b2bua.calls_locked().await;
            calls
                .values()
                .filter(|c| c.started_at.elapsed() > max_duration)
                .map(|c| {
                    (
                        c.uuid.clone(),
                        c.inbound.call_id.clone(),
                        c.started_at.elapsed().as_secs(),
                    )
                })
                .collect()
        };
        for (uuid, call_id, duration) in timed_out {
            let span = self.call_span_for_uuid(&uuid).await;
            async {
                warn!(
                    "Call timeout: {} (Call-ID: {}) exceeded {}s (active {}s) — sending BYE to both sides",
                    &uuid[..8.min(uuid.len())],
                    call_id,
                    max_duration.as_secs(),
                    duration
                );
                let outcome = CallOutcome::MaxDuration;
                self.hangup_both_legs(&uuid, &outcome).await;
                self.finish_call(&uuid, outcome).await;
            }
            .instrument(span)
            .await;
        }
    }

    /// SIGTERM/SIGINT: end every call on the wire (BYE to established legs,
    /// CANCEL to a pending callee, 503 to a still-ringing caller), write
    /// its CDR ("shutdown") and release it. Prevents phantom sessions on
    /// remote trunks (e.g. trunk OverMaxCall).
    pub(crate) async fn graceful_shutdown(&mut self) {
        let active: Vec<crate::b2bua::CallUuid> =
            self.b2bua.calls_locked().await.keys().cloned().collect();
        if active.is_empty() {
            info!("Graceful shutdown: no active calls");
            return;
        }
        info!("Graceful shutdown: ending {} active call(s)", active.len());
        for uuid in active {
            let span = self.call_span_for_uuid(&uuid).await;
            async {
                let outcome = CallOutcome::Shutdown;
                self.hangup_both_legs(&uuid, &outcome).await;
                self.finish_call(&uuid, outcome).await;
            }
            .instrument(span)
            .await;
        }
        // Give time for BYE packets to be sent
        tokio::time::sleep(Duration::from_millis(500)).await;
        info!("Graceful shutdown: all calls ended");
    }

    /// Handle ACK — must be relayed to callee so dialog completes (RFC 3261 §13.2.2.4)
    pub(crate) async fn handle_ack(
        &mut self,
        request: Request,
        source: SocketAddr,
        _transport: rsip::Transport,
        _reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        let call_id = request
            .call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        debug!("Received ACK from {} (Call-ID: {})", source, call_id);

        // The ACK to one of OUR non-2xx finals ends its retransmissions
        // (RFC 3261 §17.2.1 Timer G/H); a 2xx ACK shares the key too and is
        // harmless there.
        if let Some(key) = super::invite_tx::InviteTxCache::key_of_request(&request) {
            self.invite_tx.acked(&key);
        }

        // Try exact match first, then suffix match (some trunks add prefixes to Call-ID
        // in INVITE but send ACK with original shorter Call-ID)
        let maybe_uuid = if let Some(uuid) = self.b2bua.find_by_inbound_call_id(&call_id).await {
            Some(uuid)
        } else if let Some(uuid) = self.b2bua.find_by_inbound_call_id_suffix(&call_id).await {
            debug!("ACK matched B2BUA call via suffix match (ACK Call-ID is shorter than stored)");
            Some(uuid)
        } else {
            // Also try outbound call-id (in case ACK comes from callee side)
            self.b2bua.find_by_outbound_call_id(&call_id).await
        };

        if let Some(uuid) = maybe_uuid {
            debug!("ACK matched B2BUA call {} (call-id: {})", uuid, call_id);
            let _ = self.b2bua.handle_ack(&uuid).await;

            // Relay ACK to callee so the callee's INVITE transaction completes
            // and retransmissions of 200 OK stop (RFC 3261 §13.2.2.4)
            if let Some((callee_reply_tx, callee_dest, callee_transport)) =
                self.b2bua.get_callee_reply_info(&uuid).await
            {
                // Build a fresh ACK for the callee leg (B2BUA must rewrite headers)
                let callee_contact = format!("sip:{}:{}", callee_dest.ip(), callee_dest.port());
                let _caller_user = request
                    .from_header()
                    .ok()
                    .map(|h| h.value().to_string())
                    .unwrap_or_default();
                let to_header = request
                    .to_header()
                    .ok()
                    .map(|h| h.value().to_string())
                    .unwrap_or_default();
                let from_header = request
                    .from_header()
                    .ok()
                    .map(|h| h.value().to_string())
                    .unwrap_or_default();
                // CSeq: the callee-leg INVITE's number (RFC 3261 §13.2.2.4),
                // which differs from the caller's after a 407/422 retry.
                let caller_cseq_header = request
                    .cseq_header()
                    .ok()
                    .map(|h| h.value().to_string())
                    .unwrap_or("1 ACK".to_string());
                let cseq_header = ack_cseq_for_callee(
                    &caller_cseq_header,
                    self.b2bua.outbound_invite_cseq(&uuid).await,
                );

                // Get the callee's Request-URI (the contact from the callee's 200 OK)
                let callee_req_uri = self
                    .b2bua
                    .get_callee_contact_uri(&uuid)
                    .await
                    .unwrap_or(callee_contact.clone());

                // CRITICAL: Use the stored inbound Call-ID (the full one) for the ACK
                // to the callee — NOT the (possibly truncated) Call-ID from the ACK we received.
                // The trunk may strip prefixes from the Call-ID in the ACK.
                let callee_call_id = self
                    .b2bua
                    .get_inbound_call_id(&uuid)
                    .await
                    .unwrap_or_else(|| call_id.clone());

                let sbc_ip = self
                    .identity
                    .as_ref()
                    .map(|id| id.public_ip.clone())
                    .unwrap_or_else(|| "203.0.113.1".to_string());
                let sbc_port = if callee_transport == rsip::Transport::Udp {
                    5060
                } else {
                    5061
                };

                let transport_str = match callee_transport {
                    rsip::Transport::Udp => "UDP",
                    rsip::Transport::Tcp => "TCP",
                    _ => "UDP",
                };

                let ack_msg = format!(
                    "ACK {} SIP/2.0\r\n\
                     Via: SIP/2.0/{} {}:{};branch=z9hG4bK{:08x};rport\r\n\
                     Max-Forwards: 70\r\n\
                     From: {}\r\n\
                     To: {}\r\n\
                     Call-ID: {}\r\n\
                     CSeq: {}\r\n\
                     Content-Length: 0\r\n\r\n",
                    callee_req_uri,
                    transport_str,
                    sbc_ip,
                    sbc_port,
                    rand::random::<u32>(),
                    from_header,
                    to_header,
                    callee_call_id,
                    cseq_header,
                );

                debug!(
                    "Relaying ACK to callee at {} via {:?}:\n{}",
                    callee_dest,
                    callee_transport,
                    ack_msg.trim()
                );
                self.send_sip(
                    "ACK → callee",
                    ack_msg.as_bytes(),
                    callee_dest,
                    callee_transport,
                    callee_reply_tx.as_ref(),
                )
                .await;
            } else {
                warn!(
                    "ACK: no callee_reply_info for call {} — callee_dest may be None",
                    uuid
                );
            }
        } else {
            warn!("ACK: no B2BUA call found for call-id: {}", call_id);
        }

        Ok(())
    }

    /// Handle BYE — tear down B2BUA call + media session + relay BYE to other leg
    ///
    /// BYE may come from:
    ///   - The caller (inbound leg): relay to callee using stored callee_reply_tx
    ///   - The callee  (outbound leg): relay to caller using stored caller_reply_tx
    pub(crate) async fn handle_bye(
        &mut self,
        request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Received BYE from {}", source);

        let call_id = request
            .call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        // The peer's Reason (RFC 3326, e.g. Q.850 cause) travels on the
        // relayed BYE and into the CDR.
        let peer_reason = super::cdr::header_value(&request, "reason");

        // Find by EITHER inbound or outbound Call-ID, using source IP to disambiguate
        // (both legs share the same Call-ID in our half-B2BUA)
        let mut found = self
            .b2bua
            .find_by_any_call_id_with_source(&call_id, Some(source))
            .await;

        // ── Trunk IP fallback ──────────────────────────────────────────
        // If no match was found by source IP, but the BYE comes from a known trunk IP,
        // try again without source disambiguation. Trunk may send BYE from a different
        // IP (e.g. 198.51.100.11) than the INVITE was sent to (198.51.100.10).
        if found.is_none() {
            let source_ip = source.ip().to_string();
            if self.source_is_trunk_related(source).await {
                info!(
                    "BYE from trunk-related IP {} — retrying lookup without source filter",
                    source_ip
                );
                found = self
                    .b2bua
                    .find_by_any_call_id_with_source(&call_id, None)
                    .await;
                // For inbound PSTN calls, the "caller" is the trunk side.
                // If the fallback found it as "from caller" (trunk), that's correct —
                // we need to relay the BYE to the callee (local SIP user).
            }
        }

        if let Some((uuid, is_from_caller)) = found {
            debug!(
                "BYE identified as from {} (source: {})",
                if is_from_caller { "caller" } else { "callee" },
                source
            );

            // Get stored Call-IDs for Call-ID rewrite when trunk truncates them.
            // When BYE arrives with a shortened Call-ID (suffix match), we must
            // rewrite it to the full Call-ID that the other party knows.
            let stored_call_ids = self.b2bua.get_call_ids(&uuid).await;

            if is_from_caller {
                // BYE from caller → relay to callee
                let callee_info = self.b2bua.get_callee_reply_info(&uuid).await;
                let _ = self.b2bua.handle_bye(&uuid).await;

                if let Some((callee_reply_tx, callee_dest, callee_transport)) = callee_info {
                    info!("B2BUA: relaying BYE (caller→callee) to {}", callee_dest);

                    // Prefer a fresh in-dialog BYE with the real dialog
                    // identity and our own CSeq (true B2BUA behavior —
                    // avoids 481 when the trunk truncated the Call-ID or
                    // tags drifted). Raw relay stays as fallback.
                    let (sbc_ip, sbc_port) = self
                        .identity
                        .as_ref()
                        .map(|id| (id.public_ip.clone(), id.sip_port))
                        .unwrap_or_else(|| ("127.0.0.1".to_string(), 5060));
                    let fresh_bye = self
                        .b2bua
                        .build_relay_bye_toward_callee(
                            &uuid,
                            &sbc_ip,
                            sbc_port,
                            peer_reason.as_deref(),
                        )
                        .await;

                    let bye_out = if let Some(fresh) = fresh_bye {
                        debug!("BYE (caller→callee): synthetic in-dialog BYE");
                        fresh
                    } else {
                        let mut raw_bye = rsip::SipMessage::Request(request.clone()).to_string();
                        // Rewrite Call-ID if it was a suffix match — callee knows the full Call-ID
                        if let Some((ref stored_inbound_cid, _)) = stored_call_ids {
                            if *stored_inbound_cid != call_id
                                && stored_inbound_cid.ends_with(&call_id)
                            {
                                info!(
                                    "BYE Call-ID rewrite: '{}' → '{}'",
                                    call_id, stored_inbound_cid
                                );
                                raw_bye = raw_bye.replace(
                                    &format!("Call-ID: {}", call_id),
                                    &format!("Call-ID: {}", stored_inbound_cid),
                                );
                            }
                        }
                        self.apply_outbound_topology(&raw_bye, callee_transport)
                    };
                    debug!("BYE relayed to callee:\n{}", bye_out);
                    self.send_sip(
                        "BYE → callee",
                        bye_out.as_bytes(),
                        callee_dest,
                        callee_transport,
                        callee_reply_tx.as_ref(),
                    )
                    .await;
                }
            } else {
                // BYE from callee → relay to caller
                let caller_info = self.b2bua.get_caller_reply_info(&uuid).await;
                let _ = self.b2bua.handle_bye(&uuid).await;

                if let Some((caller_reply_tx, caller_addr, caller_transport)) = caller_info {
                    info!("B2BUA: relaying BYE (callee→caller) to {}", caller_addr);
                    let (sbc_ip, sbc_port) = self
                        .identity
                        .as_ref()
                        .map(|id| (id.public_ip.clone(), id.sip_port))
                        .unwrap_or_else(|| ("127.0.0.1".to_string(), 5060));
                    let fresh_bye = self
                        .b2bua
                        .build_relay_bye_toward_caller(
                            &uuid,
                            &sbc_ip,
                            sbc_port,
                            peer_reason.as_deref(),
                        )
                        .await;

                    let bye_out = if let Some(fresh) = fresh_bye {
                        debug!("BYE (callee→caller): synthetic in-dialog BYE");
                        fresh
                    } else {
                        let mut raw_bye = rsip::SipMessage::Request(request.clone()).to_string();
                        // Rewrite Call-ID if it was a suffix match — caller knows the full Call-ID
                        if let Some((ref stored_inbound_cid, _)) = stored_call_ids {
                            if *stored_inbound_cid != call_id
                                && stored_inbound_cid.ends_with(&call_id)
                            {
                                info!(
                                    "BYE Call-ID rewrite: '{}' → '{}'",
                                    call_id, stored_inbound_cid
                                );
                                raw_bye = raw_bye.replace(
                                    &format!("Call-ID: {}", call_id),
                                    &format!("Call-ID: {}", stored_inbound_cid),
                                );
                            }
                        }
                        self.apply_outbound_topology(&raw_bye, caller_transport)
                    };
                    self.send_sip(
                        "BYE → caller",
                        bye_out.as_bytes(),
                        caller_addr,
                        caller_transport,
                        caller_reply_tx.as_ref(),
                    )
                    .await;
                }
            }

            // Peer's Reason (Q.850 cause) travels into the CDR; one CDR,
            // counters, gauges and the release all happen in finish_call.
            if let Some(reason) = peer_reason.clone() {
                self.b2bua.set_peer_reason(&uuid, reason).await;
            }
            self.finish_call(
                &uuid,
                CallOutcome::NormalClearing {
                    by_caller: is_from_caller,
                },
            )
            .await;
        } else if self.b2bua.was_recently_terminated(&call_id) {
            // Late BYE for a dialog we already tore down (Genesys sends these
            // 1-8 min after teardown) — benign, answered 200 below.
            info!(
                "BYE: late BYE for recently terminated Call-ID: {} from {} — benign",
                call_id, source
            );
        } else {
            warn!(
                "BYE: no B2BUA call found for Call-ID: {} from {} (stray BYE — phantom session?)",
                call_id, source
            );
        }

        // Send 200 OK for BYE back to sender (RFC 3261 §15.1.2)
        self.metrics.inc_sip_response(200);
        let response_200 = match build_plain_response_for_request(&request, 200, "OK") {
            Ok(r) => r.to_string().into_bytes(),
            Err(_) => build_plain_response(200, "OK").into_bytes(),
        };
        self.transport
            .reply(&response_200, source, transport, reply_tx)
            .await
    }

    /// Handle CANCEL (RFC 3261 §9.2).
    ///
    /// - Unknown Call-ID → 481 (no INVITE transaction to cancel).
    /// - INVITE already answered (2xx relayed) → 200 to the CANCEL only; the
    ///   dialog stands and the caller ends it with BYE.
    /// - INVITE still pending → 200 to the CANCEL, CANCEL of the live
    ///   attempt toward the callee, then **487 Request Terminated** to the
    ///   caller's INVITE (built from the CANCEL, which carries the INVITE's
    ///   Via/From/To/Call-ID per §9.1), so the caller's transaction ends
    ///   instead of hanging without Timer B behind our 100 Trying.
    pub(crate) async fn handle_cancel(
        &mut self,
        request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Received CANCEL from {}", source);

        let call_id = request
            .call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        // Exact Call-ID first; a clustered trunk may CANCEL with the
        // truncated Call-ID it also uses on ACK/BYE (suffix match).
        let mut found = self.b2bua.find_by_inbound_call_id(&call_id).await;
        if found.is_none() && self.source_is_trunk_related(source).await {
            found = self.b2bua.find_by_inbound_call_id_suffix(&call_id).await;
            if found.is_some() {
                debug!("CANCEL: matched call via Call-ID suffix '{}'", call_id);
            }
        }
        let Some(uuid) = found else {
            warn!(
                "CANCEL: no INVITE transaction for Call-ID {} from {} — 481",
                call_id, source
            );
            self.metrics.inc_sip_response(481);
            let raw = match build_plain_response_for_request(
                &request,
                481,
                "Call/Transaction Does Not Exist",
            ) {
                Ok(r) => r.to_string(),
                Err(_) => build_plain_response(481, "Call/Transaction Does Not Exist"),
            };
            self.send_sip("481 → CANCEL", raw.as_bytes(), source, transport, reply_tx)
                .await;
            return Ok(());
        };

        // 200 OK for the CANCEL itself, whatever happens to the INVITE.
        self.metrics.inc_sip_response(200);
        let response_200 = match build_plain_response_for_request(&request, 200, "OK") {
            Ok(r) => r.to_string(),
            Err(_) => build_plain_response(200, "OK"),
        };
        self.send_sip(
            "200 OK → CANCEL",
            response_200.as_bytes(),
            source,
            transport,
            reply_tx,
        )
        .await;

        // Already answered: the CANCEL has no effect on the dialog (§9.2).
        let answered = {
            let calls = self.b2bua.calls_locked().await;
            calls.get(&uuid).is_some_and(|c| {
                c.outbound.as_ref().is_some_and(|l| l.established)
                    || matches!(
                        c.state,
                        crate::b2bua::CallState::Connected
                            | crate::b2bua::CallState::Terminating
                            | crate::b2bua::CallState::Terminated
                    )
            })
        };
        if answered {
            info!(
                "CANCEL for call {} arrived after its 200 OK — dialog stands, caller must BYE",
                &uuid[..8.min(uuid.len())]
            );
            return Ok(());
        }

        // Get callee info BEFORE terminating the call
        let callee_cancel_info = self.b2bua.get_callee_cancel_info(&uuid).await;
        let current_attempt = self.b2bua.current_attempt(&uuid).await;
        let caller_invite_cseq = self.b2bua.get_caller_invite_cseq(&uuid).await;

        // CDR "cancelled" (with the caller's Reason, RFC 3326), counters,
        // media release
        if let Some(reason) = super::cdr::header_value(&request, "reason") {
            self.b2bua.set_peer_reason(&uuid, reason).await;
        }
        self.finish_call(&uuid, CallOutcome::Cancelled).await;

        // CANCEL toward the callee (if the INVITE was already forwarded).
        // RFC 3261 §9.1: it must carry the INVITE's own Request-URI, Via
        // branch and CSeq, so build it from the live attempt — the raw
        // relay through topology hiding minted a fresh branch and kept
        // the caller's R-URI/CSeq, which never matched after a retry.
        if let Some((attempt, tx)) = current_attempt {
            if let Some(cancel) = crate::sip_builder::build_cancel(&attempt.raw) {
                info!(
                    "B2BUA: CANCEL → callee {} (from INVITE attempt CSeq {})",
                    attempt.dest, attempt.cseq
                );
                self.send_sip(
                    "CANCEL → callee",
                    cancel.as_bytes(),
                    attempt.dest,
                    attempt.transport,
                    tx.as_ref(),
                )
                .await;
            } else {
                warn!(
                    "B2BUA: stored INVITE for call {} is not parseable — CANCEL not sent",
                    uuid
                );
            }
        } else if let Some((_out_call_id, _cseq, callee_dest, callee_reply_tx, callee_transport)) =
            callee_cancel_info
        {
            // Legacy path: no attempt recorded (should not happen for a
            // forwarded INVITE) — best-effort relay.
            info!("B2BUA: relaying CANCEL to callee at {}", callee_dest);
            let raw_cancel = rsip::SipMessage::Request(request.clone()).to_string();
            let cancel_out = self.apply_outbound_topology(&raw_cancel, callee_transport);
            self.send_sip(
                "CANCEL relay → callee",
                cancel_out.as_bytes(),
                callee_dest,
                callee_transport,
                callee_reply_tx.as_ref(),
            )
            .await;
        }

        // 487 to the caller's INVITE. The CANCEL carries the INVITE's Via
        // (same branch), From, To and Call-ID (§9.1); only the CSeq method
        // differs. The caller's ACK to it is absorbed by handle_ack.
        let cseq_num = caller_invite_cseq.or_else(|| {
            request
                .cseq_header()
                .ok()
                .and_then(|h| h.value().split_whitespace().next()?.parse().ok())
        });
        match build_plain_response_for_request(&request, 487, "Request Terminated") {
            Ok(r) => {
                let mut raw = r.to_string();
                if let Some(n) = cseq_num {
                    if let Ok(mut msg) = crate::topology::RawSipMessage::parse(&raw) {
                        msg.set_header("CSeq", &format!("{} INVITE", n));
                        raw = msg.to_string();
                    }
                }
                self.metrics.inc_sip_response(487);
                self.send_sip("487 → caller", raw.as_bytes(), source, transport, reply_tx)
                    .await;
            }
            Err(e) => warn!("CANCEL: could not build the 487 for call {}: {}", uuid, e),
        }
        Ok(())
    }

    // REFER (RFC 3515, attended/blind transfer) is not implemented: it is
    // answered 501 by the request dispatcher. A future implementation would
    // extract Refer-To, answer 202, INVITE the target, NOTIFY the transferor
    // with progress, then bridge the new call and release the transferor.

    /// Handle a transport-level event (currently: WS/WSS connection closed).
    /// Removes registrations bound to that connection and tears down active
    /// calls (synthetic BYE to the surviving leg, CDR "ws-closed").
    pub(crate) async fn handle_transport_event(
        &mut self,
        event: crate::transport::manager::TransportEvent,
    ) {
        let crate::transport::manager::TransportEvent::ConnectionClosed { peer, transport } = event;
        info!(
            "Transport event: {:?} connection from {} closed",
            transport, peer
        );

        // ── 1. Unregister bindings that lived on this connection ─────────
        // Without a live WS the contact is unreachable (the SBC cannot dial
        // out to a browser); the client re-REGISTERs on reconnect.
        let registrar = self.register_handler.registrar();
        if let Ok(regs) = registrar.all_registrations().await {
            let peer_ip = peer.ip().to_string();
            for reg in regs.iter().filter(|r| {
                r.received_ip == peer_ip
                    && r.received_port == peer.port()
                    && matches!(r.transport.as_str(), "WS" | "WSS")
            }) {
                info!("WS closed: unregistering {} ({})", reg.aor, reg.contact);
                let _ = registrar.unregister(&reg.aor, &reg.contact).await;
            }
        }

        // ── 2. Tear down active calls bound to this connection ───────────
        let (sbc_ip, sbc_port) = self
            .identity
            .as_ref()
            .map(|id| (id.public_ip.clone(), id.sip_port))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 5060));

        let affected: Vec<_> = {
            let calls = self.b2bua.calls_locked().await;
            calls
                .values()
                .filter(|c| {
                    (c.caller_source == peer
                        && matches!(
                            c.caller_transport,
                            rsip::Transport::Ws | rsip::Transport::Wss
                        ))
                        || (c.callee_dest == Some(peer)
                            && matches!(
                                c.callee_transport,
                                rsip::Transport::Ws | rsip::Transport::Wss
                            ))
                })
                .map(|c| {
                    let caller_died = c.caller_source == peer;
                    let bye = if caller_died {
                        // Dialog established → BYE; INVITE still pending →
                        // CANCEL the live attempt (a BYE cannot match yet).
                        c.bye_toward_callee(
                            &sbc_ip,
                            sbc_port,
                            Some("SIP;cause=200;text=\"ws-closed\""),
                        )
                        .or_else(|| {
                            c.invite_attempts
                                .last()
                                .and_then(|a| crate::sip_builder::build_cancel(&a.raw))
                        })
                    } else {
                        // Callee's WS died: BYE an answered caller, or give a
                        // still-ringing caller a final for its INVITE.
                        c.dialog_info_toward_caller(&sbc_ip, sbc_port)
                            .map(|d| {
                                crate::sip_builder::build_bye(
                                    &d,
                                    Some("SIP;cause=200;text=\"ws-closed\""),
                                )
                            })
                            .or_else(|| {
                                c.final_toward_caller(480, Some("SIP;cause=200;text=\"ws-closed\""))
                            })
                    };
                    let (dest, tp, tx) = if caller_died {
                        (c.callee_dest, c.callee_transport, c.callee_reply_tx.clone())
                    } else {
                        (
                            Some(c.caller_source),
                            c.caller_transport,
                            c.caller_reply_tx.clone(),
                        )
                    };
                    (c.uuid.clone(), bye, dest, tp, tx, !caller_died)
                })
                .collect()
        };

        for (uuid, bye, dest, tp, tx, callee_died) in affected {
            warn!(
                "WS closed mid-call: terminating call {} (peer {})",
                &uuid[..8.min(uuid.len())],
                peer
            );

            if let (Some(msg), Some(dest)) = (bye, dest) {
                self.send_sip(
                    "ws-close → surviving leg",
                    msg.as_bytes(),
                    dest,
                    tp,
                    tx.as_ref(),
                )
                .await;
            }
            self.finish_call(&uuid, CallOutcome::WsClosed { callee_died })
                .await;
        }
    }

    /// Handle an in-dialog re-INVITE (session refresh, RFC 4028).
    /// Answers 200 OK with the SDP previously sent to that peer — media
    /// stays untouched. Without this, a refresher peer's re-INVITE would be
    /// treated as a new call and destroy its own session.
    pub(crate) async fn handle_reinvite(
        &mut self,
        uuid: &crate::b2bua::CallUuid,
        is_from_caller: bool,
        request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!(
            "In-dialog re-INVITE from {} ({}) for call {} — answering with unchanged SDP",
            source,
            if is_from_caller { "caller" } else { "callee" },
            &uuid[..8.min(uuid.len())]
        );

        // SDP previously sent toward that peer; fall back to mirroring the
        // request's own SDP (degenerate but keeps the session alive).
        let sdp = {
            let calls = self.b2bua.calls_locked().await;
            calls.get(uuid).and_then(|call| {
                if is_from_caller {
                    call.last_sdp_to_caller.clone()
                } else {
                    call.original_outbound_invite
                        .as_deref()
                        .and_then(|raw| raw.split_once("\r\n\r\n").map(|(_, b)| b.to_string()))
                        .filter(|b| !b.is_empty())
                }
            })
        }
        .or_else(|| {
            std::str::from_utf8(&request.body)
                .ok()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
        });

        // Session-Expires: echo the peer's value, else our configured one
        let raw_req = rsip::SipMessage::Request(request.clone()).to_string();
        let session_expires = super::response_handler_session_expires(&raw_req)
            .or(self.session_timer.map(|(e, _)| e));

        let (sbc_ip, sbc_port) = self
            .identity
            .as_ref()
            .map(|id| (id.public_ip.clone(), id.sip_port))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 5060));

        let msg = build_plain_response_for_request(&request, 200, "OK")?;
        let mut response = match msg {
            rsip::SipMessage::Response(r) => r,
            _ => return Ok(()),
        };
        response.headers.push(rsip::Header::Other(
            "Contact".to_string(),
            format!("<sip:sbc@{}:{}>", sbc_ip, sbc_port),
        ));
        response.headers.push(rsip::Header::Other(
            "Supported".to_string(),
            "timer".to_string(),
        ));
        if let Some(se) = session_expires {
            response.headers.push(rsip::Header::Other(
                "Session-Expires".to_string(),
                format!("{};refresher=uac", se),
            ));
        }
        if let Some(sdp) = sdp {
            response.headers.push(rsip::Header::Other(
                "Content-Type".to_string(),
                "application/sdp".to_string(),
            ));
            response.body = sdp.into_bytes();
        }
        update_content_length_response(&mut response);

        self.metrics.inc_sip_response(200);
        let data = rsip::SipMessage::Response(response)
            .to_string()
            .into_bytes();
        self.transport
            .reply(&data, source, transport, reply_tx)
            .await
    }

    /// Send due RFC 4028 refresh re-INVITEs (30s tick). No-op when session
    /// timers are disabled.
    pub(crate) async fn send_session_refreshes(&mut self) {
        if self.session_timer.is_none() {
            return;
        }
        let (sbc_ip, sbc_port) = self
            .identity
            .as_ref()
            .map(|id| (id.public_ip.clone(), id.sip_port))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 5060));

        for (uuid, reinvite, dest, transport, reply_tx) in
            self.b2bua.due_session_refreshes(&sbc_ip, sbc_port).await
        {
            let span = self.call_span_for_uuid(&uuid).await;
            async {
                info!(
                    "Session refresh: re-INVITE → {} (call {})",
                    dest,
                    &uuid[..8.min(uuid.len())]
                );
                if let Err(e) = self
                    .transport
                    .reply(reinvite.as_bytes(), dest, transport, reply_tx.as_ref())
                    .await
                {
                    warn!("Session refresh send failed for call {}: {}", uuid, e);
                }
            }
            .instrument(span)
            .await;
        }
    }

    /// Handle INFO — relay in-dialog INFO (e.g. DTMF via SIP INFO) to the
    /// other leg instead of answering 501. No 2833↔INFO conversion: the
    /// INFO body passes through untouched.
    pub(crate) async fn handle_info(
        &mut self,
        request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        debug!("Received INFO from {}", source);

        let call_id = request
            .call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        let found = self
            .b2bua
            .find_by_any_call_id_with_source(&call_id, Some(source))
            .await;

        if let Some((uuid, is_from_caller)) = found {
            let raw_info = rsip::SipMessage::Request(request.clone()).to_string();
            // The relayed INFO keeps its CSeq: the SBC's own later requests
            // on that leg must stay above it (RFC 3261 §12.2.1.1).
            if let Some(cseq) = request
                .cseq_header()
                .ok()
                .and_then(|h| h.typed().ok())
                .map(|c: rsip::typed::CSeq| c.seq)
            {
                self.b2bua
                    .note_relayed_cseq(&uuid, is_from_caller, cseq)
                    .await;
            }
            if is_from_caller {
                if let Some((tx, dest, tp)) = self.b2bua.get_callee_reply_info(&uuid).await {
                    debug!("B2BUA: relaying INFO (caller→callee) to {}", dest);
                    let out = self.apply_outbound_topology(&raw_info, tp);
                    self.send_sip("INFO → callee", out.as_bytes(), dest, tp, tx.as_ref())
                        .await;
                }
            } else if let Some((tx, dest, tp)) = self.b2bua.get_caller_reply_info(&uuid).await {
                debug!("B2BUA: relaying INFO (callee→caller) to {}", dest);
                let out = self.apply_outbound_topology(&raw_info, tp);
                self.send_sip("INFO → caller", out.as_bytes(), dest, tp, tx.as_ref())
                    .await;
            }
        } else {
            debug!(
                "INFO: no matching call for Call-ID {} — answering 200 anyway",
                call_id
            );
        }

        // Answer the sender (the relayed leg's response is not awaited —
        // half-B2BUA answers locally like it does for BYE)
        self.metrics.inc_sip_response(200);
        let response_200 = match build_plain_response_for_request(&request, 200, "OK") {
            Ok(r) => r.to_string().into_bytes(),
            Err(_) => build_plain_response(200, "OK").into_bytes(),
        };
        self.transport
            .reply(&response_200, source, transport, reply_tx)
            .await
    }

    pub(crate) async fn handle_refer(
        &mut self,
        request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Received REFER from {}", source);

        let call_id = request
            .call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        // Extract Refer-To header (the transfer target URI)
        let refer_to = request.headers.iter().find_map(|h| {
            let s = h.to_string();
            if s.starts_with("Refer-To:") || s.starts_with("refer-to:") {
                Some(
                    s.split_once(':')
                        .map(|(_, v)| v.trim().to_string())
                        .unwrap_or_default(),
                )
            } else {
                None
            }
        });

        if refer_to.is_none() {
            warn!("REFER missing Refer-To header");
            self.metrics.inc_sip_response(400);
            let r400 = build_plain_response_for_request(&request, 400, "Missing Refer-To")?;
            let data = r400.to_string().into_bytes();
            return self
                .transport
                .reply(&data, source, transport, reply_tx)
                .await;
        }
        let refer_target = refer_to.unwrap();
        info!("REFER: transfer to '{}'", refer_target);

        // Find the existing call
        let found = self.b2bua.find_by_any_call_id(&call_id).await;
        if found.is_none() {
            warn!("REFER: no active call for Call-ID: {}", call_id);
            self.metrics.inc_sip_response(481);
            let r481 =
                build_plain_response_for_request(&request, 481, "Call/Transaction Does Not Exist")?;
            let data = r481.to_string().into_bytes();
            return self
                .transport
                .reply(&data, source, transport, reply_tx)
                .await;
        }

        let (uuid, is_from_caller) = found.unwrap();
        if let Some(cseq) = request
            .cseq_header()
            .ok()
            .and_then(|h| h.typed().ok())
            .map(|c: rsip::typed::CSeq| c.seq)
        {
            self.b2bua
                .note_relayed_cseq(&uuid, is_from_caller, cseq)
                .await;
        }

        // Send 202 Accepted (RFC 3515 §2.4.2)
        self.metrics.inc_sip_response(202);
        let response_202 = build_plain_response_for_request(&request, 202, "Accepted")?;
        let data = response_202.to_string().into_bytes();
        self.transport
            .reply(&data, source, transport, reply_tx)
            .await?;

        // Relay REFER to the other leg (the transferee)
        // In a full implementation, the SBC would:
        //   1. Initiate a new INVITE to refer_target
        //   2. Send NOTIFY sipfrag updates to the transferor
        //   3. Bridge the new call and disconnect the original
        // For now we relay the REFER as-is (attended transfer via relay).
        if is_from_caller {
            if let Some((callee_reply_tx, callee_dest, callee_transport)) =
                self.b2bua.get_callee_reply_info(&uuid).await
            {
                info!("REFER: relaying to callee at {}", callee_dest);
                let raw = rsip::SipMessage::Request(request).to_string();
                self.send_sip(
                    "REFER → callee",
                    raw.as_bytes(),
                    callee_dest,
                    callee_transport,
                    callee_reply_tx.as_ref(),
                )
                .await;
            }
        } else if let Some((caller_reply_tx, caller_addr, caller_transport)) =
            self.b2bua.get_caller_reply_info(&uuid).await
        {
            info!("REFER: relaying to caller at {}", caller_addr);
            let raw = rsip::SipMessage::Request(request).to_string();
            self.send_sip(
                "REFER → caller",
                raw.as_bytes(),
                caller_addr,
                caller_transport,
                caller_reply_tx.as_ref(),
            )
            .await;
        }

        Ok(())
    }
}

/// CSeq header value for the ACK relayed toward the callee: the callee-leg
/// INVITE's number when known (it diverges from the caller's after a
/// 407/422 retry), else the caller's own header (registrar-routed callees
/// keep the caller's CSeq end to end).
fn ack_cseq_for_callee(caller_cseq_header: &str, outbound_invite_cseq: Option<u32>) -> String {
    match outbound_invite_cseq {
        Some(n) => format!("{} ACK", n),
        None => caller_cseq_header.to_string(),
    }
}

#[cfg(test)]
mod ack_tests {
    use super::ack_cseq_for_callee;

    #[test]
    fn ack_cseq_prefers_callee_leg_invite_cseq() {
        assert_eq!(ack_cseq_for_callee("1 ACK", Some(4)), "4 ACK");
        assert_eq!(ack_cseq_for_callee("17 ACK", Some(17)), "17 ACK");
        assert_eq!(ack_cseq_for_callee("1 ACK", None), "1 ACK");
    }
}
