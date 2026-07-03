use super::*;

impl Sbc {
    /// Check for calls that have exceeded the maximum duration and terminate them.
    /// This prevents phantom sessions when the callee drops without sending BYE.
    /// Max duration: 7200 seconds (2 hours). Check runs every 30s from the event loop.
    pub(crate) async fn check_call_timeouts(&mut self) {
        const MAX_CALL_DURATION_SECS: u64 = 7200; // 2 hours

        let calls = self.b2bua.calls_locked().await;
        let timed_out: Vec<_> = calls.values()
            .filter(|c| c.started_at.elapsed().as_secs() > MAX_CALL_DURATION_SECS)
            .map(|c| {
                (
                    c.uuid.clone(),
                    c.inbound.call_id.clone(),
                    c.caller_source,
                    c.caller_transport,
                    c.caller_reply_tx.clone(),
                    c.callee_dest,
                    c.callee_transport,
                    c.callee_reply_tx.clone(),
                    c.media_session_id.clone(),
                    c.outbound.as_ref().map(|l| l.call_id.clone()),
                    c.started_at.elapsed().as_secs(),
                )
            })
            .collect();
        drop(calls);

        if timed_out.is_empty() {
            return;
        }

        let sbc_ip = self.identity.as_ref()
            .map(|id| id.public_ip.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        for (uuid, call_id, caller_addr, caller_transport, caller_tx,
             callee_dest, callee_transport, callee_tx, media_id,
             outbound_call_id, duration) in timed_out
        {
            warn!("Call timeout: {} (Call-ID: {}) exceeded {}s (active {}s) — sending BYE to both sides",
                &uuid[..8], call_id, MAX_CALL_DURATION_SECS, duration);

            // BYE to caller (trunk)
            let bye_caller = format!(
                "BYE sip:bye@{} SIP/2.0\r\n\
                 Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK{}\r\n\
                 From: <sip:sbc@{}>;tag=timeout-{}\r\n\
                 To: <sip:caller@{}>\r\n\
                 Call-ID: {}\r\n\
                 CSeq: 1 BYE\r\n\
                 Reason: Q.850;cause=16;text=\"Call duration exceeded\"\r\n\
                 Content-Length: 0\r\n\r\n",
                caller_addr.ip(), sbc_ip,
                &uuid::Uuid::new_v4().to_string()[..8],
                sbc_ip, &uuid[..8], caller_addr.ip(),
                call_id
            );
            let _ = self.transport.reply(
                bye_caller.as_bytes(), caller_addr, caller_transport,
                caller_tx.as_ref(),
            ).await;

            // BYE to callee
            if let Some(dest) = callee_dest {
                let callee_call_id = outbound_call_id.as_deref().unwrap_or(&call_id);
                let bye_callee = format!(
                    "BYE sip:bye@{} SIP/2.0\r\n\
                     Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK{}\r\n\
                     From: <sip:sbc@{}>;tag=timeout-{}\r\n\
                     To: <sip:callee@{}>\r\n\
                     Call-ID: {}\r\n\
                     CSeq: 1 BYE\r\n\
                     Reason: Q.850;cause=16;text=\"Call duration exceeded\"\r\n\
                     Content-Length: 0\r\n\r\n",
                    dest.ip(), sbc_ip,
                    &uuid::Uuid::new_v4().to_string()[..8],
                    sbc_ip, &uuid[..8], dest.ip(),
                    callee_call_id
                );
                let _ = self.transport.reply(
                    bye_callee.as_bytes(), dest, callee_transport,
                    callee_tx.as_ref(),
                ).await;
            }

            // Terminate media session
            if let Some(ref mid) = media_id {
                if let Err(e) = self.media.terminate_session(mid) {
                    warn!("Timeout: failed to terminate media session {}: {}", mid, e);
                }
            }

            // Cleanup B2BUA state and metrics
            self.metrics.inc_call_terminated();
            self.b2bua.terminate_call(&uuid).await;
        }
    }

    /// Send BYE to all active call peers before shutdown.
    /// This prevents phantom sessions on remote trunks (e.g. trunk OverMaxCall).
    pub(crate) async fn graceful_shutdown(&mut self) {
        let calls = self.b2bua.calls_locked().await;
        let active: Vec<_> = calls.values().map(|c| {
            (
                c.uuid.clone(),
                c.inbound.call_id.clone(),
                c.caller_source,
                c.caller_transport,
                c.caller_reply_tx.clone(),
                c.callee_dest,
                c.callee_transport,
                c.callee_reply_tx.clone(),
                c.media_session_id.clone(),
                c.inbound.local_tag.clone(),
                c.inbound.remote_tag.clone(),
                c.outbound.as_ref().map(|l| l.local_tag.clone()),
                c.outbound.as_ref().map(|l| l.remote_tag.clone()),
                c.outbound.as_ref().map(|l| l.call_id.clone()),
            )
        }).collect();
        drop(calls);

        let count = active.len();
        if count == 0 {
            info!("Graceful shutdown: no active calls");
            return;
        }

        info!("Graceful shutdown: sending BYE for {} active call(s)", count);

        let sbc_ip = self.identity.as_ref()
            .map(|id| id.public_ip.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        for (uuid, call_id, caller_addr, caller_transport, caller_tx,
             callee_dest, callee_transport, callee_tx, media_id,
             _inbound_local_tag, _inbound_remote_tag,
             _outbound_local_tag, _outbound_remote_tag, outbound_call_id) in active
        {
            // Build BYE for caller leg
            let bye_caller = format!(
                "BYE sip:bye@{} SIP/2.0\r\n\
                 Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK{}\r\n\
                 From: <sip:sbc@{}>;tag=shutdown-{}\r\n\
                 To: <sip:caller@{}>\r\n\
                 Call-ID: {}\r\n\
                 CSeq: 1 BYE\r\n\
                 Reason: Q.850;cause=16;text=\"Server shutdown\"\r\n\
                 Content-Length: 0\r\n\r\n",
                caller_addr.ip(), sbc_ip,
                &uuid::Uuid::new_v4().to_string()[..8],
                sbc_ip, &uuid[..8], caller_addr.ip(),
                call_id
            );
            info!("Shutdown BYE → caller {} (call {})", caller_addr, &uuid[..8]);
            let _ = self.transport.reply(
                bye_caller.as_bytes(), caller_addr, caller_transport,
                caller_tx.as_ref(),
            ).await;

            // Build BYE for callee leg
            if let Some(dest) = callee_dest {
                let callee_call_id = outbound_call_id.as_deref().unwrap_or(&call_id);
                let bye_callee = format!(
                    "BYE sip:bye@{} SIP/2.0\r\n\
                     Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK{}\r\n\
                     From: <sip:sbc@{}>;tag=shutdown-{}\r\n\
                     To: <sip:callee@{}>\r\n\
                     Call-ID: {}\r\n\
                     CSeq: 1 BYE\r\n\
                     Reason: Q.850;cause=16;text=\"Server shutdown\"\r\n\
                     Content-Length: 0\r\n\r\n",
                    dest.ip(), sbc_ip,
                    &uuid::Uuid::new_v4().to_string()[..8],
                    sbc_ip, &uuid[..8], dest.ip(),
                    callee_call_id
                );
                info!("Shutdown BYE → callee {} (call {})", dest, &uuid[..8]);
                let _ = self.transport.reply(
                    bye_callee.as_bytes(), dest, callee_transport,
                    callee_tx.as_ref(),
                ).await;
            }

            // Terminate media session
            if let Some(ref mid) = media_id {
                if let Err(e) = self.media.terminate_session(mid) {
                    warn!("Shutdown: failed to terminate media session {}: {}", mid, e);
                } else {
                    info!("Shutdown: terminated media session {}", mid);
                }
            }
        }

        // Give time for BYE packets to be sent
        tokio::time::sleep(Duration::from_millis(500)).await;
        info!("Graceful shutdown: all BYEs sent");
    }

    /// Handle ACK — must be relayed to callee so dialog completes (RFC 3261 §13.2.2.4)
    pub(crate) async fn handle_ack(
        &mut self,
        request: Request,
        source: SocketAddr,
        _transport: rsip::Transport,
        _reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        let call_id = request.call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        info!("Received ACK from {} (Call-ID: {})", source, call_id);

        // Try exact match first, then suffix match (some trunks add prefixes to Call-ID
        // in INVITE but send ACK with original shorter Call-ID)
        let maybe_uuid = if let Some(uuid) = self.b2bua.find_by_inbound_call_id(&call_id).await {
            Some(uuid)
        } else if let Some(uuid) = self.b2bua.find_by_inbound_call_id_suffix(&call_id).await {
            info!("ACK matched B2BUA call via suffix match (ACK Call-ID is shorter than stored)");
            Some(uuid)
        } else {
            // Also try outbound call-id (in case ACK comes from callee side)
            self.b2bua.find_by_outbound_call_id(&call_id).await
        };

        if let Some(uuid) = maybe_uuid {
            info!("ACK matched B2BUA call {} (call-id: {})", uuid, call_id);
            let _ = self.b2bua.handle_ack(&uuid).await;

            // Relay ACK to callee so the callee's INVITE transaction completes
            // and retransmissions of 200 OK stop (RFC 3261 §13.2.2.4)
            if let Some((callee_reply_tx, callee_dest, callee_transport)) =
                self.b2bua.get_callee_reply_info(&uuid).await
            {
                // Build a fresh ACK for the callee leg (B2BUA must rewrite headers)
                let callee_contact = format!("sip:{}:{}", callee_dest.ip(), callee_dest.port());
                let _caller_user = request.from_header()
                    .ok()
                    .map(|h| h.value().to_string())
                    .unwrap_or_default();
                let to_header = request.to_header()
                    .ok()
                    .map(|h| h.value().to_string())
                    .unwrap_or_default();
                let from_header = request.from_header()
                    .ok()
                    .map(|h| h.value().to_string())
                    .unwrap_or_default();
                let cseq_header = request.cseq_header()
                    .ok()
                    .map(|h| h.value().to_string())
                    .unwrap_or("1 ACK".to_string());

                // Get the callee's Request-URI (the contact from the callee's 200 OK)
                let callee_req_uri = self.b2bua.get_callee_contact_uri(&uuid).await
                    .unwrap_or(callee_contact.clone());

                // CRITICAL: Use the stored inbound Call-ID (the full one) for the ACK
                // to the callee — NOT the (possibly truncated) Call-ID from the ACK we received.
                // The trunk may strip prefixes from the Call-ID in the ACK.
                let callee_call_id = self.b2bua.get_inbound_call_id(&uuid).await
                    .unwrap_or_else(|| call_id.clone());

                let sbc_ip = self.identity.as_ref()
                    .map(|id| id.public_ip.clone())
                    .unwrap_or_else(|| "203.0.113.1".to_string());
                let sbc_port = if callee_transport == rsip::Transport::Udp { 5060 } else { 5061 };

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
                    sbc_ip, sbc_port,
                    rand::random::<u32>(),
                    from_header,
                    to_header,
                    callee_call_id,
                    cseq_header,
                );

                info!("Relaying ACK to callee at {} via {:?}:\n{}", callee_dest, callee_transport, ack_msg.trim());
                let _ = self.transport.reply(
                    ack_msg.as_bytes(),
                    callee_dest,
                    callee_transport,
                    callee_reply_tx.as_ref(),
                ).await;
            } else {
                warn!("ACK: no callee_reply_info for call {} — callee_dest may be None", uuid);
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

        let call_id = request.call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        // Find by EITHER inbound or outbound Call-ID, using source IP to disambiguate
        // (both legs share the same Call-ID in our half-B2BUA)
        let mut found = self.b2bua.find_by_any_call_id_with_source(&call_id, Some(source)).await;

        // ── Trunk IP fallback ──────────────────────────────────────────
        // If no match was found by source IP, but the BYE comes from a known trunk IP,
        // try again without source disambiguation. Trunk may send BYE from a different
        // IP (e.g. 198.51.100.11) than the INVITE was sent to (198.51.100.10).
        if found.is_none() {
            let source_ip = source.ip().to_string();
            // Check if source is a trunk IP or in the same /24 as a known trunk
            let is_trunk_related = self.trunk_ips.read().await.iter().any(|tip| {
                tip == &source_ip || {
                    // Same /24 subnet check for trunk clusters
                    let tip_prefix = tip.rsplitn(2, '.').nth(1);
                    let src_prefix = source_ip.rsplitn(2, '.').nth(1);
                    tip_prefix.is_some() && tip_prefix == src_prefix
                }
            });
            if is_trunk_related {
                info!("BYE from trunk-related IP {} — retrying lookup without source filter", source_ip);
                found = self.b2bua.find_by_any_call_id_with_source(&call_id, None).await;
                // For inbound PSTN calls, the "caller" is the trunk side.
                // If the fallback found it as "from caller" (trunk), that's correct —
                // we need to relay the BYE to the callee (local SIP user).
            }
        }

        if let Some((uuid, is_from_caller)) = found {
            info!("BYE identified as from {} (source: {})",
                if is_from_caller { "caller" } else { "callee" }, source);

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

                    // Log the incoming BYE From/To for debugging dialog match issues
                    let from_hdr = request.from_header().ok().map(|h| h.to_string()).unwrap_or_default();
                    let to_hdr = request.to_header().ok().map(|h| h.to_string()).unwrap_or_default();
                    info!("BYE incoming From: {}", from_hdr);
                    info!("BYE incoming To: {}", to_hdr);

                    let mut raw_bye = rsip::SipMessage::Request(request.clone()).to_string();
                    // Rewrite Call-ID if it was a suffix match — callee knows the full Call-ID
                    if let Some((ref stored_inbound_cid, _)) = stored_call_ids {
                        if *stored_inbound_cid != call_id && stored_inbound_cid.ends_with(&call_id) {
                            info!("BYE Call-ID rewrite: '{}' → '{}'", call_id, stored_inbound_cid);
                            raw_bye = raw_bye.replace(&format!("Call-ID: {}", call_id),
                                                      &format!("Call-ID: {}", stored_inbound_cid));
                        }
                    }
                    let bye_out = self.apply_outbound_topology(&raw_bye, callee_transport);
                    info!("BYE relayed to callee:\n{}", bye_out);
                    let _ = self.transport.reply(
                        bye_out.as_bytes(),
                        callee_dest,
                        callee_transport,
                        callee_reply_tx.as_ref(),
                    ).await;
                }
            } else {
                // BYE from callee → relay to caller
                let caller_info = self.b2bua.get_caller_reply_info(&uuid).await;
                let _ = self.b2bua.handle_bye(&uuid).await;

                if let Some((caller_reply_tx, caller_addr, caller_transport)) = caller_info {
                    info!("B2BUA: relaying BYE (callee→caller) to {}", caller_addr);
                    let mut raw_bye = rsip::SipMessage::Request(request.clone()).to_string();
                    // Rewrite Call-ID if it was a suffix match — caller knows the full Call-ID
                    if let Some((ref stored_inbound_cid, _)) = stored_call_ids {
                        if *stored_inbound_cid != call_id && stored_inbound_cid.ends_with(&call_id) {
                            info!("BYE Call-ID rewrite: '{}' → '{}'", call_id, stored_inbound_cid);
                            raw_bye = raw_bye.replace(&format!("Call-ID: {}", call_id),
                                                      &format!("Call-ID: {}", stored_inbound_cid));
                        }
                    }
                    let bye_out = self.apply_outbound_topology(&raw_bye, caller_transport);
                    let _ = self.transport.reply(
                        bye_out.as_bytes(),
                        caller_addr,
                        caller_transport,
                        caller_reply_tx.as_ref(),
                    ).await;
                }
            }

            // ── CDR: record the terminated call (enriched) ──────────────────
            {
                let calls = self.b2bua.calls_locked().await;
                if let Some(call) = calls.get(&uuid) {
                    let call_id = call.inbound.call_id.clone();
                    let caller = call.caller_number.clone().unwrap_or_else(|| call.inbound.call_id.clone());
                    let callee = call.callee_number.clone().unwrap_or_else(|| {
                        call.outbound.as_ref().map(|l| l.call_id.clone()).unwrap_or_default()
                    });
                    let duration = call.duration_secs();
                    let is_webrtc = call.caller_is_webrtc;
                    let codec = call.codec.clone();
                    let trunk_name = call.trunk_name.clone();
                    drop(calls); // release lock before async call

                    let mut record = crate::storage::CdrRecord::new(
                        call_id, caller, callee,
                    ).with_duration(duration)
                     .with_webrtc(is_webrtc)
                     .with_disconnect_reason("normal-clearing");
                    if let Some(c) = codec.as_deref() {
                        record = record.with_codec(c);
                    }
                    record.trunk_id = trunk_name;
                    if let Err(e) = self.cdr.storage().insert_cdr(&record).await {
                        warn!("CDR recording failed: {}", e);
                    } else {
                        info!("CDR: {} → {} ({} secs, codec={}, trunk={}, webrtc={})",
                            record.caller, record.callee, duration,
                            record.codec.as_deref().unwrap_or("unknown"),
                            record.trunk_id.as_deref().unwrap_or("local"),
                            is_webrtc);
                    }
                }
            }

            // ── Metrics: call terminated (inc_call_terminated also decrements active_calls) ──
            self.metrics.inc_call_terminated();

            // Update gauges after termination
            {
                let stats = self.b2bua.stats().await;
                self.metrics.set_active_webrtc(stats.webrtc_calls as u64);
            }
            self.metrics.set_allocated_ports(self.media.stats().allocated_ports as u64);

            // Mark call terminated
            self.b2bua.terminate_call(&uuid).await;
        } else {
            warn!("BYE: no B2BUA call found for Call-ID: {} from {} (stray BYE — phantom session?)", call_id, source);
        }

        // Send 200 OK for BYE back to sender (RFC 3261 §15.1.2)
        self.metrics.inc_sip_response(200);
        let response_200 = match build_plain_response_for_request(&request, 200, "OK") {
            Ok(r) => r.to_string().into_bytes(),
            Err(_) => build_plain_response(200, "OK").into_bytes(),
        };
        self.transport.reply(&response_200, source, transport, reply_tx).await
    }

    /// Handle CANCEL — relay to callee + send 487 to original caller (RFC 3261 §9)
    pub(crate) async fn handle_cancel(
        &mut self,
        request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Received CANCEL from {}", source);

        let call_id = request.call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        if let Some(uuid) = self.b2bua.find_by_inbound_call_id(&call_id).await {
            // Get callee info BEFORE terminating the call
            let callee_cancel_info = self.b2bua.get_callee_cancel_info(&uuid).await;

            // Terminate call + release media
            let media_id = self.b2bua.get_media_session_id(&uuid).await;
            if let Some(mid) = media_id {
                let _ = self.media.terminate_session(&mid);
            }
            self.b2bua.terminate_call(&uuid).await;
            self.metrics.inc_call_failed();

            // Relay CANCEL to callee (if the INVITE was already forwarded)
            if let Some((_out_call_id, _cseq, callee_dest, callee_reply_tx, callee_transport)) = callee_cancel_info {
                info!("B2BUA: relaying CANCEL to callee at {}", callee_dest);
                let raw_cancel = rsip::SipMessage::Request(request.clone()).to_string();
                let cancel_out = self.apply_outbound_topology(&raw_cancel, callee_transport);
                let _ = self.transport.reply(
                    cancel_out.as_bytes(),
                    callee_dest,
                    callee_transport,
                    callee_reply_tx.as_ref(),
                ).await;
            }
        }

        // Send 200 OK for CANCEL back to caller (RFC 3261 §9.2)
        self.metrics.inc_sip_response(200);
        let response_200 = match build_plain_response_for_request(&request, 200, "OK") {
            Ok(r) => r.to_string().into_bytes(),
            Err(_) => build_plain_response(200, "OK").into_bytes(),
        };
        self.transport.reply(&response_200, source, transport, reply_tx).await
    }

    /// Handle REFER — Attended/Blind Transfer (RFC 3515)
    ///
    /// REFER triggers call transfer:
    ///  1. Extract Refer-To header (the transfer target)
    ///  2. Accept with 202 Accepted
    ///  3. Create new INVITE to the transfer target
    ///  4. Send NOTIFY to the transferor with transfer progress
    ///  5. On success, bridge new call and disconnect transferor
    pub(crate) async fn handle_refer(
        &mut self,
        request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Received REFER from {}", source);

        let call_id = request.call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        // Extract Refer-To header (the transfer target URI)
        let refer_to = request.headers.iter()
            .find_map(|h| {
                let s = h.to_string();
                if s.starts_with("Refer-To:") || s.starts_with("refer-to:") {
                    Some(s.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default())
                } else {
                    None
                }
            });

        if refer_to.is_none() {
            warn!("REFER missing Refer-To header");
            self.metrics.inc_sip_response(400);
            let r400 = build_plain_response_for_request(&request, 400, "Missing Refer-To")?;
            let data = r400.to_string().into_bytes();
            return self.transport.reply(&data, source, transport, reply_tx).await;
        }
        let refer_target = refer_to.unwrap();
        info!("REFER: transfer to '{}'", refer_target);

        // Find the existing call
        let found = self.b2bua.find_by_any_call_id(&call_id).await;
        if found.is_none() {
            warn!("REFER: no active call for Call-ID: {}", call_id);
            self.metrics.inc_sip_response(481);
            let r481 = build_plain_response_for_request(&request, 481, "Call/Transaction Does Not Exist")?;
            let data = r481.to_string().into_bytes();
            return self.transport.reply(&data, source, transport, reply_tx).await;
        }

        let (uuid, is_from_caller) = found.unwrap();

        // Send 202 Accepted (RFC 3515 §2.4.2)
        self.metrics.inc_sip_response(202);
        let response_202 = build_plain_response_for_request(&request, 202, "Accepted")?;
        let data = response_202.to_string().into_bytes();
        self.transport.reply(&data, source, transport, reply_tx).await?;

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
                let _ = self.transport.reply(
                    raw.as_bytes(), callee_dest, callee_transport,
                    callee_reply_tx.as_ref(),
                ).await;
            }
        } else {
            if let Some((caller_reply_tx, caller_addr, caller_transport)) =
                self.b2bua.get_caller_reply_info(&uuid).await
            {
                info!("REFER: relaying to caller at {}", caller_addr);
                let raw = rsip::SipMessage::Request(request).to_string();
                let _ = self.transport.reply(
                    raw.as_bytes(), caller_addr, caller_transport,
                    caller_reply_tx.as_ref(),
                ).await;
            }
        }

        Ok(())
    }
}
