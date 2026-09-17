use super::*;

/// Caller reply channel + address + transport, as returned by
/// `B2buaManager::get_caller_reply_info`.
type CallerReplyInfo = Option<(
    Option<UnboundedSender<Vec<u8>>>,
    SocketAddr,
    rsip::Transport,
)>;

impl Sbc {
    /// Handle incoming SIP response (from trunk/callee) — relay back to caller
    /// `reply_tx` is the connection the response arrived on (None for UDP):
    /// a stray final after teardown is ACKed back over it.
    pub(crate) async fn handle_response(
        &mut self,
        response: Response,
        source: SocketAddr,
        _transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        let status = response.status_code.code();
        info!("Handling {} response from {}", status, source);

        // ── Metrics: count SIP responses + error classes ──
        self.metrics.inc_sip_response(status);
        if (400..500).contains(&status) {
            self.metrics
                .sip_4xx_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if status >= 500 {
            self.metrics
                .sip_5xx_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Extract Call-ID to find associated B2BUA call
        let call_id = response
            .call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();

        info!("Response Call-ID: {}", call_id);

        // ── Route outbound REGISTER / OPTIONS health-check responses ──
        // Trunk REGISTER responses use "reg-" Call-IDs, OPTIONS health checks
        // use "hc-" Call-IDs; both are awaited on a oneshot channel by their
        // respective background task via pending_register_responses.
        if call_id.starts_with("reg-") || call_id.starts_with("hc-") {
            if let Some((_, tx)) = self.pending_register_responses.remove(&call_id) {
                let raw = rsip::SipMessage::Response(response).to_string();
                let _ = tx.send(raw);
                debug!(
                    "Routed trunk task response (Call-ID: {}) to waiting task",
                    call_id
                );
            } else {
                debug!(
                    "No pending channel for Call-ID: {} (stale or already consumed)",
                    call_id
                );
            }
            return Ok(());
        }

        if let Some(uuid) = self.b2bua.find_by_inbound_call_id(&call_id).await {
            // Get caller's reply info before processing the response
            let caller_info = self.b2bua.get_caller_reply_info(&uuid).await;
            // The caller's INVITE CSeq: restored in every relayed response,
            // since 407/422 retries bump the CSeq on the callee leg only.
            let caller_cseq = self.b2bua.get_caller_invite_cseq(&uuid).await;

            // ── Callee-leg transaction prelude ─────────────────────────────
            // 1. Responses to SBC-originated CANCEL/BYE: nothing awaits them
            //    (a 481/200 to our CANCEL after a failover must not touch the
            //    call now ringing on the next trunk).
            // 2. Answers to our own refresh re-INVITE: consumed locally.
            // 3. Attribute INVITE responses to the attempt they belong to:
            //    a late 422/487 from a superseded attempt is ACKed and dropped.
            // 4. ACK every non-2xx INVITE final (RFC 3261 §17.1.1.3) so UDP
            //    peers stop retransmitting it for 32 s.
            if let Some((resp_cseq, method)) = response_cseq(&response) {
                // Nothing awaits the answers to what the SBC sent itself
                // (CANCEL/BYE) or relayed and already answered locally
                // (INFO/REFER); letting a 200 OK to a DTMF INFO reach the
                // INVITE arm would re-run the answer logic on the dialog.
                if !method.eq_ignore_ascii_case("INVITE") {
                    debug!(
                        "{} to {} on call {} — not an INVITE transaction, dropped",
                        status, method, uuid
                    );
                    return Ok(());
                }
                if method.eq_ignore_ascii_case("INVITE") {
                    let raw_resp = rsip::SipMessage::Response(response.clone()).to_string();
                    let response_to = response
                        .to_header()
                        .ok()
                        .map(|h| h.value().to_string())
                        .unwrap_or_default();

                    if self.b2bua.is_pending_refresh(&uuid, resp_cseq).await {
                        self.handle_refresh_response(
                            &uuid,
                            status,
                            resp_cseq,
                            &raw_resp,
                            &response_to,
                        )
                        .await;
                        return Ok(());
                    }
                    // Retransmitted answer to a refresh whose outcome was already
                    // consumed (our ACK got lost): re-ACK, never treat it as a
                    // final of the callee-leg INVITE.
                    let (sbc_ip, sbc_port) = self.sbc_addr();
                    if let Some((ack, dest, tp, tx)) = self
                        .b2bua
                        .refresh_duplicate_ack(
                            &uuid,
                            resp_cseq,
                            status,
                            &response_to,
                            &sbc_ip,
                            sbc_port,
                        )
                        .await
                    {
                        debug!(
                            "{} for session refresh CSeq {} (call {}) — duplicate, re-ACKed",
                            status, resp_cseq, uuid
                        );
                        if let Some(ack) = ack {
                            self.send_sip(
                                "ACK (refresh duplicate) → callee",
                                ack.as_bytes(),
                                dest,
                                tp,
                                tx.as_ref(),
                            )
                            .await;
                        }
                        return Ok(());
                    }

                    let branch = crate::sip_builder::top_via_branch(&raw_resp);
                    if let Some(crate::b2bua::InviteResponseClass::Stale(attempt)) = self
                        .b2bua
                        .classify_invite_response(&uuid, branch.as_deref(), resp_cseq)
                        .await
                    {
                        self.handle_stale_invite_response(
                            &uuid,
                            status,
                            resp_cseq,
                            &response,
                            &response_to,
                            attempt,
                        )
                        .await;
                        return Ok(());
                    }

                    if status >= 300 {
                        self.ack_callee_final(&uuid, &response_to).await;
                    }
                }
            }

            match status {
                100..=199 => {
                    // Provisional (180 Ringing, 183 Session Progress, etc.) — relay to caller
                    // >=180 means this trunk is progressing the dialog: failover off.
                    // (100 Trying only proves the hop is alive — timer keeps running.)
                    if status >= 180 {
                        self.b2bua.mark_provisional_received(&uuid).await;
                        self.b2bua.mark_alerting(&uuid).await;
                    }
                    let _ = self.b2bua.handle_ringing(&uuid).await;
                    info!("B2BUA: relaying {} to caller", status);
                    if let Some((reply_tx, caller_addr, caller_transport)) = caller_info {
                        // ── CRITICAL: Restore caller's original Via headers ──────
                        // The response from the callee has the SBC's outbound Via.
                        // The caller will drop it because the branch doesn't match.
                        // We MUST replace the Via with the caller's original Via.
                        let caller_vias = self.b2bua.get_caller_vias(&uuid).await;
                        let raw = rsip::SipMessage::Response(response).to_string();
                        let raw = rewrite_response_for_caller(
                            &raw,
                            &caller_vias,
                            self.identity.as_ref(),
                            caller_cseq,
                        );

                        // ── WebRTC: strip SDP body from 183 Session Progress ────
                        // The trunk sends PCMA/AVP SDP in 183 which is incompatible
                        // with the browser's WebRTC PeerConnection. The real WebRTC
                        // SDP answer is generated by the SBC in the 200 OK handler.
                        let raw = if status == 183 && self.b2bua.is_caller_webrtc(&uuid).await {
                            strip_sdp_body(&raw)
                        } else {
                            raw
                        };

                        self.send_sip(
                            "1xx → caller",
                            raw.as_bytes(),
                            caller_addr,
                            caller_transport,
                            reply_tx.as_ref(),
                        )
                        .await;
                    }
                }
                200..=299 => {
                    // (Answers to our own refresh re-INVITEs were consumed by
                    // the prelude above — they never reach this arm.)

                    // Final success (200 OK) — rewrite SDP + relay to caller + start RTP proxy
                    let callee_tag = response
                        .to_header()
                        .ok()
                        .and_then(|h| h.typed().ok())
                        .and_then(|to: rsip::typed::To| {
                            to.params.iter().find_map(|p| {
                                if let rsip::Param::Tag(t) = p {
                                    Some(t.value().to_string())
                                } else {
                                    None
                                }
                            })
                        })
                        .unwrap_or_default();

                    let callee_sdp_str = if !response.body.is_empty() {
                        std::str::from_utf8(&response.body)
                            .ok()
                            .map(|s| s.to_string())
                    } else {
                        None
                    };

                    // ── Gather info BEFORE taking the B2BUA lock ──────────────────────
                    // Read caller_sdp and media_id while the lock is NOT yet held
                    // (handle_200_ok will acquire it; avoid deadlock with calls_locked)
                    let (caller_sdp_str_pre, media_id_pre) = {
                        let calls = self.b2bua.calls_locked().await;
                        let c = calls.get(&uuid);
                        let csdp = c.and_then(|c| c.caller_sdp.clone());
                        let mid = c.and_then(|c| c.media_session_id.clone());
                        (csdp, mid)
                    };

                    let _ = self
                        .b2bua
                        .handle_200_ok(&uuid, callee_tag, callee_sdp_str.clone())
                        .await;

                    // ── Record the negotiated codec (from the SDP answer) for the CDR ──
                    if let Some(ref sdp) = callee_sdp_str {
                        if let Some(codec) = crate::media::sdp::negotiated_audio_codec(sdp) {
                            self.b2bua.set_codec(&uuid, &codec).await;
                        }
                    }

                    // ── Capture established dialog identity (raw From/To/Contact) ──
                    // The 200 OK's To carries the callee tag; From matches our
                    // outbound INVITE. Needed for synthetic in-dialog requests.
                    {
                        let from_raw = response.from_header().ok().map(|h| h.value().to_string());
                        let to_raw = response.to_header().ok().map(|h| h.value().to_string());
                        let callee_contact = response
                            .contact_header()
                            .ok()
                            .map(|h| super::invite_handler_contact_uri(h.value()));
                        if let (Some(from_raw), Some(to_raw)) = (from_raw, to_raw) {
                            self.b2bua
                                .set_established_dialog(&uuid, from_raw, to_raw, callee_contact)
                                .await;
                        }
                    }

                    // ── RFC 4028: arm the session timer on the trunk leg ──────
                    // Interval = the 200 OK's Session-Expires when present
                    // (trunk answers e.g. 14400;refresher=uac — WE are the uac
                    // and must refresh), else what WE offered in the INVITE
                    // (raised by a 422 retry), else our configured value.
                    // Min-SE likewise follows the offer, so refresh
                    // re-INVITEs never fall below what the trunk demanded.
                    if let Some((configured, cfg_min_se)) = self.session_timer {
                        // Same gate as the offer (set_session_timer_headers in
                        // handle_invite): trunk_id. trunk_name is also set from
                        // the SOURCE IP on inbound trunk→user calls, where the
                        // SBC deliberately offered no timers and must not refresh.
                        let toward_trunk = {
                            let calls = self.b2bua.calls_locked().await;
                            calls
                                .get(&uuid)
                                .map(|c| c.trunk_id.is_some())
                                .unwrap_or(false)
                        };
                        if toward_trunk {
                            let raw_resp = rsip::SipMessage::Response(response.clone()).to_string();
                            let offered =
                                self.b2bua.current_attempt(&uuid).await.map(|(a, _)| a.raw);
                            let offered_se = offered.as_deref().and_then(parse_session_expires);
                            let min_se = offered
                                .as_deref()
                                .and_then(parse_min_se)
                                .unwrap_or(cfg_min_se)
                                .max(cfg_min_se);
                            let negotiated = parse_session_expires(&raw_resp)
                                .or(offered_se)
                                .unwrap_or(configured)
                                .max(min_se);
                            self.b2bua
                                .set_session_timer(&uuid, negotiated, min_se)
                                .await;
                        }
                    }

                    // ── Start RTP proxy after 200 OK ───────────────────────────────────
                    // Guard: only start once (200 OK retransmissions must not re-bind ports)
                    if let Some(media_id) = media_id_pre {
                        let rtp_already_started = self
                            .media
                            .get_session(&media_id)
                            .map(|s| s.rtp_shutdown_tx.is_some())
                            .unwrap_or(false);

                        if rtp_already_started {
                            debug!(
                                "RTP proxy already running for {} — skipping (200 OK retransmit)",
                                media_id
                            );
                        } else {
                            // First 200 OK for this session — count as connected
                            self.metrics.inc_call_connected();

                            // Get caller's public IP (from the TLS/TCP/UDP connection source)
                            // and callee's public IP. These override private IPs from SDP.
                            let (caller_public_ip, callee_public_ip) = {
                                let calls = self.b2bua.calls_locked().await;
                                let c = calls.get(&uuid);
                                let caller_ip = c.map(|c| c.caller_source.ip());
                                let callee_ip = c.and_then(|c| c.callee_dest.map(|d| d.ip()));
                                (caller_ip, callee_ip)
                            };

                            // Configure endpoints from SDP so relay knows where to send RTP.
                            // IMPORTANT: if the SDP IP is a private/NAT address,
                            // replace it with the public IP seen on the signaling connection.
                            //
                            // For WebRTC callers: do NOT pre-configure endpoint A from SDP.
                            // The browser's RTP address is discovered via ICE (STUN binding
                            // requests on the RTP port), not from the SIP signaling address.
                            let caller_is_webrtc_ep = self.b2bua.is_caller_webrtc(&uuid).await;
                            if caller_is_webrtc_ep {
                                info!("RTP proxy: WebRTC caller — endpoint A will be learned via ICE/STUN (not pre-set from SDP)");
                            } else if caller_sdp_str_pre.is_none() {
                                warn!("No caller SDP available — caller endpoint A will be learned dynamically");
                            } else if let Some(ref csdp) = caller_sdp_str_pre {
                                if let Some(sdp_addr) = extract_sdp_rtp_addr(csdp) {
                                    // Use public IP if SDP has private IP (NAT traversal)
                                    let addr = if is_private_ip(sdp_addr.ip()) {
                                        if let Some(public_ip) = caller_public_ip {
                                            let fixed = SocketAddr::new(public_ip, sdp_addr.port());
                                            info!("RTP proxy: caller endpoint A = {} (NAT: SDP had {})", fixed, sdp_addr);
                                            fixed
                                        } else {
                                            info!(
                                                "RTP proxy: caller endpoint A = {} (from SDP)",
                                                sdp_addr
                                            );
                                            sdp_addr
                                        }
                                    } else {
                                        info!("RTP proxy: caller endpoint A = {}", sdp_addr);
                                        sdp_addr
                                    };
                                    let _ = self.media.set_endpoint_a(&media_id, addr);
                                }
                            }

                            // Endpoint B = callee's RTP IP:port (from the 200 OK SDP)
                            // For WebRTC callees: do NOT pre-configure endpoint B from SDP.
                            // The browser's RTP address is discovered via ICE (STUN binding
                            // requests on the RTP port), not from the SIP signaling address.
                            let callee_is_webrtc_ep = self.b2bua.is_callee_webrtc(&uuid).await;
                            if callee_is_webrtc_ep {
                                info!("RTP proxy: WebRTC callee — endpoint B will be learned via ICE/STUN (not pre-set from SDP)");
                            } else if let Some(ref bsdp) = callee_sdp_str {
                                if let Some(sdp_addr) = extract_sdp_rtp_addr(bsdp) {
                                    let addr = if is_private_ip(sdp_addr.ip()) {
                                        if let Some(public_ip) = callee_public_ip {
                                            let fixed = SocketAddr::new(public_ip, sdp_addr.port());
                                            info!("RTP proxy: callee endpoint B = {} (NAT: SDP had {})", fixed, sdp_addr);
                                            fixed
                                        } else {
                                            info!(
                                                "RTP proxy: callee endpoint B = {} (from SDP)",
                                                sdp_addr
                                            );
                                            sdp_addr
                                        }
                                    } else {
                                        info!("RTP proxy: callee endpoint B = {}", sdp_addr);
                                        sdp_addr
                                    };
                                    let _ = self.media.set_endpoint_b(&media_id, addr);
                                }
                            }

                            // ── Store callee SDP for codec analysis / transcoding ──
                            if let Some(ref csdp) = callee_sdp_str {
                                self.media.set_callee_sdp(&media_id, csdp);
                            }

                            // ── Pass ICE password to MediaManager for STUN MESSAGE-INTEGRITY ──
                            if caller_is_webrtc_ep {
                                if let Some(pwd) = self.b2bua.get_webrtc_ice_pwd(&uuid).await {
                                    self.media.set_ice_pwd_local(&media_id, pwd);
                                }
                            }

                            // ── SRTP extraction DISABLED ──────────────────────────
                            // The SBC relays (S)RTP packets as opaque bytes.
                            // It does NOT participate in SRTP key negotiation
                            // (no a=crypto: in SDP answers), so attempting to
                            // decrypt would fail and drop all audio packets.
                            // Both endpoints negotiate SRTP between themselves
                            // via the forwarded SDP crypto attributes.

                            // Start the RTP relay task (bidirectional A↔B relay)
                            match self.media.start_rtp_session(&media_id).await {
                                Ok((webrtc_info, webrtc_info_b)) => {
                                    info!("RTP proxy started for media session {}", media_id);
                                    self.metrics.set_allocated_ports(
                                        self.media.stats().allocated_ports as u64,
                                    );

                                    // ── Spawn DTLS handshake if caller is WebRTC (leg-A) ──
                                    if let Some(winfo) = webrtc_info {
                                        // Get the WebRTC session (contains DtlsContext)
                                        let webrtc_session =
                                            self.b2bua.get_webrtc_session(&uuid).await;
                                        if let Some(ws) = webrtc_session {
                                            let media_id_dtls = media_id.clone();
                                            let srtp_recv_shared = winfo.srtp_recv_ctx_a;
                                            let srtp_send_shared = winfo.srtp_send_ctx_a;

                                            // Pre-generate WebRTC SDP answer BEFORE spawning DTLS task.
                                            // The DTLS task holds the WebRtcSession lock for 15s+ during
                                            // handshake, which would block the 200 OK relay if we tried
                                            // to generate the SDP later.
                                            {
                                                let leg_a_port = self
                                                    .media
                                                    .get_session(&media_id)
                                                    .map(|s| s.ports.rtp)
                                                    .unwrap_or(10000);
                                                let sbc_ip = self
                                                    .identity
                                                    .as_ref()
                                                    .map(|id| id.public_ip.clone())
                                                    .unwrap_or_else(|| "127.0.0.1".to_string());
                                                let sess = ws.lock().await;
                                                let sdp_answer =
                                                    sess.generate_sdp_answer(leg_a_port, &sbc_ip);
                                                drop(sess);
                                                self.b2bua
                                                    .set_webrtc_sdp_answer(&uuid, sdp_answer)
                                                    .await;
                                            }

                                            info!("Spawning DTLS handshake task for call {} (media {})", uuid, media_id_dtls);

                                            tokio::spawn(async move {
                                                // Create the DTLS-UDP bridge
                                                let bridge = Arc::new(DtlsUdpBridge::new(
                                                    winfo.dtls_rx,
                                                    winfo.rtp_socket_a,
                                                    winfo.local_addr,
                                                ));

                                                // Perform the real DTLS handshake
                                                let sess = ws.lock().await;
                                                match sess
                                                    .dtls_context
                                                    .perform_handshake(bridge)
                                                    .await
                                                {
                                                    Ok(()) => {
                                                        info!("DTLS handshake complete for media session {}", media_id_dtls);

                                                        // Create SRTP contexts from DTLS keys
                                                        match sess
                                                            .dtls_context
                                                            .create_srtp_contexts()
                                                            .await
                                                        {
                                                            Ok((recv_ctx, send_ctx)) => {
                                                                // Hot-swap: inject SRTP contexts into the running relay task.
                                                                // recv_ctx: decrypts incoming SRTP from browser (client keys)
                                                                // send_ctx: encrypts outgoing RTP to browser (server keys)
                                                                *srtp_recv_shared.lock().await =
                                                                    Some(recv_ctx);
                                                                *srtp_send_shared.lock().await =
                                                                    Some(send_ctx);
                                                                info!("DTLS-SRTP hot-swap complete for media session {} — audio should flow", media_id_dtls);
                                                            }
                                                            Err(e) => {
                                                                error!("Failed to create SRTP contexts from DTLS keys: {}", e);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("DTLS handshake failed for media session {}: {}", media_id_dtls, e);
                                                    }
                                                }
                                            });
                                        }
                                    }

                                    // ── Spawn DTLS handshake if callee is WebRTC (leg-B) ──
                                    if let Some(winfo_b) = webrtc_info_b {
                                        let webrtc_session_b =
                                            self.b2bua.get_webrtc_session_b(&uuid).await;
                                        if let Some(ws_b) = webrtc_session_b {
                                            let media_id_dtls_b = media_id.clone();
                                            let srtp_recv_shared_b = winfo_b.srtp_recv_ctx_b;
                                            let srtp_send_shared_b = winfo_b.srtp_send_ctx_b;

                                            info!("Spawning DTLS handshake task for call {} leg-B (media {})", uuid, media_id_dtls_b);

                                            tokio::spawn(async move {
                                                let bridge = Arc::new(DtlsUdpBridge::new(
                                                    winfo_b.dtls_rx,
                                                    winfo_b.rtp_socket_b,
                                                    winfo_b.local_addr,
                                                ));

                                                let sess = ws_b.lock().await;
                                                match sess
                                                    .dtls_context
                                                    .perform_handshake(bridge)
                                                    .await
                                                {
                                                    Ok(()) => {
                                                        info!("DTLS handshake complete for leg-B media session {}", media_id_dtls_b);

                                                        match sess
                                                            .dtls_context
                                                            .create_srtp_contexts()
                                                            .await
                                                        {
                                                            Ok((recv_ctx, send_ctx)) => {
                                                                *srtp_recv_shared_b.lock().await =
                                                                    Some(recv_ctx);
                                                                *srtp_send_shared_b.lock().await =
                                                                    Some(send_ctx);
                                                                info!("DTLS-SRTP hot-swap complete for leg-B media session {} — audio should flow", media_id_dtls_b);
                                                            }
                                                            Err(e) => {
                                                                error!("Failed to create SRTP contexts from DTLS keys (leg-B): {}", e);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("DTLS handshake failed for leg-B media session {}: {}", media_id_dtls_b, e);
                                                    }
                                                }
                                            });
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to start RTP proxy for {}: {}", media_id, e)
                                }
                            }
                        }
                    }

                    info!("B2BUA: relaying 200 OK to caller");
                    if let Some((reply_tx, caller_addr, caller_transport)) = caller_info {
                        // Rewrite SDP in 200 OK body before relaying to caller:
                        // Replace callee's private IP+port with SBC's public IP + leg-B proxy port.
                        // Leg-B port is what the caller will send RTP to (callee side of the proxy).
                        let mut response_to_relay = response;

                        // ── Phase 13: Process callee WebRTC INDEPENDENTLY of caller type ──
                        // When callee is WebRTC, we MUST set_remote_sdp() on leg-B session
                        // regardless of whether the caller is also WebRTC. Previously this
                        // was inside an `else` branch and skipped for WebRTC→WebRTC calls.
                        let callee_is_webrtc = self.b2bua.is_callee_webrtc(&uuid).await;
                        if callee_is_webrtc && !response_to_relay.body.is_empty() {
                            if let Ok(callee_webrtc_sdp) =
                                std::str::from_utf8(&response_to_relay.body)
                            {
                                info!("200 OK from WebRTC callee — SDP:\n{}", callee_webrtc_sdp);

                                // Set remote SDP on the WebRTC session for leg-B (DTLS needs this)
                                let ws_b = self.b2bua.get_webrtc_session_b(&uuid).await;
                                if let Some(ws) = ws_b {
                                    let mut sess = ws.lock().await;
                                    sess.set_remote_sdp(callee_webrtc_sdp);
                                    drop(sess);
                                    info!("WebRTC session B: remote SDP set from callee 200 OK");
                                }
                            }
                        }

                        // ── Decide which SDP to send to the caller ──
                        let is_webrtc_call = self.b2bua.is_caller_webrtc(&uuid).await;

                        // Log both-WebRTC calls for Phase 13 debugging
                        if is_webrtc_call && callee_is_webrtc {
                            info!(
                                "WebRTC ↔ WebRTC call detected — Opus passthrough, dual DTLS-SRTP"
                            );
                        }

                        if is_webrtc_call {
                            // WebRTC caller: use the pre-generated SDP answer (Opus/SAVPF/DTLS/ICE)
                            // instead of relaying the callee's SDP directly.
                            // The SDP was pre-generated before the DTLS task was spawned to avoid
                            // deadlock (DTLS task holds the WebRtcSession lock during handshake).
                            let pre_sdp = self.b2bua.get_webrtc_sdp_answer(&uuid).await;
                            if let Some(webrtc_sdp) = pre_sdp {
                                info!("WebRTC SDP answer for browser:\n{}", webrtc_sdp);
                                response_to_relay.body = webrtc_sdp.into_bytes();
                                update_content_length_response(&mut response_to_relay);
                            } else {
                                warn!("WebRTC call {} but no pre-generated SDP answer — falling back to standard SDP rewrite", uuid);
                                // Fallback: standard SDP rewrite
                                if !response_to_relay.body.is_empty() {
                                    if let Ok(sdp_str) =
                                        std::str::from_utf8(&response_to_relay.body)
                                    {
                                        let media_id = self.b2bua.get_media_session_id(&uuid).await;
                                        let rewritten = if let Some(ref mid) = media_id {
                                            if let Some(session) = self.media.get_session(mid) {
                                                self.media.rewrite_sdp_for_proxy(
                                                    sdp_str,
                                                    session.ports.rtp,
                                                )
                                            } else {
                                                self.media.rewrite_sdp_ip(sdp_str)
                                            }
                                        } else {
                                            self.media.rewrite_sdp_ip(sdp_str)
                                        };
                                        response_to_relay.body = rewritten.into_bytes();
                                        update_content_length_response(&mut response_to_relay);
                                    }
                                }
                            }
                        } else if callee_is_webrtc && !response_to_relay.body.is_empty() {
                            // Caller is NOT WebRTC (PSTN/SIP), callee IS WebRTC:
                            // Transform WebRTC SDP → trunk PCMA/AVP for the non-WebRTC caller.
                            if let Ok(callee_webrtc_sdp) =
                                std::str::from_utf8(&response_to_relay.body)
                            {
                                let sbc_ip = self
                                    .identity
                                    .as_ref()
                                    .map(|id| id.public_ip.clone())
                                    .unwrap_or_else(|| "127.0.0.1".to_string());
                                let media_id = self.b2bua.get_media_session_id(&uuid).await;
                                let trunk_port = if let Some(ref mid) = media_id {
                                    self.media
                                        .get_session(mid)
                                        .map(|s| s.ports.rtp)
                                        .unwrap_or(10000)
                                } else {
                                    10000
                                };
                                let trunk_sdp = transform_webrtc_to_trunk(
                                    callee_webrtc_sdp,
                                    &sbc_ip,
                                    trunk_port,
                                );
                                info!(
                                    "WebRTC→Trunk 200 OK SDP transformation (port {}):\n{}",
                                    trunk_port, trunk_sdp
                                );
                                response_to_relay.body = trunk_sdp.into_bytes();
                                update_content_length_response(&mut response_to_relay);
                            }
                        } else if !response_to_relay.body.is_empty() {
                            // Standard SIP caller + standard SIP callee: rewrite SDP with SBC proxy IP+port
                            if let Ok(sdp_str) = std::str::from_utf8(&response_to_relay.body) {
                                let media_id = self.b2bua.get_media_session_id(&uuid).await;
                                let rewritten = if let Some(ref mid) = media_id {
                                    if let Some(session) = self.media.get_session(mid) {
                                        // Use leg-A port: caller sends RTP to leg-A, leg-A relays to callee.
                                        self.media.rewrite_sdp_for_proxy(sdp_str, session.ports.rtp)
                                    } else {
                                        self.media.rewrite_sdp_ip(sdp_str)
                                    }
                                } else {
                                    self.media.rewrite_sdp_ip(sdp_str)
                                };
                                if rewritten != sdp_str {
                                    info!("SDP 200 OK outbound (to caller):\n{}", rewritten);
                                } else {
                                    info!("SDP 200 OK outbound (unchanged):\n{}", rewritten);
                                }
                                self.b2bua
                                    .set_last_sdp_to_caller(&uuid, rewritten.clone())
                                    .await;
                                response_to_relay.body = rewritten.into_bytes();
                                // Update Content-Length to match new body size (critical for TCP framing)
                                update_content_length_response(&mut response_to_relay);
                            }
                        }
                        // ── CRITICAL: Restore caller's original Via headers ──────
                        // The 200 OK from the callee has the SBC's outbound Via.
                        // The caller will drop it because the branch doesn't match.
                        // We MUST replace the Via with the caller's original Via.
                        let caller_vias = self.b2bua.get_caller_vias(&uuid).await;
                        let raw = rsip::SipMessage::Response(response_to_relay).to_string();
                        let raw = rewrite_response_for_caller(
                            &raw,
                            &caller_vias,
                            self.identity.as_ref(),
                            caller_cseq,
                        );
                        self.send_sip(
                            "200 OK → caller",
                            raw.as_bytes(),
                            caller_addr,
                            caller_transport,
                            reply_tx.as_ref(),
                        )
                        .await;
                    }
                }
                407 => {
                    // ── Proxy Authentication Required from trunk ──────────────
                    // The trunk is challenging us for credentials. We need to:
                    // 1. Extract the Proxy-Authenticate challenge
                    // 2. Look up trunk credentials
                    // 3. Resend the INVITE with Proxy-Authorization
                    info!("B2BUA: received 407 Proxy Auth Required for call {}", uuid);

                    let retry_result = self.handle_407_auth_retry(&uuid, &response, source).await;

                    match retry_result {
                        Ok(true) => {
                            // Successfully resent INVITE with auth — wait for next response
                            info!(
                                "B2BUA: retrying INVITE with Proxy-Authorization for call {}",
                                uuid
                            );
                        }
                        Ok(false) | Err(_) => {
                            // Auth retry failed or exhausted — 503 to caller (don't leak trunk's 407)
                            warn!(
                                "B2BUA: 407 auth retry failed for call {}, relaying to caller",
                                uuid
                            );
                            // Same dialog identity as the 407 (From/To/Call-ID),
                            // status replaced, challenge stripped; Via/CSeq are
                            // restored for the caller by relay_error_and_terminate.
                            let response_503 = {
                                let raw = rsip::SipMessage::Response(response.clone()).to_string();
                                match crate::topology::RawSipMessage::parse(&raw) {
                                    Ok(mut m) => {
                                        m.start_line = "SIP/2.0 503 Service Unavailable".into();
                                        m.remove_header("proxy-authenticate");
                                        m.remove_header("www-authenticate");
                                        m.to_string()
                                    }
                                    Err(_) => build_plain_response(503, "Service Unavailable"),
                                }
                            };
                            self.relay_error_and_terminate(
                                &uuid,
                                response_503,
                                caller_info,
                                caller_cseq,
                            )
                            .await;
                        }
                    }
                }
                422 => {
                    // ── Session Interval Too Small (RFC 4028 §7.4) ────────────
                    // The trunk's Min-SE is above the Session-Expires WE offered
                    // on its leg: re-send the INVITE with its floor. The caller
                    // never offered the rejected value, so it only sees the 422
                    // when a retry is impossible (already retried, no Min-SE…).
                    info!(
                        "B2BUA: received 422 Session Interval Too Small for call {}",
                        uuid
                    );
                    match self
                        .handle_422_session_interval_retry(&uuid, &response, source)
                        .await
                    {
                        Ok(true) => {
                            info!(
                                "B2BUA: retrying INVITE with the trunk's Min-SE for call {}",
                                uuid
                            );
                        }
                        Ok(false) | Err(_) => {
                            info!("B2BUA: relaying 422 to caller, terminating call {}", uuid);
                            let raw = rsip::SipMessage::Response(response).to_string();
                            self.relay_error_and_terminate(&uuid, raw, caller_info, caller_cseq)
                                .await;
                        }
                    }
                }
                _ => {
                    // ── Trunk-level failures → active failover ──────────────
                    // 408/5xx/6xx from the trunk mean THIS trunk failed, not the
                    // call: try the next candidate before surfacing an error.
                    // Call-level rejections (486 Busy, 487, 404, 403…) are relayed.
                    let is_trunk_failure = status == 408 || (500..=699).contains(&status);
                    if is_trunk_failure {
                        if let Some(next) = self.b2bua.take_next_failover_candidate(&uuid).await {
                            // Push the candidate back and let the shared path handle it
                            warn!(
                                "B2BUA: trunk answered {} — failing over (call {})",
                                status, uuid
                            );
                            {
                                let mut calls = self.b2bua.calls_locked().await;
                                if let Some(fo) =
                                    calls.get_mut(&uuid).and_then(|c| c.failover.as_mut())
                                {
                                    fo.candidates.insert(0, next);
                                    fo.attempt = fo.attempt.saturating_sub(1);
                                }
                            }
                            if self.failover_to_next_trunk(&uuid).await {
                                return Ok(());
                            }
                            warn!(
                                "B2BUA: failover exhausted for call {} — relaying the {}",
                                uuid, status
                            );
                        }
                    }

                    // Error response (4xx/5xx/6xx) — relay to caller, terminate call
                    info!(
                        "B2BUA: relaying error {} to caller, terminating call",
                        status
                    );
                    let raw = rsip::SipMessage::Response(response).to_string();
                    self.relay_error_and_terminate(&uuid, raw, caller_info, caller_cseq)
                        .await;
                }
            }
        } else {
            // A final answer for a dialog we already tore down: typically the
            // 487 that follows the caller's CANCEL, or a 200 OK that crossed
            // that CANCEL on the wire. ACK it from the last attempt so the
            // peer stops retransmitting; a 2xx is also BYEd, otherwise the
            // trunk keeps a billed, answered ghost session. Sent back over the
            // connection the response arrived on (WS/TLS), else to the attempt's
            // destination (UDP).
            if let Some((cseq, method)) = response_cseq(&response) {
                if status >= 200 && method.eq_ignore_ascii_case("INVITE") {
                    if let Some(attempt) = self.b2bua.recent_attempt_for_call_id(&call_id) {
                        if attempt.cseq == cseq {
                            let to = response
                                .to_header()
                                .ok()
                                .map(|h| h.value().to_string())
                                .unwrap_or_default();
                            if status < 300 {
                                warn!(
                                    "{} for terminated call (Call-ID {}) — ACK + BYE → {}",
                                    status, call_id, attempt.dest
                                );
                                self.ack_and_bye_answered_dialog(
                                    &attempt,
                                    &response,
                                    cseq,
                                    &to,
                                    reply_tx,
                                    "Q.850;cause=31;text=\"Call already cancelled\"",
                                )
                                .await;
                                return Ok(());
                            }
                            if let Some(ack) =
                                crate::sip_builder::build_ack_for_non_2xx(&attempt.raw, &to)
                            {
                                debug!(
                                    "{} for terminated call (Call-ID {}) — ACK → {}",
                                    status, call_id, attempt.dest
                                );
                                self.send_sip(
                                    "ACK (after teardown) → callee",
                                    ack.as_bytes(),
                                    attempt.dest,
                                    attempt.transport,
                                    reply_tx,
                                )
                                .await;
                                return Ok(());
                            }
                        }
                    }
                }
            }
            info!(
                "No B2BUA call found for response Call-ID: {} from {} (stray response)",
                call_id, source
            );
        }

        Ok(())
    }

    /// SBC IP/port for synthetic requests (identity when configured).
    fn sbc_addr(&self) -> (String, u16) {
        self.identity
            .as_ref()
            .map(|id| (id.public_ip.clone(), id.sip_port))
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 5060))
    }

    /// ACK a 2xx that answered an INVITE nobody is waiting for any more
    /// (superseded attempt, or a dialog already torn down), then BYE the
    /// dialog it created (RFC 3261 §13.2.2.4 + §15): otherwise the peer
    /// retransmits the 2xx for 32 s and keeps an answered ghost session.
    async fn ack_and_bye_answered_dialog(
        &self,
        attempt: &crate::b2bua::InviteAttempt,
        response: &Response,
        cseq: u32,
        response_to: &str,
        tx: Option<&UnboundedSender<Vec<u8>>>,
        reason: &str,
    ) {
        let (sbc_ip, sbc_port) = self.sbc_addr();
        let from_raw = response
            .from_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();
        let call_id = response
            .call_id_header()
            .ok()
            .map(|h| h.value().to_string())
            .unwrap_or_default();
        let request_uri = response
            .contact_header()
            .ok()
            .map(|h| super::invite_handler_contact_uri(h.value()))
            .unwrap_or_else(|| format!("sip:{}", attempt.dest));
        let d = crate::sip_builder::DialogInfo {
            call_id,
            from_raw,
            to_raw: response_to.to_string(),
            request_uri,
            cseq,
            local_ip: sbc_ip,
            local_port: sbc_port,
            transport: crate::b2bua::transport_token(attempt.transport),
        };
        let ack = crate::sip_builder::build_ack_for_2xx(&d, cseq);
        let bye = crate::sip_builder::build_bye(
            &crate::sip_builder::DialogInfo {
                cseq: cseq + 1,
                ..d
            },
            Some(reason),
        );
        self.send_sip(
            "ACK (orphan 2xx) → callee",
            ack.as_bytes(),
            attempt.dest,
            attempt.transport,
            tx,
        )
        .await;
        self.send_sip(
            "BYE (orphan 2xx) → callee",
            bye.as_bytes(),
            attempt.dest,
            attempt.transport,
            tx,
        )
        .await;
    }

    /// The peer no longer has the dialog (481/408 to our refresh, or the
    /// refresh budget is exhausted): BYE the caller, write the CDR and
    /// release the call — a dead dialog must not be refreshed for hours.
    async fn teardown_lost_dialog(&mut self, uuid: &crate::b2bua::CallUuid, status: u16) {
        let (sbc_ip, sbc_port) = self.sbc_addr();
        if let Some(bye) = self
            .b2bua
            .build_relay_bye_toward_caller(
                uuid,
                &sbc_ip,
                sbc_port,
                CallOutcome::DialogLost { status }
                    .reason_header()
                    .as_deref(),
            )
            .await
        {
            if let Some((tx, addr, tp)) = self.b2bua.get_caller_reply_info(uuid).await {
                info!(
                    "Session refresh {}: dialog lost on the trunk — BYE → caller {} (call {})",
                    status, addr, uuid
                );
                self.send_sip(
                    "BYE (dialog lost) → caller",
                    bye.as_bytes(),
                    addr,
                    tp,
                    tx.as_ref(),
                )
                .await;
            }
        } else {
            warn!("Session refresh {}: dialog lost on the trunk, no caller dialog identity — releasing call {}", status, uuid);
        }

        self.finish_call(uuid, CallOutcome::DialogLost { status })
            .await;
    }

    /// Relay a final error to the caller (Vias + CSeq restored) and tear the
    /// call down. `terminate_call` releases the media session.
    pub(super) async fn relay_error_and_terminate(
        &mut self,
        uuid: &crate::b2bua::CallUuid,
        raw_response: String,
        caller_info: CallerReplyInfo,
        caller_cseq: Option<u32>,
    ) {
        let code = super::cdr::status_code_of(&raw_response).unwrap_or(500);
        if let Some((reply_tx, caller_addr, caller_transport)) = caller_info {
            let caller_vias = self.b2bua.get_caller_vias(uuid).await;
            let raw = rewrite_response_for_caller(
                &raw_response,
                &caller_vias,
                self.identity.as_ref(),
                caller_cseq,
            );
            self.send_sip(
                "error response → caller",
                raw.as_bytes(),
                caller_addr,
                caller_transport,
                reply_tx.as_ref(),
            )
            .await;
        }
        self.finish_call(uuid, CallOutcome::Rejected { code }).await;
    }

    /// ACK a non-2xx final of the live callee-leg INVITE (RFC 3261
    /// §17.1.1.3), sent where the INVITE went — clustered trunks answer
    /// from other IPs than the one we dialled.
    async fn ack_callee_final(&self, uuid: &crate::b2bua::CallUuid, response_to: &str) {
        let Some((attempt, tx)) = self.b2bua.current_attempt(uuid).await else {
            return;
        };
        let Some(ack) = crate::sip_builder::build_ack_for_non_2xx(&attempt.raw, response_to) else {
            warn!(
                "ACK (non-2xx): stored INVITE for call {} is not parseable — no ACK sent",
                uuid
            );
            return;
        };
        match self
            .transport
            .reply(ack.as_bytes(), attempt.dest, attempt.transport, tx.as_ref())
            .await
        {
            Ok(()) => debug!(
                "ACK (non-2xx) → {} for call {} (CSeq {})",
                attempt.dest, uuid, attempt.cseq
            ),
            Err(e) => warn!(
                "ACK (non-2xx) → {} failed for call {}: {}",
                attempt.dest, uuid, e
            ),
        }
    }

    /// Answer to one of OUR refresh re-INVITEs: never relayed to the caller.
    async fn handle_refresh_response(
        &mut self,
        uuid: &crate::b2bua::CallUuid,
        status: u16,
        cseq: u32,
        raw_resp: &str,
        response_to: &str,
    ) {
        match status {
            100..=199 => debug!("{} to session refresh (call {}) — ignored", status, uuid),
            200..=299 => {
                let (sbc_ip, sbc_port) = self.sbc_addr();
                if let Some((ack, dest, tp, tx)) = self
                    .b2bua
                    .complete_session_refresh(uuid, cseq, &sbc_ip, sbc_port)
                    .await
                {
                    info!(
                        "Session refresh 200 OK consumed (call {}) — sending ACK",
                        uuid
                    );
                    self.send_sip(
                        "ACK (refresh) → callee",
                        ack.as_bytes(),
                        dest,
                        tp,
                        tx.as_ref(),
                    )
                    .await;
                }
            }
            _ => {
                let min_se = (status == 422).then(|| parse_min_se(raw_resp)).flatten();
                let Some(outcome) = self
                    .b2bua
                    .fail_session_refresh(uuid, cseq, status, min_se, response_to)
                    .await
                else {
                    return;
                };
                match outcome.ack {
                    Some(ack) => {
                        self.send_sip(
                            "ACK (refresh rejected) → callee",
                            ack.as_bytes(),
                            outcome.dest,
                            outcome.transport,
                            outcome.reply_tx.as_ref(),
                        )
                        .await;
                    }
                    None => warn!(
                        "Session refresh {} for call {}: no stored re-INVITE — cannot ACK",
                        status, uuid
                    ),
                }
                if outcome.dialog_gone {
                    self.teardown_lost_dialog(uuid, status).await;
                }
            }
        }
    }

    /// Response for a superseded INVITE attempt (retransmitted 422/407, a
    /// 487 after the failover CANCEL, an answer from an abandoned trunk).
    /// Never relayed to the caller; ACKed (and BYEd for a 2xx) toward the
    /// attempt it belongs to.
    async fn handle_stale_invite_response(
        &self,
        uuid: &crate::b2bua::CallUuid,
        status: u16,
        cseq: u32,
        response: &Response,
        response_to: &str,
        attempt: Option<crate::b2bua::InviteAttempt>,
    ) {
        let Some(attempt) = attempt else {
            debug!(
                "{} for a superseded INVITE of call {} (CSeq {}) — no attempt record, dropped",
                status, uuid, cseq
            );
            return;
        };
        // Reuse the live connection only when the stale attempt went to the
        // same peer (retry); a failed-over trunk gets a fresh send.
        let tx = match self.b2bua.current_attempt(uuid).await {
            Some((cur, tx)) if cur.dest == attempt.dest => tx,
            _ => None,
        };
        match status {
            100..=199 => debug!(
                "{} for superseded INVITE (call {}, CSeq {}) — dropped",
                status, uuid, cseq
            ),
            200..=299 => {
                // Glare: an attempt we abandoned was answered. Honour the
                // dialog (ACK) and end it (BYE) — the caller is on another leg.
                warn!(
                    "{} for superseded INVITE (call {}, CSeq {}) — ACK + BYE → {}",
                    status, uuid, cseq, attempt.dest
                );
                self.ack_and_bye_answered_dialog(
                    &attempt,
                    response,
                    cseq,
                    response_to,
                    tx.as_ref(),
                    "Q.850;cause=31;text=\"Superseded INVITE answered\"",
                )
                .await;
            }
            _ => {
                if let Some(ack) =
                    crate::sip_builder::build_ack_for_non_2xx(&attempt.raw, response_to)
                {
                    debug!(
                        "{} for superseded INVITE (call {}, CSeq {}) — ACK → {}, dropped",
                        status, uuid, cseq, attempt.dest
                    );
                    self.send_sip(
                        "ACK (stale) → callee",
                        ack.as_bytes(),
                        attempt.dest,
                        attempt.transport,
                        tx.as_ref(),
                    )
                    .await;
                }
            }
        }
    }
}

/// CSeq number and method of a response.
fn response_cseq(response: &Response) -> Option<(u32, String)> {
    let raw = response
        .headers
        .iter()
        .map(|h| h.to_string())
        .find(|h| h.to_lowercase().starts_with("cseq:"))?;
    let value = raw.split_once(':')?.1.trim();
    let mut parts = value.split_whitespace();
    let num = parts.next()?.parse().ok()?;
    let method = parts.next()?.to_string();
    Some((num, method))
}

/// Integer value of the first header among `names` (lowercase, with
/// trailing colon): `Session-Expires: 1800;refresher=uac` → 1800. None when
/// that header's value up to the first `;` is not a u32 (later duplicates
/// are not consulted — a malformed 422 is relayed, not guessed at).
fn header_u32(raw: &str, names: &[&str]) -> Option<u32> {
    for line in raw.split("\r\n") {
        if line.is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if names.iter().any(|n| lower.starts_with(n)) {
            let value = line.split_once(':')?.1.trim();
            let secs = value.split(';').next()?.trim();
            return secs.parse().ok();
        }
    }
    None
}

/// Parse `Session-Expires: 1800;refresher=uac` (long or compact `x:` form).
pub(crate) fn parse_session_expires(raw: &str) -> Option<u32> {
    header_u32(raw, &["session-expires:", "x:"])
}

/// Parse `Min-SE: 14400` (RFC 4028; no compact form).
pub(crate) fn parse_min_se(raw: &str) -> Option<u32> {
    header_u32(raw, &["min-se:"])
}

#[cfg(test)]
mod session_timer_tests {
    #[test]
    fn parse_session_expires_forms() {
        let raw = "SIP/2.0 200 OK\r\nSession-Expires: 14400;refresher=uac\r\n\r\n";
        assert_eq!(super::parse_session_expires(raw), Some(14400));
        let bare = "SIP/2.0 200 OK\r\nSession-Expires: 1800\r\n\r\n";
        assert_eq!(super::parse_session_expires(bare), Some(1800));
        let none = "SIP/2.0 200 OK\r\nContact: <sip:x@y>\r\n\r\n";
        assert_eq!(super::parse_session_expires(none), None);
        let compact = "INVITE sip:x SIP/2.0\r\nx: 600\r\n\r\n";
        assert_eq!(super::parse_session_expires(compact), Some(600));
        let in_body_only = "SIP/2.0 200 OK\r\n\r\nSession-Expires: 5\r\n";
        assert_eq!(
            super::parse_session_expires(in_body_only),
            None,
            "headers end at the blank line"
        );
    }

    #[test]
    fn parse_min_se_forms() {
        assert_eq!(
            super::parse_min_se("SIP/2.0 422 Session Interval Too Small\r\nMin-SE: 14400\r\n\r\n"),
            Some(14400)
        );
        assert_eq!(
            super::parse_min_se("SIP/2.0 422 x\r\nmin-se:  90;foo=bar\r\n\r\n"),
            Some(90)
        );
        assert_eq!(
            super::parse_min_se("SIP/2.0 422 x\r\nMin-SE: abc\r\n\r\n"),
            None
        );
        assert_eq!(
            super::parse_min_se("SIP/2.0 422 x\r\nMin-Expires: 3600\r\n\r\n"),
            None,
            "Min-Expires is not Min-SE"
        );
        assert_eq!(super::parse_min_se("SIP/2.0 422 x\r\n\r\n"), None);
    }

    #[test]
    fn response_cseq_number_and_method() {
        let raw = "SIP/2.0 481 Call/Transaction Does Not Exist\r\nCSeq: 3 CANCEL\r\nContent-Length: 0\r\n\r\n";
        let resp = match rsip::SipMessage::try_from(raw.as_bytes().to_vec()).unwrap() {
            rsip::SipMessage::Response(r) => r,
            _ => panic!(),
        };
        assert_eq!(super::response_cseq(&resp), Some((3, "CANCEL".to_string())));
    }
}

/// Transaction-level tests: drive `handle_response` on an `Sbc` whose caller
/// and callee legs are mpsc channels, so every ACK/CANCEL/BYE/INVITE the SBC
/// emits is observable without sockets.
#[cfg(test)]
mod transaction_tests {
    use super::super::test_support::*;
    use super::*;
    use std::sync::atomic::Ordering;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

    #[tokio::test]
    async fn current_final_is_acked_relayed_with_caller_cseq_and_terminates() {
        let (mut sbc, _uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;
        assert!(
            sbc.media.stats().allocated_ports > 0,
            "the call holds an RTP port pair"
        );

        sbc.handle_response(
            response("487 Request Terminated", "z9hG4bKaaa", 3, "INVITE", ""),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();

        let to_trunk = drain(&mut callee_rx);
        assert_eq!(
            to_trunk.len(),
            1,
            "exactly one ACK toward the trunk: {:?}",
            to_trunk
        );
        assert!(to_trunk[0].starts_with("ACK sip:bob@203.0.113.9:5060 SIP/2.0\r\n"));
        assert!(
            to_trunk[0].contains("branch=z9hG4bKaaa"),
            "ACK reuses the INVITE branch"
        );
        assert!(to_trunk[0].contains("CSeq: 3 ACK\r\n"));
        assert!(
            to_trunk[0].contains("To: <sip:bob@b.example.com>;tag=trunk-1\r\n"),
            "To copied from the response"
        );

        let to_caller = drain(&mut caller_rx);
        assert_eq!(to_caller.len(), 1);
        assert!(to_caller[0].starts_with("SIP/2.0 487"), "{}", to_caller[0]);
        assert!(
            to_caller[0].contains("branch=z9hG4bKcaller"),
            "caller's own Via restored"
        );
        assert!(to_caller[0].contains("CSeq: 3 INVITE\r\n"));

        assert!(!alive(&sbc).await);
        assert_eq!(
            sbc.media.stats().allocated_ports,
            0,
            "media released on error relay"
        );
    }

    #[tokio::test]
    async fn retransmitted_422_is_acked_and_dropped_then_budget_exhausted_relays() {
        let (mut sbc, uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;

        // 1. Genesys: 422 Min-SE 14400 → ACK + INVITE re-sent with the floor
        sbc.handle_response(
            response(
                "422 Session Interval Too Small",
                "z9hG4bKaaa",
                3,
                "INVITE",
                "Min-SE: 14400\r\n",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let to_trunk = drain(&mut callee_rx);
        assert_eq!(
            to_trunk.len(),
            2,
            "ACK then the retried INVITE: {:?}",
            to_trunk
        );
        assert!(to_trunk[0].starts_with("ACK "));
        assert!(to_trunk[0].contains("CSeq: 3 ACK\r\n"));
        assert!(to_trunk[0].contains("branch=z9hG4bKaaa"));
        let retry = &to_trunk[1];
        assert!(
            retry.starts_with("INVITE sip:bob@203.0.113.9:5060 SIP/2.0\r\n"),
            "{}",
            retry
        );
        assert!(retry.contains("CSeq: 4 INVITE\r\n"));
        assert!(!retry.contains("z9hG4bKaaa"), "new transaction, new branch");
        assert_eq!(retry.matches("Session-Expires:").count(), 1);
        assert_eq!(retry.matches("Min-SE:").count(), 1);
        assert!(
            retry.contains("Session-Expires: 14400\r\nMin-SE: 14400\r\n"),
            "{}",
            retry
        );
        assert_eq!(retry.matches("Supported: timer").count(), 1);
        assert!(retry.ends_with(SDP), "body intact");
        assert!(
            drain(&mut caller_rx).is_empty(),
            "the caller never sees the 422"
        );
        assert!(alive(&sbc).await);
        assert_eq!(sbc.b2bua.get_session_timer_retry_count(&uuid).await, 1);
        assert_eq!(
            sbc.metrics
                .session_timer_422_retries_total
                .load(Ordering::Relaxed),
            1
        );
        let (attempt, _) = sbc.b2bua.current_attempt(&uuid).await.unwrap();
        assert_eq!(attempt.cseq, 4);
        let retry_branch = attempt.branch.clone().expect("retry branch recorded");
        assert!(retry.contains(&retry_branch));

        // 2. UDP retransmission of the first 422 (our ACK got lost): ACK only
        sbc.handle_response(
            response(
                "422 Session Interval Too Small",
                "z9hG4bKaaa",
                3,
                "INVITE",
                "Min-SE: 14400\r\n",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let dup = drain(&mut callee_rx);
        assert_eq!(dup.len(), 1, "{:?}", dup);
        assert!(
            dup[0].starts_with("ACK ")
                && dup[0].contains("branch=z9hG4bKaaa")
                && dup[0].contains("CSeq: 3 ACK")
        );
        assert!(drain(&mut caller_rx).is_empty());
        assert!(alive(&sbc).await);
        assert_eq!(
            sbc.b2bua.get_session_timer_retry_count(&uuid).await,
            1,
            "no second retry"
        );

        // 3. The trunk raises its floor again on the retried INVITE: budget is
        //    one per attempt → ACK, relay the 422 with the caller's CSeq, tear down
        sbc.handle_response(
            response(
                "422 Session Interval Too Small",
                &retry_branch,
                4,
                "INVITE",
                "Min-SE: 20000\r\n",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let last = drain(&mut callee_rx);
        assert_eq!(last.len(), 1, "ACK only, no third INVITE: {:?}", last);
        assert!(
            last[0].starts_with("ACK ")
                && last[0].contains("CSeq: 4 ACK")
                && last[0].contains(&retry_branch)
        );
        let to_caller = drain(&mut caller_rx);
        assert_eq!(to_caller.len(), 1);
        assert!(to_caller[0].starts_with("SIP/2.0 422"), "{}", to_caller[0]);
        assert!(
            to_caller[0].contains("CSeq: 3 INVITE\r\n"),
            "caller's CSeq restored: {}",
            to_caller[0]
        );
        assert!(to_caller[0].contains("Min-SE: 20000"), "diagnostics kept");
        assert!(!alive(&sbc).await);
        assert_eq!(
            sbc.metrics
                .session_timer_422_retries_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn no_retry_when_timers_are_off_or_min_se_missing() {
        // Timers off: the caller's own offer was rejected → relay
        let (mut sbc, _uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;
        sbc.session_timer = None;
        sbc.handle_response(
            response(
                "422 Session Interval Too Small",
                "z9hG4bKaaa",
                3,
                "INVITE",
                "Min-SE: 14400\r\n",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let to_trunk = drain(&mut callee_rx);
        assert_eq!(to_trunk.len(), 1, "ACK only: {:?}", to_trunk);
        assert!(to_trunk[0].starts_with("ACK "));
        assert!(drain(&mut caller_rx)[0].starts_with("SIP/2.0 422"));
        assert!(!alive(&sbc).await);

        // 422 without Min-SE (RFC 4028 §6 violation): nothing to retry with → relay
        let (mut sbc, _uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;
        sbc.handle_response(
            response(
                "422 Session Interval Too Small",
                "z9hG4bKaaa",
                3,
                "INVITE",
                "",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        assert_eq!(drain(&mut callee_rx).len(), 1, "ACK only");
        assert!(drain(&mut caller_rx)[0].starts_with("SIP/2.0 422"));
        assert!(!alive(&sbc).await);
    }

    #[tokio::test]
    async fn stale_2xx_is_acked_and_byed_caller_untouched() {
        let (mut sbc, uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;
        // A 407 retry superseded the first attempt (same trunk, CSeq 4)
        sbc.b2bua
            .push_invite_attempt(
                &uuid,
                invite("z9hG4bKbbb", 4),
                trunk_addr(),
                rsip::Transport::Udp,
                None,
            )
            .await;

        // Late 200 OK for the FIRST attempt (glare)
        sbc.handle_response(
            response(
                "200 OK",
                "z9hG4bKaaa",
                3,
                "INVITE",
                "Contact: <sip:bob@203.0.113.9:5060>\r\n",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();

        let to_trunk = drain(&mut callee_rx);
        assert_eq!(to_trunk.len(), 2, "ACK then BYE: {:?}", to_trunk);
        assert!(
            to_trunk[0].starts_with("ACK sip:bob@203.0.113.9:5060 SIP/2.0\r\n"),
            "{}",
            to_trunk[0]
        );
        assert!(to_trunk[0].contains("CSeq: 3 ACK\r\n"));
        assert!(
            to_trunk[1].starts_with("BYE sip:bob@203.0.113.9:5060 SIP/2.0\r\n"),
            "{}",
            to_trunk[1]
        );
        assert!(
            to_trunk[1].contains("CSeq: 4 BYE\r\n"),
            "BYE CSeq above the ACK's"
        );
        assert!(to_trunk[1].contains("From: <sip:alice@a.example.com>;tag=al-1\r\n"));
        assert!(to_trunk[1].contains("To: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
        assert!(to_trunk[1].contains("Reason: Q.850;cause=31"));
        assert!(
            drain(&mut caller_rx).is_empty(),
            "never relayed to the caller"
        );
        assert!(alive(&sbc).await, "the live attempt is untouched");
        let calls = sbc.b2bua.calls_locked().await;
        assert_ne!(calls[&uuid].state, crate::b2bua::CallState::Connected);
    }

    #[tokio::test]
    async fn responses_to_our_cancel_or_bye_are_dropped() {
        let (mut sbc, _uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;
        sbc.handle_response(
            response(
                "481 Call/Transaction Does Not Exist",
                "z9hG4bKaaa",
                3,
                "CANCEL",
                "",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        sbc.handle_response(
            response("200 OK", "z9hG4bKbye", 4, "BYE", ""),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        assert!(drain(&mut callee_rx).is_empty());
        assert!(drain(&mut caller_rx).is_empty());
        assert!(alive(&sbc).await);
    }

    /// Bring the call to Connected with an armed session timer and force a
    /// refresh re-INVITE out; returns (its CSeq, its Via branch).
    async fn arm_and_refresh(
        sbc: &Sbc,
        uuid: &crate::b2bua::CallUuid,
        callee_rx: &mut UnboundedReceiver<Vec<u8>>,
    ) -> (u32, String) {
        sbc.b2bua
            .set_established_dialog(
                uuid,
                "<sip:alice@a.example.com>;tag=al-1".into(),
                "<sip:bob@b.example.com>;tag=trunk-1".into(),
                Some("sip:bob@203.0.113.9:5060".into()),
            )
            .await;
        {
            let mut calls = sbc.b2bua.calls_locked().await;
            calls.get_mut(uuid).unwrap().state = crate::b2bua::CallState::Connected;
        }
        if sbc.b2bua.calls_locked().await[uuid].session_timer.is_none() {
            sbc.b2bua.set_session_timer(uuid, 1800, 90).await;
        }
        {
            let mut calls = sbc.b2bua.calls_locked().await;
            let st = calls.get_mut(uuid).unwrap().session_timer.as_mut().unwrap();
            st.next_refresh_at = std::time::Instant::now() - Duration::from_secs(1);
            st.pending_refresh_cseq = None;
        }
        let due = sbc.b2bua.due_session_refreshes("127.0.0.1", 5060).await;
        assert_eq!(due.len(), 1);
        let reinvite = due[0].1.clone();
        // (due_session_refreshes only builds; the tick would send it — not needed here)
        let _ = drain(callee_rx);
        (
            crate::b2bua::parse_cseq_number(&reinvite).unwrap(),
            crate::sip_builder::top_via_branch(&reinvite).unwrap(),
        )
    }

    #[tokio::test]
    async fn refresh_rejections_keep_the_session_until_the_dialog_is_gone() {
        let (mut sbc, uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;
        let (cseq, branch) = arm_and_refresh(&sbc, &uuid, &mut callee_rx).await;
        assert_eq!(cseq, 4, "refresh CSeq follows the stored INVITE");

        // 500 to the refresh: ACK, session kept, caller untouched
        sbc.handle_response(
            response("500 Server Internal Error", &branch, cseq, "INVITE", ""),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let out = drain(&mut callee_rx);
        assert_eq!(out.len(), 1, "{:?}", out);
        assert!(
            out[0].starts_with("ACK ")
                && out[0].contains(&format!("CSeq: {} ACK", cseq))
                && out[0].contains(&branch)
        );
        assert!(drain(&mut caller_rx).is_empty());
        assert!(alive(&sbc).await);

        // The same 500 retransmitted (branch unknown to the attempts, CSeq above
        // the live INVITE): re-ACKed, NOT treated as the INVITE's final
        sbc.handle_response(
            response("500 Server Internal Error", &branch, cseq, "INVITE", ""),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let out = drain(&mut callee_rx);
        assert_eq!(out.len(), 1, "{:?}", out);
        assert!(out[0].starts_with("ACK "));
        assert!(
            drain(&mut caller_rx).is_empty(),
            "no error relayed mid-call"
        );
        assert!(
            alive(&sbc).await,
            "the established call survives a duplicate answer"
        );

        // Next refresh gets 481: the trunk lost the dialog → ACK, BYE the caller, release
        let (cseq2, branch2) = arm_and_refresh(&sbc, &uuid, &mut callee_rx).await;
        assert!(cseq2 > cseq);
        sbc.handle_response(
            response(
                "481 Call/Transaction Does Not Exist",
                &branch2,
                cseq2,
                "INVITE",
                "",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let out = drain(&mut callee_rx);
        assert_eq!(out.len(), 1, "ACK toward the trunk: {:?}", out);
        assert!(out[0].starts_with("ACK ") && out[0].contains(&format!("CSeq: {} ACK", cseq2)));
        let to_caller = drain(&mut caller_rx);
        assert_eq!(to_caller.len(), 1, "BYE toward the caller: {:?}", to_caller);
        assert!(
            to_caller[0].starts_with("BYE sip:alice@10.0.0.9:5060 SIP/2.0\r\n"),
            "{}",
            to_caller[0]
        );
        assert!(to_caller[0].contains("From: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
        assert!(to_caller[0].contains("To: <sip:alice@a.example.com>;tag=al-1\r\n"));
        assert!(!alive(&sbc).await);
        assert_eq!(sbc.media.stats().allocated_ports, 0);
    }

    #[tokio::test]
    async fn refresh_491_retries_soon_and_405_disables_the_timer_but_keeps_the_call() {
        let (mut sbc, uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;
        let (cseq, branch) = arm_and_refresh(&sbc, &uuid, &mut callee_rx).await;

        // 491 Request Pending: glare, not a failure — ACK, retry shortly
        sbc.handle_response(
            response("491 Request Pending", &branch, cseq, "INVITE", ""),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let out = drain(&mut callee_rx);
        assert_eq!(out.len(), 1, "{:?}", out);
        assert!(out[0].starts_with("ACK ") && out[0].contains(&format!("CSeq: {} ACK", cseq)));
        {
            let calls = sbc.b2bua.calls_locked().await;
            let st = calls[&uuid].session_timer.as_ref().expect("timer kept");
            assert_eq!(st.refresh_failures, 0, "491 is not a strike");
            let wait = st
                .next_refresh_at
                .saturating_duration_since(std::time::Instant::now());
            assert!(
                wait >= Duration::from_secs(2) && wait <= Duration::from_secs(4),
                "retry in 2.1–4 s, got {:?}",
                wait
            );
        }
        assert!(drain(&mut caller_rx).is_empty());
        assert!(alive(&sbc).await);

        // 405 to the next refresh: the peer never refreshes by re-INVITE —
        // timer off for this call, call kept.
        let (cseq2, branch2) = arm_and_refresh(&sbc, &uuid, &mut callee_rx).await;
        sbc.handle_response(
            response("405 Method Not Allowed", &branch2, cseq2, "INVITE", ""),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        let out = drain(&mut callee_rx);
        assert_eq!(out.len(), 1, "ACK only: {:?}", out);
        assert!(out[0].starts_with("ACK "));
        assert!(drain(&mut caller_rx).is_empty(), "no BYE to the caller");
        assert!(alive(&sbc).await, "the call survives");
        assert!(
            sbc.b2bua.calls_locked().await[&uuid]
                .session_timer
                .is_none(),
            "no further refresh for this call"
        );
        assert!(
            sbc.b2bua
                .due_session_refreshes("127.0.0.1", 5060)
                .await
                .is_empty(),
            "nothing is due any more"
        );
    }

    #[tokio::test]
    async fn stray_final_after_teardown_is_acked_and_a_2xx_is_byed() {
        let (mut sbc, uuid, mut caller_rx, mut callee_rx) = sbc_with_call().await;
        // Caller cancelled: the call is gone, its last attempt remembered
        sbc.b2bua.terminate_call(&uuid).await;
        assert!(!alive(&sbc).await);
        let (stray_tx, mut stray_rx) = unbounded_channel();

        // 487 that follows the CANCEL: ACK back over the connection it arrived on
        sbc.handle_response(
            response("487 Request Terminated", "z9hG4bKaaa", 3, "INVITE", ""),
            trunk_addr(),
            rsip::Transport::Udp,
            Some(&stray_tx),
        )
        .await
        .unwrap();
        let out = drain(&mut stray_rx);
        assert_eq!(out.len(), 1, "{:?}", out);
        assert!(
            out[0].starts_with("ACK ")
                && out[0].contains("CSeq: 3 ACK")
                && out[0].contains("branch=z9hG4bKaaa")
        );

        // 200 OK that crossed the CANCEL on the wire: ACK + BYE, no ghost session
        sbc.handle_response(
            response(
                "200 OK",
                "z9hG4bKaaa",
                3,
                "INVITE",
                "Contact: <sip:bob@203.0.113.9:5060>\r\n",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            Some(&stray_tx),
        )
        .await
        .unwrap();
        let out = drain(&mut stray_rx);
        assert_eq!(out.len(), 2, "ACK then BYE: {:?}", out);
        assert!(
            out[0].starts_with("ACK sip:bob@203.0.113.9:5060 SIP/2.0\r\n")
                && out[0].contains("CSeq: 3 ACK")
        );
        assert!(
            out[1].starts_with("BYE sip:bob@203.0.113.9:5060 SIP/2.0\r\n")
                && out[1].contains("CSeq: 4 BYE")
        );
        assert!(out[1].contains("Reason: Q.850;cause=31"));

        assert!(drain(&mut caller_rx).is_empty());
        assert!(
            drain(&mut callee_rx).is_empty(),
            "nothing on the old callee channel"
        );
    }
}
