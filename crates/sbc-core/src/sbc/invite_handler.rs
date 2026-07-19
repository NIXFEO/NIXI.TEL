use super::*;

impl Sbc {
    /// Handle INVITE — B2BUA leg setup + routing + topology hiding
    pub(super) async fn handle_invite(
        &mut self,
        mut request: Request,
        source: SocketAddr,
        transport: rsip::Transport,
        reply_tx: Option<&UnboundedSender<Vec<u8>>>,
    ) -> Result<()> {
        info!("Received INVITE from {}", source);

        // ── In-dialog re-INVITE (RFC 4028 session refresh)? ─────────────
        // A To-tag + a known Call-ID means an existing dialog: answer with
        // unchanged SDP instead of treating it as a new call.
        let to_has_tag = request.to_header().ok()
            .and_then(|h| h.typed().ok())
            .map(|to: rsip::typed::To| to.params.iter().any(|p| matches!(p, rsip::Param::Tag(_))))
            .unwrap_or(false);
        if to_has_tag {
            if let Ok(cid_header) = request.call_id_header() {
                let cid = cid_header.value().to_string();
                if let Some((uuid, is_from_caller)) =
                    self.b2bua.find_by_any_call_id_with_source(&cid, Some(source)).await
                {
                    return self
                        .handle_reinvite(&uuid, is_from_caller, request, source, transport, reply_tx)
                        .await;
                }
            }
        }

        // ── Anti-spam: reject INVITE from unregistered/unknown sources ──
        // Allow if any of:
        //   (1) source IP matches a registered user's received_ip
        //   (2) source is localhost (trunk)
        //   (3) From URI user matches a registered AOR (user calling from proxy/TLS)
        //   (4) callee is registered (incoming call from trunk for our user)
        //   (5) source IP is a known trunk IP (whitelisted)
        let source_ip = source.ip().to_string();
        let is_localhost = source_ip == "127.0.0.1" || source_ip == "::1";
        let is_trunk_ip = self.trunk_ips.read().await.iter().any(|ip| ip == &source_ip);
        if is_trunk_ip {
            info!("INVITE from trunk IP {} — whitelisted", source_ip);
        }
        if !is_localhost && !is_trunk_ip {
            let all_regs = self.register_handler.all_registrations().await.unwrap_or_default();
            let ip_known = all_regs.iter().any(|r| r.received_ip == source_ip);

            // Also check From user against registered AORs
            let from_user_known = request.from_header().ok()
                .and_then(|h| h.typed().ok())
                .map(|from: rsip::typed::From| {
                    let from_uri = from.uri.to_string();
                    all_regs.iter().any(|r| r.aor == from_uri)
                })
                .unwrap_or(false);

            // Also check if the To URI is one of our registered users (incoming call)
            let to_user_known = request.to_header().ok()
                .and_then(|h| h.typed().ok())
                .map(|to: rsip::typed::To| {
                    let to_uri = to.uri.to_string();
                    all_regs.iter().any(|r| r.aor == to_uri)
                })
                .unwrap_or(false);

            if !ip_known && !from_user_known && !to_user_known {
                warn!("INVITE rejected from unregistered source {} (IP/From/To all unknown)", source);
                self.metrics.inc_spam_blocked();
                // Scanner INVITE floods count toward the fail2ban window
                if let Some(entry) = self.security.record_auth_failure(source.ip(), None, "INVITE") {
                    self.metrics.inc_security_ban();
                    self.persist_ban(&entry);
                }
                self.metrics.inc_sip_response(403);
                let response_403 = build_plain_response_for_request(&request, 403, "Forbidden")?;
                let data = response_403.to_string().into_bytes();
                return self.transport.reply(&data, source, transport, reply_tx).await;
            }
        }

        // ── Per-user call limits (concurrent + setup rate) ──────────────
        // Identity: registration matched by source IP, else From user.
        // Trunk/localhost sources are exempt (inbound PSTN calls).
        if !is_localhost && !is_trunk_ip {
            let caller_user = {
                let regs = self.register_handler.all_registrations().await.unwrap_or_default();
                regs.iter()
                    .find(|r| r.received_ip == source_ip)
                    .and_then(|r| r.aor.strip_prefix("sip:").and_then(|a| a.split('@').next()))
                    .map(str::to_string)
                    .or_else(|| {
                        request.from_header().ok()
                            .and_then(|h| h.typed().ok())
                            .and_then(|f: rsip::typed::From| f.uri.user().map(str::to_string))
                    })
            };
            if let Some(user) = caller_user {
                let concurrent = self.b2bua.active_calls_for_user(&user).await;
                match self.security.user_limits.check_and_record(&user, concurrent) {
                    crate::security::LimitDecision::Allowed => {}
                    crate::security::LimitDecision::ConcurrentExceeded { current, limit } => {
                        warn!(target: "security", "User '{}' concurrent limit: {}/{}", user, current, limit);
                        self.security.emit(crate::security::SecurityEvent::UserLimitHit {
                            user: user.clone(), kind: "concurrent".into(), current, limit,
                            ts: crate::events::event_ts(),
                        });
                        self.metrics.inc_security_user_limit_rejection();
                        self.metrics.inc_sip_response(403);
                        let r = build_plain_response_for_request(&request, 403, "Too Many Concurrent Calls")?;
                        let data = r.to_string().into_bytes();
                        return self.transport.reply(&data, source, transport, reply_tx).await;
                    }
                    crate::security::LimitDecision::RateExceeded { current, limit, retry_after_secs } => {
                        warn!(target: "security", "User '{}' rate limit: {}/{} per min", user, current, limit);
                        self.security.emit(crate::security::SecurityEvent::UserLimitHit {
                            user: user.clone(), kind: "rate".into(), current, limit,
                            ts: crate::events::event_ts(),
                        });
                        self.metrics.inc_security_user_limit_rejection();
                        self.metrics.inc_sip_response(503);
                        // 503 + Retry-After (RFC 3261-conformant throttle)
                        let raw = format!(
                            "SIP/2.0 503 Service Unavailable\r\nRetry-After: {}\r\nContent-Length: 0\r\n\r\n",
                            retry_after_secs
                        );
                        let r = build_plain_response_for_request(&request, 503, "Service Unavailable")?;
                        let with_retry = r.to_string().replace(
                            "\r\nContent-Length:",
                            &format!("\r\nRetry-After: {}\r\nContent-Length:", retry_after_secs),
                        );
                        let _ = raw; // keep formatting simple: send the header-injected variant
                        return self.transport.reply(with_retry.as_bytes(), source, transport, reply_tx).await;
                    }
                }
            }
        }

        // ── Metrics: call attempted ──
        self.metrics.inc_call_attempted();

        // Create server transaction
        let tx_id = self.transactions.create_server_transaction(request.clone(), transport, source)?;
        debug!("Created server transaction: {:?}", tx_id);

        // Extract Call-ID and caller tag
        let call_id = request.call_id_header()
            .map_err(|e| Error::Other(format!("Missing Call-ID: {}", e)))?
            .value()
            .to_string();

        let caller_tag = request.from_header()
            .ok()
            .and_then(|h| h.typed().ok())
            .and_then(|from: rsip::typed::From| {
                from.params.iter().find_map(|p| {
                    if let rsip::Param::Tag(t) = p { Some(t.value().to_string()) } else { None }
                })
            })
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()[..8].to_string());

        // Extract SDP body
        let caller_sdp: Option<String> = if !request.body.is_empty() {
            std::str::from_utf8(&request.body).ok().map(|s| s.to_string())
        } else {
            None
        };

        // Send 100 Trying immediately (RFC 3261 §8.2.6.1)
        if let Ok(trying) = build_trying(&request) {
            self.metrics.inc_sip_response(100);
            let data = trying.to_string().into_bytes();
            let _ = self.transport.reply(&data, source, transport, reply_tx).await;
            debug!("Sent 100 Trying to {}", source);
        }

        // Create B2BUA call (allocates media ports, tracks call state)
        // Pass the reply_tx so later provisional/final responses can reach the caller
        let uuid = match self.b2bua.create_call(
            call_id.clone(),
            caller_tag,
            source,
            caller_sdp.as_deref(),
            reply_tx.cloned(),
            transport,
        ).await {
            Ok(uuid) => uuid,
            Err(e) => {
                warn!("B2BUA create_call failed: {}", e);
                self.metrics.inc_sip_response(500);
                let response_500 = build_plain_response(500, "Server Internal Error");
                let _ = self.transport.reply(response_500.as_bytes(), source, transport, reply_tx).await;
                return Ok(());
            }
        };

        // ── Capture caller-side dialog identity (raw From + Contact) ──
        // Needed to build synthetic in-dialog requests (BYE on timeout/
        // shutdown) that the caller accepts instead of answering 481.
        {
            let from_raw = request.from_header().ok().map(|h| h.value().to_string());
            let caller_contact = request
                .contact_header()
                .ok()
                .map(|h| extract_contact_uri(h.value()));
            if let Some(from_raw) = from_raw {
                self.b2bua
                    .set_inbound_dialog(&uuid, from_raw, caller_contact)
                    .await;
            }
        }

        // ── Metrics: update active WebRTC calls gauge ──
        {
            let stats = self.b2bua.stats().await;
            self.metrics.set_active_webrtc(stats.webrtc_calls as u64);
        }

        // ── WebRTC session: create ICE/DTLS/SRTP session if caller is WebRTC ──
        let caller_is_webrtc = self.b2bua.is_caller_webrtc(&uuid).await;
        if caller_is_webrtc {
            if let Some(ref sdp) = caller_sdp {
                match WebRtcSession::new(call_id.clone(), sdp) {
                    Ok(session) => {
                        // Extract local ICE credentials for STUN MESSAGE-INTEGRITY
                        let (_, ice_pwd) = session.ice_agent.credentials();
                        let ice_pwd_owned = ice_pwd.to_string();
                        info!("WebRTC session created for call {} (ICE+DTLS+SRTP, ice_pwd_len={})", uuid, ice_pwd_owned.len());

                        // Store ice_pwd in B2BUA call for later use by MediaManager
                        self.b2bua.set_webrtc_ice_pwd(&uuid, ice_pwd_owned).await;

                        self.b2bua.set_webrtc_session(&uuid, session).await;
                    }
                    Err(e) => {
                        warn!("Failed to create WebRTC session for call {}: {}", uuid, e);
                        // Continue without WebRTC session — fallback to standard SIP
                    }
                }
            }
        }

        // ── Step 1: Registrar-based routing (SIP→WebRTC / WebRTC→SIP) ──────────
        // Extract the callee username from the Request-URI
        let mut callee_aor = extract_callee_aor(&request);
        debug!("INVITE callee AOR: {:?}", callee_aor);

        // ── DID mapping: if callee is a PSTN number, map to local SIP user ──
        // This handles inbound calls from trunks (e.g. 0123456789 → user1)
        let mut did_mapped = false;
        if let Some(ref aor) = callee_aor {
            // Extract just the user part from the AOR (e.g. "0123456789" from "sip:0123456789@sip.nixi.tel")
            let callee_user = aor.strip_prefix("sip:")
                .and_then(|s| s.split('@').next())
                .unwrap_or(aor);

            // Check if this number matches a DID mapping
            let did_match = self.did_mappings.read().await.iter().find(|did| {
                // Match against the number as-is, or with/without leading 0, or E.164 format
                let n = &did.number;
                callee_user == n
                    || callee_user == n.trim_start_matches('0')
                    || callee_user == format!("+33{}", n.trim_start_matches('0'))
                    || format!("+33{}", callee_user.trim_start_matches('0')) == format!("+33{}", n.trim_start_matches('0'))
            }).cloned();

            if let Some(did) = did_match {
                let sip_realm = self.identity.as_ref()
                    .map(|id| id.sip_domain.clone())
                    .unwrap_or_else(|| "sip.nixi.tel".to_string());
                let mapped_aor = format!("sip:{}@{}", did.user, sip_realm);
                info!("DID mapping: {} → {} (user: {})", did.number, mapped_aor, did.user);
                callee_aor = Some(mapped_aor);
                did_mapped = true;
            }
        }

        let registrar_contact = if let Some(ref aor) = callee_aor {
            match self.register_handler.lookup(aor).await {
                Ok(contacts) if !contacts.is_empty() => {
                    // Pick the most recently registered contact
                    let contact = contacts.into_iter().max_by_key(|r| r.registered_at);
                    if let Some(ref c) = contact {
                        info!("Registrar lookup: callee {} found at {} (transport={})", aor, c.contact, c.transport);
                    }
                    contact
                }
                Ok(_) => {
                    debug!("Registrar lookup: no active registration for {}", aor);
                    None
                }
                Err(e) => {
                    warn!("Registrar lookup error for {}: {}", aor, e);
                    None
                }
            }
        } else {
            None
        };

        // ── Step 2: Determine destination, transport and outbound reply channel ─
        let (dest, outbound_transport, outbound_reply_tx) = if let Some(ref reg) = registrar_contact {
            // Route to registered contact (e.g., a WebRTC/WSS client)
            let addr: std::net::SocketAddr = format!("{}:{}", reg.received_ip, reg.received_port)
                .parse()
                .map_err(|e| Error::Other(format!("Invalid registered addr: {}", e)))?;

            let reg_transport = match reg.transport.as_str() {
                "WSS" => rsip::Transport::Wss,
                "WS"  => rsip::Transport::Ws,
                "TLS" => rsip::Transport::Tls,
                "TCP" => rsip::Transport::Tcp,
                _     => rsip::Transport::Udp,
            };

            info!("Routing INVITE to registered contact {} via {}", addr, reg.transport);

            // For connection-oriented transports (WS/WSS/TLS/TCP): reuse the stored
            // reply_tx (the inbound connection channel). This is critical for NAT
            // traversal — the callee's private IP is not reachable from the server.
            let callee_reply_tx = reg.reply_tx.clone();

            // WS/WSS callee with a dead connection is unreachable: the SBC
            // cannot dial out to a browser behind NAT (by design, like
            // Kamailio). Answer 480 now instead of sending into the void.
            if matches!(reg_transport, rsip::Transport::Ws | rsip::Transport::Wss) {
                let connection_alive = callee_reply_tx
                    .as_ref()
                    .map(|tx| !tx.is_closed())
                    .unwrap_or(false);
                if !connection_alive {
                    warn!(
                        "Registered WS contact {} has no live connection — 480",
                        addr
                    );
                    self.b2bua.terminate_call(&uuid).await;
                    self.metrics.inc_call_failed();
                    self.metrics.inc_sip_response(480);
                    let response_480 = build_plain_response(480, "Temporarily Unavailable");
                    let _ = self.transport.reply(response_480.as_bytes(), source, transport, reply_tx).await;
                    return Ok(());
                }
            }

            (addr, reg_transport, callee_reply_tx)
        } else if did_mapped {
            // DID matched a local user but they are NOT registered → 480 Temporarily Unavailable
            // Do NOT fall through to trunk routing (that would loop the call back to the trunk)
            let aor = callee_aor.as_deref().unwrap_or("unknown");
            warn!("DID target {} is not registered — responding 480", aor);
            self.b2bua.terminate_call(&uuid).await;
            self.metrics.inc_call_failed();
            self.metrics.inc_sip_response(480);
            let response_480 = build_plain_response(480, "Temporarily Unavailable");
            let _ = self.transport.reply(response_480.as_bytes(), source, transport, reply_tx).await;
            return Ok(());
        } else {
            // No DID match and no registered user — fall back to trunk routing
            // (outbound PSTN call). Multi-candidate: first trunk is used now,
            // the rest are armed for active failover (5s no-answer / 5xx).
            // ── Destination blocking (anti-IRSF) before trunk selection ──
            if let Some(dialed) = request.uri.user().map(|s| s.to_string()) {
                let caller_user = request.from_header().ok()
                    .and_then(|h| h.typed().ok())
                    .and_then(|f: rsip::typed::From| f.uri.user().map(str::to_string));
                if let crate::security::DestinationDecision::Blocked { rule_id, description } =
                    self.security.destinations.check(&dialed, caller_user.as_deref())
                {
                    warn!(target: "security", "Destination blocked: {} (rule {}: {})", dialed, rule_id, description);
                    self.security.emit(crate::security::SecurityEvent::DestinationBlocked {
                        user: caller_user,
                        destination: dialed,
                        rule: rule_id,
                        ts: crate::events::event_ts(),
                    });
                    self.b2bua.terminate_call(&uuid).await;
                    self.metrics.inc_security_destination_blocked();
                    self.metrics.inc_call_failed();
                    self.metrics.inc_sip_response(403);
                    let r403 = build_plain_response_for_request(&request, 403, "Forbidden - Destination Blocked")?;
                    let data = r403.to_string().into_bytes();
                    let _ = self.transport.reply(&data, source, transport, reply_tx).await;
                    return Ok(());
                }
            }

            let mut candidates = self.router.route_request_candidates(&request);
            if candidates.is_empty() {
                warn!("Routing failed for INVITE: no candidate trunk");
                self.b2bua.terminate_call(&uuid).await;
                self.metrics.inc_call_failed();
                self.metrics.inc_sip_response(503);
                let response_503 = build_plain_response(503, "Service Unavailable");
                let _ = self.transport.reply(response_503.as_bytes(), source, transport, reply_tx).await;
                return Ok(());
            }
            let trunk = candidates.remove(0);
            let backup_ids: Vec<crate::routing::TrunkId> =
                candidates.iter().map(|t| t.id).collect();
            self.b2bua.set_failover_candidates(&uuid, backup_ids.clone()).await;
            if !backup_ids.is_empty() {
                info!("Failover armed: {} backup trunk(s) for call {}", backup_ids.len(), uuid);
            }

            info!("Routing INVITE via trunk: {} ({}:{})", trunk.name, trunk.host, trunk.port);

            // ── Number normalization for trunk ──────────────────────────────
            // Extract user part from Request-URI and normalize for this trunk's format
            if let Some(user_part) = request.uri.user().map(|s| s.to_string()) {
                let normalized = trunk.normalize_number(&user_part);
                if normalized != user_part {
                    info!("Number normalized: {} → {} (trunk '{}' expects {:?})", user_part, normalized, trunk.name, trunk.number_format);
                    // Rewrite the Request-URI auth (user part) with the normalized number
                    if let Some(ref mut auth) = request.uri.auth {
                        auth.user = normalized;
                    }
                }
            }

            // ── Store trunk_id on the B2BUA call for 407 retry ──────────────
            // We need trunk_id to look up credentials when we get a 407 response
            self.b2bua.store_outbound_invite(&uuid, String::new(), trunk.id).await;
            // Store trunk name for CDR enrichment
            {
                let mut calls = self.b2bua.calls_locked().await;
                if let Some(call) = calls.get_mut(&uuid) {
                    call.trunk_name = Some(trunk.name.clone());
                }
            }
            info!("B2BUA: stored trunk_id={} for call {}", trunk.id, uuid);

            let dest = match trunk.destination() {
                Some(d) => d,
                None => {
                    error!("Invalid trunk destination for: {}", trunk.host);
                    self.b2bua.terminate_call(&uuid).await;
                    self.metrics.inc_call_failed();
                    self.metrics.inc_sip_response(503);
                    let response_503 = build_plain_response(503, "Service Unavailable");
                    let _ = self.transport.reply(response_503.as_bytes(), source, transport, reply_tx).await;
                    return Ok(());
                }
            };

            (dest, trunk.transport.to_rsip_transport(), None)
        };

        // ── CDR enrichment: store caller/callee numbers and trunk name ──────
        {
            let caller_num = request.from_header().ok()
                .and_then(|h| h.typed().ok())
                .map(|from: rsip::typed::From| from.uri.user().unwrap_or("unknown").to_string());
            let callee_num = callee_aor.as_deref()
                .and_then(|aor| aor.strip_prefix("sip:"))
                .and_then(|s| s.split('@').next())
                .map(|s| s.to_string());
            // Inbound (PSTN → registered user) calls carry no outbound trunk,
            // so trunk_name is unset above. Attribute them to the originating
            // trunk by matching the source IP, so the CDR trunk_id is populated.
            let inbound_trunk = self.trunk_manager.name_for_ip(&source.ip().to_string());
            let mut calls = self.b2bua.calls_locked().await;
            if let Some(call) = calls.get_mut(&uuid) {
                call.caller_number = caller_num;
                call.callee_number = callee_num;
                if call.trunk_name.is_none() {
                    call.trunk_name = inbound_trunk;
                }
            }
        }

        // ── Detect callee WebRTC (PSTN → WebRTC) ──────────────────────────────
        // If the callee is on WSS/WS transport, it's a WebRTC endpoint.
        // We need to generate a WebRTC SDP offer (Opus/SAVPF/ICE/DTLS) instead
        // of forwarding the trunk's PCMA/AVP SDP.
        let callee_is_webrtc = matches!(outbound_transport, rsip::Transport::Wss | rsip::Transport::Ws);
        if callee_is_webrtc {
            self.b2bua.set_callee_is_webrtc(&uuid, true).await;
            info!("Callee is WebRTC (transport={:?}) — will generate WebRTC SDP offer", outbound_transport);
        }

        // ── Step 3: Rewrite SDP body for NAT traversal ───────────────────────
        // Replace private IP in SDP c= line with the SBC's public IP.
        // This ensures the callee sends RTP to the SBC (or at least to a routable address).
        let mut request_with_sdp = request;
        if !request_with_sdp.body.is_empty() {
            if let Ok(sdp_str) = std::str::from_utf8(&request_with_sdp.body) {
                // Get the media session ports if available (for full RTP proxy mode)
                let media_session_id = self.b2bua.get_media_session_id(&uuid).await;

                // ── Trunk → WebRTC SDP transformation ──────────────────
                // When callee is WebRTC and caller is a trunk (plain RTP),
                // completely replace the SDP with a WebRTC Opus/SAVPF offer.
                let rewritten_sdp = if callee_is_webrtc {
                    let sbc_ip = self.identity.as_ref()
                        .map(|id| id.public_ip.clone())
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    // Get the leg-B RTP port (callee/WebRTC side)
                    let leg_b_port = if let Some(ref media_id) = media_session_id {
                        self.media.get_session(media_id)
                            .and_then(|s| s.ports_b.map(|pb| pb.rtp))
                            .unwrap_or(10000)
                    } else {
                        10000
                    };

                    // Create WebRTC session for leg-B and generate SDP offer
                    match WebRtcSession::new_for_offer(call_id.clone()) {
                        Ok(session) => {
                            let ice_pwd_owned = {
                                let (_, ice_pwd) = session.ice_agent.credentials();
                                ice_pwd.to_string()
                            };
                            self.b2bua.set_webrtc_ice_pwd_b(&uuid, ice_pwd_owned.clone()).await;

                            let sdp_offer = session.generate_sdp_offer(leg_b_port, &sbc_ip);
                            self.b2bua.set_webrtc_sdp_offer(&uuid, sdp_offer.clone()).await;
                            self.b2bua.set_webrtc_session_b(&uuid, session).await;

                            // Set ICE pwd on MediaManager for leg-B STUN MESSAGE-INTEGRITY
                            if let Some(ref media_id) = media_session_id {
                                self.media.set_ice_pwd_local_b(media_id, ice_pwd_owned);
                            }

                            info!("Trunk→WebRTC SDP transformation (port {}): generate Opus/SAVPF/ICE/DTLS offer", leg_b_port);
                            info!("SDP INVITE outbound (Trunk→WebRTC):\n{}", sdp_offer);
                            sdp_offer
                        }
                        Err(e) => {
                            warn!("Failed to create WebRTC session for callee: {} — falling back to standard SDP", e);
                            self.media.rewrite_sdp_ip(sdp_str)
                        }
                    }
                } else if caller_is_webrtc {
                    let sbc_ip = self.identity.as_ref()
                        .map(|id| id.public_ip.clone())
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    // Get the leg-B RTP port (callee/trunk side)
                    let trunk_rtp_port = if let Some(ref media_id) = media_session_id {
                        self.media.get_session(media_id)
                            .and_then(|s| s.ports_b.map(|pb| pb.rtp))
                            .unwrap_or_else(|| {
                                self.media.get_session(media_id)
                                    .map(|s| s.ports.rtp)
                                    .unwrap_or(10000)
                            })
                    } else {
                        10000
                    };
                    let trunk_sdp = transform_webrtc_to_trunk(sdp_str, &sbc_ip, trunk_rtp_port);
                    info!("WebRTC→Trunk SDP transformation (port {}): strip SAVPF/DTLS/ICE → RTP/AVP PCMA", trunk_rtp_port);
                    info!("SDP INVITE outbound (WebRTC→Trunk):\n{}", trunk_sdp);
                    trunk_sdp
                } else if let Some(ref media_id) = media_session_id {
                    // Full proxy mode: replace IP and port with SBC proxy port.
                    // Use leg-B port: callee sends RTP to leg-B, leg-B relays to caller.
                    if let Some(session) = self.media.get_session(media_id) {
                        let proxy_port = session.ports_b
                            .map(|pb| pb.rtp)
                            .unwrap_or(session.ports.rtp);
                        self.media.rewrite_sdp_for_proxy(sdp_str, proxy_port)
                    } else {
                        self.media.rewrite_sdp_ip(sdp_str)
                    }
                } else {
                    // IP-only rewrite (NAT passthrough): replace private IP with SBC public IP
                    self.media.rewrite_sdp_ip(sdp_str)
                };

                if !caller_is_webrtc {
                    if rewritten_sdp != sdp_str {
                        info!("SDP INVITE outbound (to callee):\n{}", rewritten_sdp);
                    } else {
                        info!("SDP INVITE outbound (unchanged):\n{}", rewritten_sdp);
                    }
                }

                // ── SRTP extraction DISABLED ──────────────────────────
                // The SBC relays (S)RTP as opaque bytes — no decryption.
                // See comment in handle_response for full rationale.

                request_with_sdp.body = rewritten_sdp.into_bytes();
                // Update Content-Length to match new body size (critical for TCP framing)
                update_content_length_request(&mut request_with_sdp);
            }
        }

        // Save the callee Request-URI before topology hiding consumes the request
        let callee_request_uri_str = request_with_sdp.uri.to_string();

        // ── Step 3a: Store caller's original Via headers BEFORE topology hiding ──
        // The caller's Via is critical: responses relayed back to the caller MUST
        // contain the caller's original Via so the UAC can match the response to
        // its INVITE transaction (RFC 3261 §18.1.2). Topology hiding will strip
        // all Vias and insert the SBC's own Via for the outbound leg.
        {
            let caller_vias: Vec<String> = request_with_sdp.headers.iter()
                .filter_map(|h| {
                    let s = h.to_string();
                    if s.to_lowercase().starts_with("via:") || s.to_lowercase().starts_with("v:") {
                        Some(s)
                    } else {
                        None
                    }
                })
                .collect();
            info!("Stored {} original Via header(s) for caller", caller_vias.len());
            self.b2bua.set_caller_vias(&uuid, caller_vias).await;
        }

        // ── Step 3b: Apply topology hiding on outbound message ────────────────
        let raw_request = rsip::SipMessage::Request(request_with_sdp).to_string();
        // Use the OUTBOUND transport name (not the inbound one), so the Via header
        // reflects the correct transport the callee must use to reply.
        let outbound_transport_name = match outbound_transport {
            rsip::Transport::Tls  => "TLS",
            rsip::Transport::Tcp  => "TCP",
            rsip::Transport::Wss  => "WSS",
            rsip::Transport::Ws   => "WS",
            _                     => "UDP",
        };
        // Build an identity with the correct port for the outbound transport:
        // TLS/WSS → 5061, others → 5060
        let outbound_raw = if let Some(base_identity) = &self.identity {
            let out_port = match outbound_transport {
                rsip::Transport::Tls | rsip::Transport::Wss => 5061,
                _ => 5060,
            };
            let outbound_identity = if out_port != base_identity.sip_port {
                let tls_flag = matches!(outbound_transport, rsip::Transport::Tls | rsip::Transport::Wss);
                crate::topology::SbcIdentity::new(
                    &base_identity.public_ip,
                    &base_identity.sip_domain,
                    out_port,
                    tls_flag,
                )
            } else {
                base_identity.clone()
            };
            apply_topology_hiding_outbound(&raw_request, &outbound_identity, outbound_transport_name)
                .unwrap_or(raw_request)
        } else {
            raw_request
        };

        // ── Step 4: Forward INVITE ────────────────────────────────────────────
        // For WSS/TLS clients, use their stored reply_tx (existing inbound connection).
        // For UDP/TCP, open a new connection.
        // Log the From/To in the outbound INVITE for dialog matching debug
        {
            let from_line = outbound_raw.lines().find(|l| l.to_lowercase().starts_with("from:"));
            let to_line = outbound_raw.lines().find(|l| l.to_lowercase().starts_with("to:"));
            let callid_line = outbound_raw.lines().find(|l| l.to_lowercase().starts_with("call-id:"));
            info!("INVITE outbound {}", from_line.unwrap_or("(no From)"));
            info!("INVITE outbound {}", to_line.unwrap_or("(no To)"));
            info!("INVITE outbound {}", callid_line.unwrap_or("(no Call-ID)"));
        }
        // ── RFC 4028: offer session timers on trunk legs ─────────────────
        let outbound_raw = {
            let is_trunk_call = {
                let calls = self.b2bua.calls_locked().await;
                calls.get(&uuid).map(|c| c.trunk_name.is_some()).unwrap_or(false)
            };
            match (self.session_timer, is_trunk_call) {
                (Some((expires, min_se)), true) => inject_session_timer_headers(
                    &outbound_raw, expires, min_se,
                ),
                _ => outbound_raw,
            }
        };

        self.transport.reply(outbound_raw.as_bytes(), dest, outbound_transport, outbound_reply_tx.as_ref()).await?;
        info!("Forwarded INVITE to {} via {:?}", dest, outbound_transport);

        // ── Store raw outbound INVITE for 407 auth retry ──────────────────
        // If the trunk responds with 407 Proxy Authentication Required,
        // we need to resend this INVITE with Proxy-Authorization header.
        // store_outbound_invite was already called with empty string + trunk_id;
        // now update it with the actual raw INVITE.
        if let Some((_, trunk_id, _)) = self.b2bua.get_auth_retry_info(&uuid).await {
            self.b2bua.store_outbound_invite(&uuid, outbound_raw.clone(), trunk_id).await;
            debug!("B2BUA: stored raw outbound INVITE ({} bytes) for potential 407 retry", outbound_raw.len());
        }

        // Attach outbound leg to B2BUA call (store callee reply_tx for BYE relay)
        // IMPORTANT: the outbound Call-ID is the SAME as the inbound INVITE Call-ID
        // because we forward the INVITE as-is (not a true B2BUA re-origination).
        // The callee will use this Call-ID in its BYE, so we must match on it.
        let outbound_call_id = call_id.clone();
        let local_tag = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let _ = self.b2bua.attach_outbound(
            &uuid, outbound_call_id, local_tag, dest,
            outbound_reply_tx.clone(), outbound_transport,
        ).await;

        // Store callee's Request-URI for ACK relay
        self.b2bua.set_callee_request_uri(&uuid, callee_request_uri_str).await;

        Ok(())
    }

    /// Periodic scan (1s tick): calls whose outbound INVITE got no >=180
    /// provisional within `invite_timeout` fail over to the next candidate
    /// trunk. With no remaining candidate the call is left to the normal
    /// call-setup timeout (a single slow trunk must not be aborted early).
    pub(crate) async fn check_invite_failover(&mut self) {
        let timed_out = self.b2bua.invite_attempts_timed_out(self.invite_timeout).await;
        for (uuid, attempt, has_remaining) in timed_out {
            if !has_remaining {
                continue;
            }
            warn!(
                "Failover: call {} attempt {} unanswered after {:?} — trying next trunk",
                &uuid[..8.min(uuid.len())], attempt, self.invite_timeout
            );
            self.failover_to_next_trunk(&uuid).await;
        }
    }

    /// CANCEL the current outbound attempt and re-send the stored INVITE,
    /// retargeted to the next candidate trunk (fresh Via branch, R-URI and
    /// number normalization for that trunk).
    pub(crate) async fn failover_to_next_trunk(&mut self, uuid: &crate::b2bua::CallUuid) {
        let Some(next_id) = self.b2bua.take_next_failover_candidate(uuid).await else {
            return;
        };
        let Some(trunk) = self.trunk_manager.get_trunk(&next_id) else {
            warn!("Failover: candidate trunk {} no longer exists — trying next", next_id);
            // Recurse once per missing candidate (bounded by candidate list length)
            return Box::pin(self.failover_to_next_trunk(uuid)).await;
        };
        let Some(new_dest) = trunk.destination() else {
            warn!("Failover: trunk '{}' has no destination — trying next", trunk.name);
            return Box::pin(self.failover_to_next_trunk(uuid)).await;
        };

        // Snapshot the previous attempt (stored INVITE + current callee dest)
        let (stored_invite, prev_dest, prev_transport, callee_reply_tx) = {
            let calls = self.b2bua.calls_locked().await;
            let Some(call) = calls.get(uuid) else { return };
            (
                call.original_outbound_invite.clone(),
                call.callee_dest,
                call.callee_transport,
                call.callee_reply_tx.clone(),
            )
        };
        let Some(stored_invite) = stored_invite.filter(|s| !s.is_empty()) else {
            warn!("Failover: no stored outbound INVITE for call {} — cannot fail over", uuid);
            return;
        };

        // 1. CANCEL the previous attempt (harmless if the trunk never got it)
        if let (Some(cancel), Some(dest)) =
            (crate::sip_builder::build_cancel(&stored_invite), prev_dest)
        {
            info!("Failover: CANCEL previous attempt → {}", dest);
            let _ = self.transport
                .reply(cancel.as_bytes(), dest, prev_transport, callee_reply_tx.as_ref())
                .await;
        }

        // 2. Retarget the INVITE to the new trunk
        let Some(new_invite) = retarget_invite_for_trunk(&stored_invite, &trunk) else {
            warn!("Failover: could not retarget INVITE for trunk '{}'", trunk.name);
            return;
        };
        let new_transport = trunk.transport.to_rsip_transport();

        info!(
            "Failover: re-sending INVITE via trunk '{}' ({}:{})",
            trunk.name, trunk.host, trunk.port
        );
        if let Err(e) = self.transport
            .reply(new_invite.as_bytes(), new_dest, new_transport, None)
            .await
        {
            warn!("Failover: send to trunk '{}' failed: {}", trunk.name, e);
            return Box::pin(self.failover_to_next_trunk(uuid)).await;
        }

        // 3. Update call state for the new attempt
        self.b2bua.store_outbound_invite(uuid, new_invite, trunk.id).await;
        {
            let mut calls = self.b2bua.calls_locked().await;
            if let Some(call) = calls.get_mut(uuid) {
                call.trunk_name = Some(trunk.name.clone());
                call.callee_dest = Some(new_dest);
                call.callee_transport = new_transport;
                call.callee_reply_tx = None;
                if let Some(out) = call.outbound.as_mut() {
                    out.remote_addr = new_dest;
                }
            }
        }
    }

    /// Handle 407 Proxy Authentication Required from a trunk.
    /// Extracts the challenge, computes credentials, and resends the INVITE.
    /// Returns Ok(true) if INVITE was resent, Ok(false) if retry exhausted/impossible.
    pub(super) async fn handle_407_auth_retry(
        &self,
        uuid: &crate::b2bua::CallUuid,
        response: &Response,
        trunk_source: SocketAddr,
    ) -> Result<bool> {
        // 1. Check retry count — only allow one retry
        let (original_invite, trunk_id, retry_count) = match self.b2bua.get_auth_retry_info(uuid).await {
            Some(info) => info,
            None => {
                warn!("407 retry: no auth info stored for call {}", uuid);
                return Ok(false);
            }
        };

        if retry_count >= 1 {
            warn!("407 retry: already retried once for call {} — giving up", uuid);
            return Ok(false);
        }

        if original_invite.is_empty() {
            warn!("407 retry: no original INVITE stored for call {}", uuid);
            return Ok(false);
        }

        // 2. Get trunk credentials
        let trunk = match self.trunk_manager.get_trunk(&trunk_id) {
            Some(t) => t,
            None => {
                warn!("407 retry: trunk {} not found", trunk_id);
                return Ok(false);
            }
        };

        if !trunk.auth_required {
            warn!("407 retry: trunk '{}' does not require auth but sent 407", trunk.name);
            return Ok(false);
        }

        let username = match &trunk.username {
            Some(u) => u.clone(),
            None => {
                warn!("407 retry: no username configured for trunk '{}'", trunk.name);
                return Ok(false);
            }
        };
        let password = match &trunk.password {
            Some(p) => p.clone(),
            None => {
                warn!("407 retry: no password configured for trunk '{}'", trunk.name);
                return Ok(false);
            }
        };

        // 3. Extract Proxy-Authenticate header from the 407 response
        let response_raw = rsip::SipMessage::Response(response.clone()).to_string();
        let proxy_auth_header = response_raw.lines()
            .find(|line| line.to_lowercase().starts_with("proxy-authenticate:"))
            .map(|line| {
                let colon_pos = line.find(':').unwrap_or(0);
                line[colon_pos + 1..].trim().to_string()
            });

        let proxy_auth_value = match proxy_auth_header {
            Some(v) => v,
            None => {
                warn!("407 retry: no Proxy-Authenticate header in 407 response");
                return Ok(false);
            }
        };

        // 4. Parse the Digest challenge
        let challenge = match DigestChallenge::from_header(&proxy_auth_value) {
            Ok(c) => c,
            Err(e) => {
                warn!("407 retry: failed to parse Digest challenge: {}", e);
                return Ok(false);
            }
        };

        // 5. Extract the Request-URI from the original INVITE (first line)
        let digest_uri = extract_request_uri_from_raw(&original_invite)
            .unwrap_or_else(|| "sip:unknown@unknown".to_string());

        // 6. Generate Proxy-Authorization header value
        let auth_header_value = generate_digest_response(
            &username,
            &password,
            &challenge,
            "INVITE",
            &digest_uri,
        );

        info!("407 retry: computed Proxy-Authorization for user '{}' realm '{}'", username, challenge.realm);

        // 7. Rebuild the INVITE: inject Proxy-Authorization, new Via branch, CSeq+1
        let new_invite = inject_proxy_auth_into_invite(&original_invite, &auth_header_value);

        // 8. Send the authenticated INVITE to the trunk
        let dest = trunk.destination().unwrap_or(trunk_source);
        let outbound_transport = trunk.transport.to_rsip_transport();

        // Get callee reply_tx from B2BUA (for connection-oriented transports)
        let callee_reply_tx = {
            let calls = self.b2bua.calls_locked().await;
            calls.get(uuid).and_then(|c| c.callee_reply_tx.clone())
        };

        self.transport.reply(
            new_invite.as_bytes(),
            dest,
            outbound_transport,
            callee_reply_tx.as_ref(),
        ).await?;

        // 9. Increment retry count so we don't loop forever
        self.b2bua.increment_auth_retry(uuid).await;

        // Update stored invite with the authenticated version
        self.b2bua.store_outbound_invite(uuid, new_invite, trunk_id).await;

        info!("407 retry: resent authenticated INVITE to {} for call {}", dest, uuid);
        Ok(true)
    }

    /// Apply topology hiding to an outbound SIP request (Via rewrite, Record-Route, Contact).
    /// Used for INVITE, ACK, BYE, CANCEL relayed to the other leg.
    pub(crate) fn apply_outbound_topology(&self, raw_msg: &str, outbound_transport: rsip::Transport) -> String {
        if let Some(base_identity) = &self.identity {
            let outbound_transport_name = match outbound_transport {
                rsip::Transport::Tls  => "TLS",
                rsip::Transport::Tcp  => "TCP",
                rsip::Transport::Wss  => "WSS",
                rsip::Transport::Ws   => "WS",
                _                     => "UDP",
            };
            let out_port = match outbound_transport {
                rsip::Transport::Tls | rsip::Transport::Wss => 5061,
                _ => 5060,
            };
            let out_id = if out_port != base_identity.sip_port {
                let tls_flag = matches!(outbound_transport, rsip::Transport::Tls | rsip::Transport::Wss);
                crate::topology::SbcIdentity::new(
                    &base_identity.public_ip,
                    &base_identity.sip_domain,
                    out_port,
                    tls_flag,
                )
            } else {
                base_identity.clone()
            };
            crate::topology::apply_topology_hiding_outbound(raw_msg, &out_id, outbound_transport_name)
                .unwrap_or_else(|_| raw_msg.to_string())
        } else {
            raw_msg.to_string()
        }
    }
}

/// Extract the URI from a Contact header value: `"Bob" <sip:b@1.2.3.4:5060;transport=tcp>;expires=60`
/// → `sip:b@1.2.3.4:5060;transport=tcp`. Falls back to the trimmed value.
pub(crate) fn extract_contact_uri(value: &str) -> String {
    if let (Some(start), Some(end)) = (value.find('<'), value.find('>')) {
        if end > start {
            return value[start + 1..end].to_string();
        }
    }
    // No angle brackets: strip header params after ';'… but ';' may belong to
    // URI params. Without brackets, URI params are indistinguishable from
    // header params — keep everything up to the first comma.
    value.split(',').next().unwrap_or(value).trim().to_string()
}

/// Retarget a stored outbound INVITE to another trunk: rewrite the
/// Request-URI (host:port + trunk-specific number normalization) and
/// refresh the top Via branch. Returns None when the message is not an
/// INVITE or has no parseable request line.
pub(crate) fn retarget_invite_for_trunk(
    raw_invite: &str,
    trunk: &crate::routing::TrunkConfig,
) -> Option<String> {
    let mut lines: Vec<String> = raw_invite.split("\r\n").map(str::to_string).collect();
    let first = lines.first()?.clone();
    let mut parts = first.splitn(3, ' ');
    if parts.next() != Some("INVITE") {
        return None;
    }
    let uri = parts.next()?;
    let version = parts.next().unwrap_or("SIP/2.0");

    // Extract the user part from "sip:user@host..." and renormalize
    let user = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))?
        .split('@')
        .next()?
        .split(';')
        .next()?
        .to_string();
    let normalized = trunk.normalize_number(&user);
    lines[0] = format!("INVITE sip:{}@{}:{} {}", normalized, trunk.host, trunk.port, version);

    // Fresh branch on the top Via
    let fresh = crate::sip_builder::new_branch();
    for line in lines.iter_mut().skip(1) {
        let lower = line.to_lowercase();
        if lower.starts_with("via:") || lower.starts_with("v:") {
            if let Some(pos) = line.find("branch=") {
                let after = &line[pos + "branch=".len()..];
                let end = after.find(|c: char| c == ';' || c == ',').map(|i| pos + "branch=".len() + i)
                    .unwrap_or(line.len());
                line.replace_range(pos + "branch=".len()..end, &fresh);
            }
            break;
        }
        if line.is_empty() {
            break;
        }
    }

    Some(lines.join("\r\n"))
}

#[cfg(test)]
mod failover_tests {
    use super::*;

    fn trunk(host: &str, port: u16) -> crate::routing::TrunkConfig {
        crate::routing::TrunkConfig {
            id: uuid::Uuid::new_v4(),
            name: "backup".to_string(),
            enabled: true,
            transport: crate::routing::TransportType::Udp,
            host: host.to_string(),
            port,
            resolved_addr: None,
            auth_required: false,
            username: None,
            password: None,
            realm: None,
            allowed_codecs: vec![],
            transcoding_enabled: false,
            max_concurrent_calls: 10,
            calls_per_second: 10,
            allowed_ips: vec![],
            register_with_trunk: false,
            registration_interval: std::time::Duration::from_secs(300),
            cost_per_minute: 0,
            priority: 100,
            weight: 100,
            prefix_patterns: vec![],
            number_format: crate::routing::trunk::NumberFormat::E164,
            country_code: Some("33".to_string()),
            national_prefix: Some("0".to_string()),
            caller_number_format: None,
            caller_number_override: None,
            caller_display_name: None,
            tls_sni: None,
            tls_ca_cert: None,
            tls_verify: true,
            tls_client_cert: None,
            tls_client_key: None,
        }
    }

    const INVITE: &str = "INVITE sip:0612345678@10.0.0.1:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKoldbranch;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@a.example.com>;tag=al-1\r\n\
To: <sip:0612345678@pstn>\r\n\
Call-ID: xyz@host\r\n\
CSeq: 3 INVITE\r\n\
Content-Length: 0\r\n\r\n";

    #[test]
    fn retarget_rewrites_uri_and_branch() {
        let t = trunk("203.0.113.9", 5080);
        let out = retarget_invite_for_trunk(INVITE, &t).expect("retarget");
        assert!(out.starts_with("INVITE sip:+33612345678@203.0.113.9:5080 SIP/2.0\r\n"), "{}", out);
        assert!(!out.contains("z9hG4bKoldbranch"), "branch must be fresh");
        assert!(out.contains("branch=z9hG4bK"));
        assert!(out.contains("Call-ID: xyz@host\r\n"), "dialog identity preserved");
        rsip::SipMessage::try_from(out.as_bytes().to_vec()).expect("retargeted INVITE parses");
    }

    #[test]
    fn retarget_rejects_non_invite() {
        let t = trunk("203.0.113.9", 5060);
        assert!(retarget_invite_for_trunk("BYE sip:x SIP/2.0\r\n\r\n", &t).is_none());
    }

    #[test]
    fn inject_session_timer_headers_before_content_length() {
        let raw = "INVITE sip:x@y SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKx\r\nContent-Length: 0\r\n\r\n";
        let out = inject_session_timer_headers(raw, 1800, 90);
        assert!(out.contains("Supported: timer\r\nSession-Expires: 1800\r\nMin-SE: 90\r\nContent-Length: 0"));
        rsip::SipMessage::try_from(out.as_bytes().to_vec()).unwrap();
    }

    #[test]
    fn extract_contact_uri_variants() {
        assert_eq!(
            extract_contact_uri("\"Bob\" <sip:b@1.2.3.4:5060;transport=tcp>;expires=60"),
            "sip:b@1.2.3.4:5060;transport=tcp"
        );
        assert_eq!(extract_contact_uri("sip:b@1.2.3.4"), "sip:b@1.2.3.4");
    }
}

/// Insert `Supported: timer`, `Session-Expires` and `Min-SE` before the
/// Content-Length header of a raw INVITE.
pub(crate) fn inject_session_timer_headers(raw: &str, expires: u32, min_se: u32) -> String {
    let insert = format!(
        "Supported: timer\r\nSession-Expires: {}\r\nMin-SE: {}\r\n",
        expires, min_se
    );
    if let Some(pos) = raw.to_lowercase().find("content-length:") {
        let mut out = String::with_capacity(raw.len() + insert.len());
        out.push_str(&raw[..pos]);
        out.push_str(&insert);
        out.push_str(&raw[pos..]);
        out
    } else {
        raw.to_string()
    }
}
