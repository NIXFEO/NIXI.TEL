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

        // ── Anti-spam: reject INVITE from unregistered/unknown sources ──
        // Allow if any of:
        //   (1) source IP matches a registered user's received_ip
        //   (2) source is localhost (trunk)
        //   (3) From URI user matches a registered AOR (user calling from proxy/TLS)
        //   (4) callee is registered (incoming call from trunk for our user)
        //   (5) source IP is a known trunk IP (whitelisted)
        let source_ip = source.ip().to_string();
        let is_localhost = source_ip == "127.0.0.1" || source_ip == "::1";
        let is_trunk_ip = self.trunk_ips.iter().any(|ip| ip == &source_ip);
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
                self.metrics.inc_sip_response(403);
                let response_403 = build_plain_response_for_request(&request, 403, "Forbidden")?;
                let data = response_403.to_string().into_bytes();
                return self.transport.reply(&data, source, transport, reply_tx).await;
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
            let did_match = self.did_mappings.iter().find(|did| {
                // Match against the number as-is, or with/without leading 0, or E.164 format
                let n = &did.number;
                callee_user == n
                    || callee_user == n.trim_start_matches('0')
                    || callee_user == format!("+33{}", n.trim_start_matches('0'))
                    || format!("+33{}", callee_user.trim_start_matches('0')) == format!("+33{}", n.trim_start_matches('0'))
            });

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
            // No DID match and no registered user — fall back to trunk routing (outbound PSTN call)
            let trunk = match self.router.route_request(&request) {
                Ok(t) => t,
                Err(e) => {
                    warn!("Routing failed for INVITE: {}", e);
                    self.b2bua.terminate_call(&uuid).await;
                    self.metrics.inc_call_failed();
                    self.metrics.inc_sip_response(503);
                    let response_503 = build_plain_response(503, "Service Unavailable");
                    let _ = self.transport.reply(response_503.as_bytes(), source, transport, reply_tx).await;
                    return Ok(());
                }
            };

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
