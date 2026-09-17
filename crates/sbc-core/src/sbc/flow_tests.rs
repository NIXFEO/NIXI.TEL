//! Call-flow tests over the channel harness (`test_support`): one real
//! `Sbc`, a caller leg and a trunk leg, exact wire assertions. They pin the
//! B2BUA behaviours production depends on (dialog identity on synthetic
//! requests, CANCEL of the live attempt, teardown paths releasing media
//! and writing CDRs) so the SIP lots can refactor safely.

use super::test_support::*;
use super::*;

/// INVITE → 200 OK → ACK → BYE: the everyday outbound call.
#[tokio::test]
async fn full_call_relays_200_ack_and_bye_then_releases_media_and_writes_a_cdr() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    assert!(
        sbc.media.stats().allocated_ports > 0,
        "the call holds RTP ports"
    );
    let media_id = sbc.b2bua.get_media_session_id(&call.uuid).await.unwrap();
    let leg_a_port = sbc.media.get_session(&media_id).unwrap().ports.rtp;

    let wire = connect(&mut sbc, &mut call).await;

    // 200 OK toward the caller: its own Via and CSeq, the callee's tag,
    // and an SDP pointing at the SBC's relay instead of the trunk.
    assert!(wire.ok_to_caller.contains("branch=z9hG4bKcaller"));
    assert!(wire.ok_to_caller.contains("CSeq: 3 INVITE\r\n"));
    assert!(wire
        .ok_to_caller
        .contains("To: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
    assert!(
        wire.ok_to_caller
            .contains(&format!("m=audio {} RTP/AVP 0", leg_a_port)),
        "media anchored on the SBC (leg A port {}): {}",
        leg_a_port,
        wire.ok_to_caller
    );
    assert!(
        !wire.ok_to_caller.contains("m=audio 6004 "),
        "the trunk's media port never reaches the caller"
    );

    // ACK toward the trunk: the 200 OK's Contact as R-URI (RFC 3261
    // §13.2.2.4), the trunk-leg INVITE's CSeq, a fresh branch.
    assert!(
        wire.ack_to_trunk
            .starts_with(&format!("ACK {} SIP/2.0\r\n", TRUNK_CONTACT)),
        "{}",
        wire.ack_to_trunk
    );
    assert!(wire.ack_to_trunk.contains("CSeq: 3 ACK\r\n"));
    assert!(wire.ack_to_trunk.contains("Call-ID: cid-1\r\n"));
    assert!(wire
        .ack_to_trunk
        .contains("To: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
    assert!(!wire.ack_to_trunk.contains("z9hG4bKack"), "no branch leaks");
    {
        let calls = sbc.b2bua.calls_locked().await;
        assert_eq!(calls[&call.uuid].state, crate::b2bua::CallState::Connected);
    }

    // BYE from the caller
    sbc.handle_bye(
        bye_from_caller(&call.spec, 4),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(to_caller.len(), 1, "200 OK to the BYE: {:?}", to_caller);
    assert!(
        to_caller[0].starts_with("SIP/2.0 200 OK\r\n"),
        "{}",
        to_caller[0]
    );
    assert!(to_caller[0].contains("CSeq: 4 BYE\r\n"));
    assert!(to_caller[0].contains("branch=z9hG4bKbye"));

    let to_trunk = drain(&mut call.callee_rx);
    assert_eq!(
        to_trunk.len(),
        1,
        "one BYE toward the trunk: {:?}",
        to_trunk
    );
    let bye = &to_trunk[0];
    assert!(
        bye.starts_with(&format!("BYE {} SIP/2.0\r\n", TRUNK_CONTACT)),
        "in-dialog requests go to the 200 OK's Contact: {}",
        bye
    );
    assert!(bye.contains("From: <sip:alice@a.example.com>;tag=al-1\r\n"));
    assert!(bye.contains("To: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
    assert!(bye.contains("Call-ID: cid-1\r\n"));
    assert!(
        bye.contains("CSeq: 4 BYE\r\n"),
        "above the trunk-leg INVITE's CSeq: {}",
        bye
    );

    assert!(!alive(&sbc).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0, "media released");
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1, "one CDR");
    let cdr = &cdrs[0];
    assert_eq!(cdr.call_id, "cid-1");
    assert_eq!(cdr.disconnect_reason, "normal-clearing");
    assert_eq!(cdr.trunk_id.as_deref(), Some(TRUNK_NAME));
    assert_eq!(cdr.v, crate::storage::CDR_SCHEMA_VERSION);
    assert_eq!(cdr.uuid, call.uuid);
    assert_eq!(cdr.direction, "outbound");
    assert_eq!(cdr.sip_code, Some(200));
    assert_eq!(cdr.source_ip, "10.0.0.9");
    assert_eq!(cdr.caller, "alice");
    assert_eq!(cdr.callee, "bob");
    assert_eq!(
        cdr.codec.as_deref(),
        Some("PCMU"),
        "negotiated from the trunk's answer"
    );
    assert!(cdr.answered_at.is_some(), "answered");
    assert!(cdr.answered_at.unwrap() >= cdr.started_at);
    assert!(cdr.ended_at >= cdr.answered_at.unwrap());
    assert!(cdr.billable_secs <= cdr.duration_secs);
    assert_eq!(cdr.reason, None, "the caller's BYE carried no Reason");

    // A second teardown of the same call writes nothing.
    assert!(!sbc.finish_call(&call.uuid, CallOutcome::AdminKick).await);
    assert_eq!(sbc.cdr.get_recent(10).await.unwrap().len(), 1);
}

/// Genesys clusters BYE from a sibling host of the one the INVITE went to.
/// On an outbound call that BYE belongs to the trunk leg: relay it to the
/// caller, not back to the trunk.
#[tokio::test]
async fn bye_from_another_host_of_the_trunk_cluster_is_relayed_to_the_caller() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;

    let sibling: SocketAddr = "203.0.113.77:5060".parse().unwrap();
    let (conn_tx, mut conn_rx) = tokio::sync::mpsc::unbounded_channel();
    sbc.handle_bye(
        bye_from_trunk_with(
            &call.spec,
            2,
            "Reason: Q.850;cause=16;text=\"Normal call clearing\"\r\n",
        ),
        sibling,
        rsip::Transport::Udp,
        Some(&conn_tx),
    )
    .await
    .unwrap();

    let to_sibling = drain(&mut conn_rx);
    assert_eq!(
        to_sibling.len(),
        1,
        "200 OK back to the sender: {:?}",
        to_sibling
    );
    assert!(to_sibling[0].starts_with("SIP/2.0 200 OK\r\n"));
    assert!(to_sibling[0].contains("CSeq: 2 BYE\r\n"));

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(
        to_caller.len(),
        1,
        "one BYE toward the caller: {:?}",
        to_caller
    );
    let bye = &to_caller[0];
    assert!(
        bye.starts_with("BYE sip:alice@10.0.0.9:5060 SIP/2.0\r\n"),
        "{}",
        bye
    );
    assert!(bye.contains("From: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
    assert!(bye.contains("To: <sip:alice@a.example.com>;tag=al-1\r\n"));
    assert!(bye.contains("Call-ID: cid-1\r\n"));
    assert!(
        drain(&mut call.callee_rx).is_empty(),
        "nothing goes back toward the trunk"
    );

    assert!(!alive(&sbc).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0);
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].disconnect_reason, "normal-clearing");
    assert_eq!(
        cdrs[0].reason.as_deref(),
        Some("Q.850;cause=16;text=\"Normal call clearing\""),
        "the trunk's Reason header is kept for billing"
    );
    assert_eq!(cdrs[0].sip_code, Some(200));
}

/// CANCEL from the caller cancels the LIVE attempt (after a 422 retry: the
/// retried INVITE's branch and CSeq), answers 200 and releases everything.
#[tokio::test]
async fn cancel_targets_the_live_invite_attempt_and_releases_the_call() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;

    // 422 from the trunk → ACK + retried INVITE (CSeq 4, fresh branch)
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
    let out = drain(&mut call.callee_rx);
    assert_eq!(out.len(), 2, "ACK then retried INVITE: {:?}", out);
    let retry_branch = top_branch(&out[1]);
    assert_ne!(retry_branch, "z9hG4bKaaa");

    sbc.handle_cancel(
        cancel_from_caller(&call.spec),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();

    let to_trunk = drain(&mut call.callee_rx);
    assert_eq!(
        to_trunk.len(),
        1,
        "one CANCEL toward the trunk: {:?}",
        to_trunk
    );
    let cancel = &to_trunk[0];
    assert!(
        cancel.starts_with("CANCEL sip:bob@203.0.113.9:5060 SIP/2.0\r\n"),
        "{}",
        cancel
    );
    assert!(
        cancel.contains("CSeq: 4 CANCEL\r\n"),
        "retried attempt's CSeq: {}",
        cancel
    );
    assert!(
        cancel.contains(&retry_branch),
        "retried attempt's branch: {}",
        cancel
    );
    assert!(cancel.contains("From: <sip:alice@a.example.com>;tag=al-1\r\n"));

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(
        to_caller.len(),
        2,
        "200 OK to the CANCEL, then 487 to the INVITE: {:?}",
        to_caller
    );
    assert!(to_caller[0].starts_with("SIP/2.0 200 OK\r\n"));
    assert!(to_caller[0].contains("CSeq: 3 CANCEL\r\n"));
    let terminated = &to_caller[1];
    assert!(
        terminated.starts_with("SIP/2.0 487 Request Terminated\r\n"),
        "{}",
        terminated
    );
    assert!(terminated.contains("CSeq: 3 INVITE\r\n"), "{}", terminated);
    assert!(
        terminated.contains("Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKcaller\r\n"),
        "the INVITE transaction's Via: {}",
        terminated
    );
    assert!(terminated.contains("From: <sip:alice@a.example.com>;tag=al-1\r\n"));
    assert!(
        terminated.contains("To: <sip:bob@b.example.com>;tag="),
        "final gets a To tag"
    );
    assert!(terminated.contains("Call-ID: cid-1\r\n"));

    assert!(!alive(&sbc).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0);
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1, "a cancelled call is a CDR too");
    assert_eq!(cdrs[0].disconnect_reason, "cancelled");
    assert_eq!(cdrs[0].sip_code, Some(487));
    assert_eq!(cdrs[0].answered_at, None);
    assert_eq!(cdrs[0].billable_secs, 0);

    // The caller's ACK to the 487 is absorbed: nothing forwarded anywhere.
    sbc.handle_ack(
        ack_from_caller(&call.spec),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();
    assert!(drain(&mut call.caller_rx).is_empty());
    assert!(drain(&mut call.callee_rx).is_empty());
}

/// RFC 3261 §9.2: a CANCEL that crosses the 200 OK has no effect on the
/// dialog — 200 to the CANCEL, nothing toward the trunk, call untouched.
#[tokio::test]
async fn cancel_after_the_200_ok_is_answered_but_leaves_the_call_alone() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;

    sbc.handle_cancel(
        cancel_from_caller(&call.spec),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(
        to_caller.len(),
        1,
        "200 OK to the CANCEL only: {:?}",
        to_caller
    );
    assert!(to_caller[0].starts_with("SIP/2.0 200 OK\r\n"));
    assert!(to_caller[0].contains("CSeq: 3 CANCEL\r\n"));
    assert!(
        drain(&mut call.callee_rx).is_empty(),
        "no CANCEL toward an answered trunk leg"
    );
    assert!(alive(&sbc).await, "the dialog stands until the caller BYEs");
    assert!(sbc.media.stats().allocated_ports > 0);
}

/// RFC 3261 §9.2: CANCEL for an INVITE transaction we do not have → 481.
#[tokio::test]
async fn cancel_for_an_unknown_call_gets_481() {
    let mut sbc = SbcBuilder::new().build();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let spec = CallSpec::numbered(9);
    sbc.handle_cancel(
        cancel_from_caller(&spec),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1, "{:?}", out);
    assert!(
        out[0].starts_with("SIP/2.0 481 Call/Transaction Does Not Exist\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("CSeq: 3 CANCEL\r\n"));
    assert!(out[0].contains("Call-ID: cid-9\r\n"));
}

/// An unanswered INVITE past `invite_timeout` is CANCELed on the first
/// trunk and re-sent to the next candidate (real UDP socket as the backup).
#[tokio::test]
async fn invite_timeout_cancels_and_retargets_to_the_next_trunk() {
    let mut sbc = SbcBuilder::new().invite_timeout(Duration::ZERO).build();
    sbc.start(&udp_loopback(), None).await.unwrap();

    let backup = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backup_addr = backup.local_addr().unwrap();
    let mut trunk = crate::routing::TrunkConfig::new("backup".to_string());
    trunk.host = "127.0.0.1".to_string();
    trunk.port = backup_addr.port();
    let backup_id = sbc.add_trunk(trunk);

    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    sbc.b2bua
        .set_failover_candidates(&call.uuid, vec![backup_id])
        .await;

    sbc.check_invite_failover().await;

    let to_first = drain(&mut call.callee_rx);
    assert_eq!(
        to_first.len(),
        1,
        "CANCEL on the first trunk: {:?}",
        to_first
    );
    assert!(
        to_first[0].starts_with("CANCEL sip:bob@203.0.113.9:5060 SIP/2.0\r\n"),
        "{}",
        to_first[0]
    );
    assert!(to_first[0].contains("branch=z9hG4bKaaa"));
    assert!(to_first[0].contains("CSeq: 3 CANCEL\r\n"));

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), backup.recv_from(&mut buf))
        .await
        .expect("the INVITE reaches the backup trunk")
        .unwrap();
    let invite = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(invite.starts_with("INVITE sip:"), "{}", invite);
    assert!(
        invite
            .lines()
            .next()
            .unwrap()
            .ends_with(&format!("@127.0.0.1:{} SIP/2.0", backup_addr.port())),
        "retargeted R-URI: {}",
        invite
    );
    assert!(!invite.contains("z9hG4bKaaa"), "fresh branch");
    assert!(invite.contains("CSeq: 3 INVITE\r\n"));
    assert!(invite.ends_with(SDP), "same offer");

    let (attempt, _) = sbc.b2bua.current_attempt(&call.uuid).await.unwrap();
    assert_eq!(attempt.dest, backup_addr);
    assert_eq!(attempt.trunk_id, Some(backup_id));
    assert_ne!(backup_id, call.trunk_id, "moved off the first trunk");
    assert!(alive(&sbc).await);
    assert!(
        drain(&mut call.caller_rx).is_empty(),
        "the caller sees nothing during failover"
    );

    // No candidate left: another tick changes nothing.
    sbc.check_invite_failover().await;
    assert!(drain(&mut call.callee_rx).is_empty());
    assert!(alive(&sbc).await);
}

/// `security.max_call_duration`: the SBC BYEs both legs with a Reason and
/// releases the call.
#[tokio::test]
async fn call_past_max_duration_is_byed_on_both_legs() {
    let mut sbc = SbcBuilder::new().max_call_duration(Duration::ZERO).build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;

    sbc.check_call_timeouts().await;

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(to_caller.len(), 1, "{:?}", to_caller);
    assert!(
        to_caller[0].starts_with("BYE sip:alice@10.0.0.9:5060 SIP/2.0\r\n"),
        "{}",
        to_caller[0]
    );
    assert!(to_caller[0].contains("From: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
    assert!(to_caller[0].contains("To: <sip:alice@a.example.com>;tag=al-1\r\n"));
    assert!(to_caller[0].contains("Reason: Q.850;cause=16;text=\"Call duration exceeded\"\r\n"));

    let to_trunk = drain(&mut call.callee_rx);
    assert_eq!(to_trunk.len(), 1, "{:?}", to_trunk);
    assert!(
        to_trunk[0].starts_with(&format!("BYE {} SIP/2.0\r\n", TRUNK_CONTACT)),
        "{}",
        to_trunk[0]
    );
    assert!(to_trunk[0].contains("From: <sip:alice@a.example.com>;tag=al-1\r\n"));
    assert!(to_trunk[0].contains("To: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
    assert!(
        to_trunk[0].contains("CSeq: 4 BYE\r\n"),
        "above the INVITE's CSeq: {}",
        to_trunk[0]
    );
    assert!(to_trunk[0].contains("Reason: Q.850;cause=16"));

    assert!(!alive(&sbc).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0);
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].disconnect_reason, "timeout");
    assert_eq!(cdrs[0].sip_code, Some(200), "the call had been answered");
    assert_eq!(
        cdrs[0].reason.as_deref(),
        Some("Q.850;cause=16;text=\"Call duration exceeded\"")
    );
}

/// SIGTERM: connected calls get a BYE on both legs, a still-ringing call
/// gets its trunk-side INVITE CANCELed (a BYE would leave a ghost session).
#[tokio::test(start_paused = true)]
async fn graceful_shutdown_byes_connected_calls_and_cancels_pending_ones() {
    let mut sbc = SbcBuilder::new().build();
    let mut connected = add_call(&mut sbc, CallSpec::default()).await;
    let mut pending = add_call(&mut sbc, CallSpec::numbered(2)).await;
    connect(&mut sbc, &mut connected).await;

    sbc.graceful_shutdown().await;

    let to_caller = drain(&mut connected.caller_rx);
    assert_eq!(to_caller.len(), 1, "{:?}", to_caller);
    assert!(to_caller[0].starts_with("BYE sip:alice@10.0.0.9:5060 SIP/2.0\r\n"));
    assert!(to_caller[0].contains("Reason: Q.850;cause=16;text=\"Server shutdown\"\r\n"));
    let to_trunk = drain(&mut connected.callee_rx);
    assert_eq!(to_trunk.len(), 1, "{:?}", to_trunk);
    assert!(
        to_trunk[0].starts_with(&format!("BYE {} SIP/2.0\r\n", TRUNK_CONTACT)),
        "{}",
        to_trunk[0]
    );
    assert!(to_trunk[0].contains("To: <sip:bob@b.example.com>;tag=trunk-1\r\n"));
    assert!(to_trunk[0].contains("CSeq: 4 BYE\r\n"));

    let to_trunk = drain(&mut pending.callee_rx);
    assert_eq!(to_trunk.len(), 1, "{:?}", to_trunk);
    assert!(
        to_trunk[0].starts_with("CANCEL sip:bob@203.0.113.9:5060 SIP/2.0\r\n"),
        "pending INVITE is CANCELed, not BYEd: {}",
        to_trunk[0]
    );
    assert!(to_trunk[0].contains("branch=z9hG4bK000002"));
    assert!(to_trunk[0].contains("CSeq: 3 CANCEL\r\n"));
    assert!(to_trunk[0].contains("Call-ID: cid-2\r\n"));
    // The ringing caller has no dialog yet: its INVITE gets a final.
    let to_caller = drain(&mut pending.caller_rx);
    assert_eq!(to_caller.len(), 1, "{:?}", to_caller);
    assert!(
        to_caller[0].starts_with("SIP/2.0 503 Service Unavailable\r\n"),
        "{}",
        to_caller[0]
    );
    assert!(to_caller[0].contains("Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKcaller\r\n"));
    assert!(to_caller[0].contains("From: <sip:alice@a.example.com>;tag=al-2\r\n"));
    assert!(to_caller[0].contains("To: <sip:bob@b.example.com>;tag=sbc-"));
    assert!(to_caller[0].contains("Call-ID: cid-2\r\n"));
    assert!(to_caller[0].contains("CSeq: 3 INVITE\r\n"));
    assert!(to_caller[0].contains("Reason: Q.850;cause=16;text=\"Server shutdown\"\r\n"));

    assert_eq!(sbc.media.stats().allocated_ports, 0, "all media released");
    assert!(
        sbc.b2bua.calls_locked().await.is_empty(),
        "every call released"
    );
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 2, "one CDR per call");
    assert!(cdrs.iter().all(|c| c.disconnect_reason == "shutdown"));
    let answered = cdrs.iter().find(|c| c.call_id == "cid-1").unwrap();
    let ringing = cdrs.iter().find(|c| c.call_id == "cid-2").unwrap();
    assert_eq!(answered.sip_code, Some(200));
    assert!(answered.answered_at.is_some());
    assert_eq!(ringing.sip_code, Some(503));
    assert_eq!(ringing.answered_at, None);
}

/// A re-INVITE from the caller is answered locally with the SDP the caller
/// last received; the trunk never sees it.
#[tokio::test]
async fn reinvite_from_caller_is_answered_locally_with_the_last_sdp() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;
    let last_sdp = sbc.b2bua.calls_locked().await[&call.uuid]
        .last_sdp_to_caller
        .clone()
        .expect("the 200 OK relay stored the SDP sent to the caller");

    sbc.handle_reinvite(
        &call.uuid,
        true,
        reinvite_from_caller(&call.spec, 5, 900),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(to_caller.len(), 1, "{:?}", to_caller);
    let ok = &to_caller[0];
    assert!(ok.starts_with("SIP/2.0 200 OK\r\n"), "{}", ok);
    assert!(ok.contains("CSeq: 5 INVITE\r\n"));
    assert!(ok.contains("branch=z9hG4bKreinv"));
    assert!(ok.contains("Contact: <sip:sbc@127.0.0.1:5060>\r\n"));
    assert!(ok.contains("Supported: timer\r\n"));
    assert!(ok.contains("Session-Expires: 900;refresher=uac\r\n"));
    assert!(ok.contains("Content-Type: application/sdp\r\n"));
    let (_, body) = ok.split_once("\r\n\r\n").unwrap();
    assert_eq!(body, last_sdp);
    assert!(ok.contains(&format!("Content-Length: {}\r\n", body.len())));
    assert!(
        drain(&mut call.callee_rx).is_empty(),
        "answered locally — the trunk never sees the caller's re-INVITE"
    );
    assert!(alive(&sbc).await);
}

/// Churn: calls created and cancelled in a loop leave no state behind.
#[tokio::test]
async fn cancelled_calls_leave_no_state_behind() {
    let mut sbc = SbcBuilder::new().build();
    for n in 0..100 {
        let spec = CallSpec::numbered(n);
        let call = add_call(&mut sbc, spec.clone()).await;
        sbc.handle_cancel(
            cancel_from_caller(&spec),
            caller_addr(),
            rsip::Transport::Udp,
            Some(&call.caller_tx),
        )
        .await
        .unwrap();
    }
    assert!(sbc.b2bua.calls_locked().await.is_empty());
    assert_eq!(sbc.b2bua.stats().await.total_active, 0);
    assert_eq!(sbc.media.stats().allocated_ports, 0);
}

/// An inbound trunk call to a number that is neither a DID nor a
/// registered user is answered 404 (never routed back out to a trunk).
#[tokio::test]
async fn trunk_call_to_an_unknown_number_is_answered_404() {
    let mut sbc = SbcBuilder::new().build();
    register_trunk_ip(&sbc).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    sbc.handle_invite(
        invite_from_trunk("+33999000111", 70),
        trunk_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();

    let out = drain(&mut rx);
    assert_eq!(out.len(), 2, "100 Trying then 404: {:?}", out);
    assert!(out[0].starts_with("SIP/2.0 100 Trying\r\n"), "{}", out[0]);
    let nf = &out[1];
    assert!(nf.starts_with("SIP/2.0 404 Not Found\r\n"), "{}", nf);
    assert!(
        nf.contains("Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKtrk1"),
        "{}",
        nf
    );
    assert!(nf.contains("From: <sip:+33612345678@203.0.113.9>;tag=g1\r\n"));
    assert!(
        nf.contains("To: <sip:+33999000111@127.0.0.1>;tag="),
        "final gets a To tag: {}",
        nf
    );
    assert!(nf.contains("Call-ID: cid-in-1\r\n"));
    assert!(nf.contains("CSeq: 1 INVITE\r\n"));

    assert!(
        sbc.b2bua.calls_locked().await.is_empty(),
        "no call left behind"
    );
    assert_eq!(sbc.media.stats().allocated_ports, 0, "media released");
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1, "a rejected inbound call is billed as such");
    assert_eq!(cdrs[0].disconnect_reason, "rejected-404");
    assert_eq!(cdrs[0].sip_code, Some(404));
    assert_eq!(cdrs[0].direction, "inbound");
    assert_eq!(cdrs[0].trunk_id.as_deref(), Some(TRUNK_NAME));
    assert_eq!(cdrs[0].caller, "+33612345678");
    assert_eq!(cdrs[0].callee, "+33999000111");
    assert_eq!(cdrs[0].source_ip, "203.0.113.9");
    assert_eq!(cdrs[0].answered_at, None);
}

/// RFC 3261 §16.3: Max-Forwards: 0 is answered 483 before any work.
#[tokio::test]
async fn invite_with_exhausted_max_forwards_is_answered_483() {
    let mut sbc = SbcBuilder::new().build();
    register_trunk_ip(&sbc).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    sbc.handle_invite(
        invite_from_trunk("+33999000111", 0),
        trunk_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();

    let out = drain(&mut rx);
    assert_eq!(out.len(), 1, "483 only, no 100 Trying: {:?}", out);
    assert!(
        out[0].starts_with("SIP/2.0 483 Too Many Hops\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("branch=z9hG4bKtrk1"));
    assert!(out[0].contains("CSeq: 1 INVITE\r\n"));
    assert!(sbc.b2bua.calls_locked().await.is_empty());
    assert_eq!(sbc.media.stats().allocated_ports, 0);
}

/// A final error from the trunk (486) is relayed and billed as rejected.
#[tokio::test]
async fn rejected_final_from_the_trunk_is_relayed_and_billed() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;

    sbc.handle_response(
        response("486 Busy Here", "z9hG4bKaaa", 3, "INVITE", ""),
        trunk_addr(),
        rsip::Transport::Udp,
        None,
    )
    .await
    .unwrap();

    let to_trunk = drain(&mut call.callee_rx);
    assert_eq!(to_trunk.len(), 1, "ACK: {:?}", to_trunk);
    assert!(to_trunk[0].starts_with("ACK "));
    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(to_caller.len(), 1, "{:?}", to_caller);
    assert!(
        to_caller[0].starts_with("SIP/2.0 486 Busy Here\r\n"),
        "{}",
        to_caller[0]
    );
    assert!(to_caller[0].contains("CSeq: 3 INVITE\r\n"));

    assert!(!alive(&sbc).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0);
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].disconnect_reason, "rejected-486");
    assert_eq!(cdrs[0].sip_code, Some(486));
    assert_eq!(cdrs[0].direction, "outbound");
    assert_eq!(cdrs[0].trunk_id.as_deref(), Some(TRUNK_NAME));
    assert_eq!(cdrs[0].billable_secs, 0);
}

/// RTP inactivity (relay reported) ends the SIP dialog on both legs.
#[tokio::test]
async fn rtp_timeout_ends_the_call_on_both_legs() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;
    let media_id = sbc.b2bua.get_media_session_id(&call.uuid).await.unwrap();

    sbc.media.mark_timed_out(&media_id);
    sbc.check_media_timeouts().await;

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(to_caller.len(), 1, "{:?}", to_caller);
    assert!(to_caller[0].starts_with("BYE sip:alice@10.0.0.9:5060 SIP/2.0\r\n"));
    assert!(to_caller[0].contains("Reason: Q.850;cause=16;text=\"RTP timeout\"\r\n"));
    let to_trunk = drain(&mut call.callee_rx);
    assert_eq!(to_trunk.len(), 1, "{:?}", to_trunk);
    assert!(to_trunk[0].starts_with(&format!("BYE {} SIP/2.0\r\n", TRUNK_CONTACT)));
    assert!(to_trunk[0].contains("CSeq: 4 BYE\r\n"));

    assert!(!alive(&sbc).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0, "ports released");
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].disconnect_reason, "rtp-timeout");
    assert_eq!(cdrs[0].sip_code, Some(200));

    // Unknown session ids are ignored.
    sbc.media.mark_timed_out("no-such-session");
    sbc.check_media_timeouts().await;
    assert_eq!(sbc.cdr.get_recent(10).await.unwrap().len(), 1);
}

/// `DELETE /api/v1/calls/{uuid}`: the engine ends the call on the wire.
#[tokio::test]
async fn admin_kick_ends_the_call_on_both_legs() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;

    let kicks = sbc.admin_kicks();
    kicks.request(call.uuid.clone());
    kicks.request(call.uuid.clone());
    assert_eq!(kicks.pending().len(), 1, "queued once");
    sbc.process_admin_kicks().await;
    assert!(kicks.pending().is_empty());

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(to_caller.len(), 1, "{:?}", to_caller);
    assert!(to_caller[0].starts_with("BYE sip:alice@10.0.0.9:5060 SIP/2.0\r\n"));
    assert!(to_caller[0].contains("Reason: SIP;cause=200;text=\"Administrative teardown\"\r\n"));
    let to_trunk = drain(&mut call.callee_rx);
    assert_eq!(to_trunk.len(), 1, "{:?}", to_trunk);
    assert!(to_trunk[0].starts_with(&format!("BYE {} SIP/2.0\r\n", TRUNK_CONTACT)));

    assert!(!alive(&sbc).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0);
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].disconnect_reason, "admin-kick");

    // Kicking a call that is gone is a no-op.
    kicks.request(call.uuid.clone());
    sbc.process_admin_kicks().await;
    assert_eq!(sbc.cdr.get_recent(10).await.unwrap().len(), 1);
}

/// An INVITE nobody answers within `invite_setup_timeout` is CANCELed
/// toward the trunk and answered 408 to the caller.
#[tokio::test]
async fn unanswered_invite_is_bounded_by_the_setup_timeout() {
    let mut sbc = SbcBuilder::new().setup_timeout(Duration::ZERO).build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;

    sbc.check_setup_timeouts().await;

    let to_trunk = drain(&mut call.callee_rx);
    assert_eq!(to_trunk.len(), 1, "{:?}", to_trunk);
    assert!(
        to_trunk[0].starts_with(&format!("CANCEL {} SIP/2.0\r\n", TRUNK_INVITE_URI)),
        "{}",
        to_trunk[0]
    );
    assert!(to_trunk[0].contains("branch=z9hG4bKaaa"));
    assert!(to_trunk[0].contains("CSeq: 3 CANCEL\r\n"));

    let to_caller = drain(&mut call.caller_rx);
    assert_eq!(to_caller.len(), 1, "{:?}", to_caller);
    assert!(
        to_caller[0].starts_with("SIP/2.0 408 Request Timeout\r\n"),
        "{}",
        to_caller[0]
    );
    assert!(to_caller[0].contains("branch=z9hG4bKcaller"));
    assert!(to_caller[0].contains("CSeq: 3 INVITE\r\n"));
    assert!(to_caller[0].contains("Reason: SIP;cause=408;text=\"No answer\"\r\n"));

    assert!(!alive(&sbc).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0);
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].disconnect_reason, "setup-timeout");
    assert_eq!(cdrs[0].sip_code, Some(408));
    assert_eq!(cdrs[0].answered_at, None);

    // An answered call is never a setup timeout.
    let mut sbc = SbcBuilder::new().setup_timeout(Duration::ZERO).build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;
    sbc.check_setup_timeouts().await;
    assert!(alive(&sbc).await);
    assert!(drain(&mut call.caller_rx).is_empty());
    assert!(drain(&mut call.callee_rx).is_empty());
}
