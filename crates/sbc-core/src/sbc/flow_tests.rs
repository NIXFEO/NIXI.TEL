//! Call-flow tests over the channel harness (`test_support`): one real
//! `Sbc`, a caller leg and a trunk leg, exact wire assertions. They pin the
//! B2BUA behaviours production depends on (dialog identity on synthetic
//! requests, CANCEL of the live attempt, teardown paths releasing media
//! and writing CDRs) so the SIP lots can refactor safely.

use super::test_support::*;
use super::*;

/// The CDR's media facts must survive the teardown order: on the everyday
/// BYE path the media session is released *before* the CDR is written, and
/// reading the counters afterwards used to report "no relay, nothing
/// delivered" for every successful call.
#[tokio::test]
async fn a_bye_terminated_call_keeps_its_media_facts_in_the_cdr() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    let media_id = sbc.b2bua.get_media_session_id(&call.uuid).await.unwrap();
    connect(&mut sbc, &mut call).await;

    // Two packets delivered each way, as a real call would.
    let stats = sbc
        .media
        .call_media_stats(&media_id)
        .expect("live counters");
    for _ in 0..2 {
        stats.note_tx(crate::media::stats::Leg::Caller, 172);
        stats.note_tx(crate::media::stats::Leg::Callee, 172);
        stats.note_rx(crate::media::stats::Leg::Caller, &rtp_packet(1, 1));
        stats.note_rx(crate::media::stats::Leg::Callee, &rtp_packet(2, 1));
    }

    sbc.handle_bye(
        bye_from_caller(&call.spec, 4),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();

    let cdr = sbc.cdr.get_recent(1).await.unwrap().pop().expect("one CDR");
    assert_eq!(cdr.disconnect_reason, "normal-clearing");
    assert_eq!(
        (cdr.rtp_tx_caller, cdr.rtp_tx_callee),
        (2, 2),
        "the delivered counts survive the media release"
    );
    assert_eq!(cdr.media_flags, "", "a healthy call carries no flag");
    // And the counters are not kept for ever.
    assert_eq!(sbc.media.ended_stats_len(), 0, "released after the CDR");
}

/// `one-way-<leg>` must name the side that went silent, the same way the
/// metric label does.
#[tokio::test]
async fn the_cdr_one_way_flag_names_the_silent_leg() {
    use crate::media::stats::Leg;
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    let media_id = sbc.b2bua.get_media_session_id(&call.uuid).await.unwrap();
    connect(&mut sbc, &mut call).await;

    let stats = sbc.media.call_media_stats(&media_id).unwrap();
    // The caller talks, the callee never does.
    for _ in 0..5 {
        stats.note_rx(Leg::Caller, &rtp_packet(1, 1));
        stats.note_tx(Leg::Callee, 172);
    }
    assert_eq!(
        stats.one_way_leg(0).map(|l| l.label()),
        Some("callee"),
        "the relay names the callee as the silent side"
    );

    sbc.handle_bye(
        bye_from_caller(&call.spec, 4),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();
    let cdr = sbc.cdr.get_recent(1).await.unwrap().pop().expect("one CDR");
    assert_eq!(
        cdr.media_flags, "one-way-callee",
        "the CDR names the same side as the metric"
    );
}

/// A minimal RTP packet for the counter tests.
fn rtp_packet(ssrc: u32, seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(&[0xd5u8; 160]);
    p
}

/// Genesys truncates Call-IDs, so two live calls can share one: their
/// media sessions, ports and counters must still be separate.
#[tokio::test]
async fn two_calls_with_the_same_call_id_get_their_own_media_session() {
    let mut sbc = SbcBuilder::new().build();
    let first = add_call(&mut sbc, CallSpec::default()).await;
    let second = add_call(
        &mut sbc,
        CallSpec {
            from_tag: "al-2".into(),
            branch: "z9hG4bKtrunk2".into(),
            ..CallSpec::default()
        },
    )
    .await;
    assert_ne!(first.uuid, second.uuid);

    let a = sbc
        .b2bua
        .get_media_session_id(&first.uuid)
        .await
        .expect("first media session");
    let b = sbc
        .b2bua
        .get_media_session_id(&second.uuid)
        .await
        .expect("second media session");
    assert_ne!(a, b, "the two calls share the Call-ID, not the session");
    let ports_a = sbc.media.get_session(&a).unwrap().ports.rtp;
    let ports_b = sbc.media.get_session(&b).unwrap().ports.rtp;
    assert_ne!(ports_a, ports_b, "and not the ports either");
    assert_eq!(sbc.media.stats().active_sessions, 2);
}

/// A call the SBC cannot anchor media for is refused before it is dialled
/// out: the SDP would already point at this SBC, so the alternative is a
/// silent call billed for its whole life.
#[tokio::test]
async fn an_invite_with_no_media_port_is_refused_with_503() {
    let mut sbc = SbcBuilder::new().without_media_ports().build();
    register_trunk_ip(&sbc).await;
    let (caller_tx, mut caller_rx) = tokio::sync::mpsc::unbounded_channel();

    // The B2BUA refuses outright…
    let err = sbc
        .b2bua
        .create_call(
            "cid-no-ports".into(),
            "tag-1".into(),
            caller_addr(),
            Some(SDP),
            Some(caller_tx.clone()),
            rsip::Transport::Udp,
        )
        .await
        .expect_err("no media resources");
    assert!(err.to_string().contains("no media resources"), "{}", err);
    assert!(
        sbc.b2bua.active_calls().await.is_empty(),
        "no call was kept"
    );

    // …and the handler answers 503 rather than dialling the trunk.
    sbc.handle_invite(
        invite_from_trunk("+33612345678", 70),
        trunk_addr(),
        rsip::Transport::Udp,
        Some(&caller_tx),
    )
    .await
    .unwrap();
    let out = drain(&mut caller_rx);
    let all = out.join("\n");
    assert!(
        all.contains("SIP/2.0 503 Service Unavailable"),
        "the caller must get a 503, got: {}",
        all
    );
    assert_eq!(
        sbc.metrics
            .calls_failed_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "a call refused for lack of media counts as failed (no CDR is possible: \
         the call never existed)"
    );

    // With one pair free, the leg-B allocation must be refused too — the
    // old "single-leg fallback" bound leg A's ports twice and only failed
    // after the callee had answered.
    let one_pair = crate::media::MediaManager::with_port_range(21000..21002, None);
    let err = one_pair
        .create_session("one-pair".into(), Some(SDP))
        .await
        .expect_err("two pairs are required");
    assert!(err.to_string().contains("No available ports"), "{}", err);
    assert_eq!(
        one_pair.stats().allocated_ports,
        0,
        "the first pair is given back, not leaked"
    );
    assert_eq!(
        sbc.metrics
            .media_relay_failures
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

/// An answered call whose media relay could not start is ended right away:
/// the SDP on both sides points at this SBC, so without a relay the call
/// is silent — and with no relay there is no inactivity watchdog either,
/// so it would otherwise run to `max_call_duration`, billed.
#[tokio::test]
async fn an_answered_call_without_a_relay_is_ended_as_media_unavailable() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    let media_id = sbc.b2bua.get_media_session_id(&call.uuid).await.unwrap();
    let session = sbc.media.get_session(&media_id).unwrap();

    // Hold the relay's own port so `start_rtp_session` cannot bind it.
    let _squatter = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", session.ports.rtp))
        .await
        .expect("squat the leg-A RTP port");

    sbc.handle_response(
        response_for(
            &call.spec,
            "200 OK",
            &call.spec.branch,
            call.spec.cseq,
            "INVITE",
            &format!(
                "Contact: <{}>\r\nContent-Type: application/sdp\r\n",
                TRUNK_CONTACT
            ),
            TRUNK_SDP,
        ),
        trunk_addr(),
        rsip::Transport::Udp,
        None,
    )
    .await
    .expect("200 OK handled");

    // The caller got its 200 (both dialogs exist), then the SBC ended them.
    let to_caller = drain(&mut call.caller_rx);
    assert!(
        to_caller[0].starts_with("SIP/2.0 200 OK\r\n"),
        "{:?}",
        to_caller
    );
    assert!(
        to_caller.iter().any(|m| m.starts_with("BYE ")),
        "the caller leg is hung up: {:?}",
        to_caller
    );
    let to_trunk = drain(&mut call.callee_rx);
    assert!(
        to_trunk.iter().any(|m| m.starts_with("BYE ")),
        "the trunk leg is hung up: {:?}",
        to_trunk
    );
    assert!(
        to_trunk
            .iter()
            .any(|m| m.contains("cause=47") && m.contains("No media resource")),
        "the BYE says why: {:?}",
        to_trunk
    );

    let cdr = sbc.cdr.get_recent(1).await.unwrap().pop().expect("one CDR");
    assert_eq!(cdr.disconnect_reason, "media-unavailable");
    assert_eq!(cdr.hangup_by, "sbc");
    assert_eq!(
        cdr.media_flags, "no-relay",
        "billing can see this call had no media anchor"
    );
    assert_eq!((cdr.rtp_tx_caller, cdr.rtp_tx_callee), (0, 0));
    assert_eq!(
        sbc.metrics
            .media_relay_failures
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(sbc.media.stats().allocated_ports, 0, "media released");
    assert!(sbc.b2bua.active_calls().await.is_empty());
}

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
    assert_eq!(cdr.hangup_by, "caller");

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
        bye.contains("Reason: Q.850;cause=16;text=\"Normal call clearing\"\r\n"),
        "the trunk's Reason is relayed to the caller: {}",
        bye
    );
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
    assert_eq!(cdrs[0].hangup_by, "callee");
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
    assert_eq!(cdrs[0].hangup_by, "caller");

    // Our 487 went over UDP: it is retransmitted (Timer G) until the ACK.
    assert_eq!(sbc.invite_tx.pending_retransmissions(), 1);

    // The caller's ACK to the 487 is absorbed: nothing forwarded anywhere,
    // and the retransmissions stop.
    sbc.handle_ack(
        ack_for_final_from_caller(&call.spec),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();
    assert!(drain(&mut call.caller_rx).is_empty());
    assert!(drain(&mut call.callee_rx).is_empty());
    assert_eq!(sbc.invite_tx.pending_retransmissions(), 0, "ACKed");
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
    let first = sbc.trunk_manager.get_state(&call.trunk_id).unwrap();
    assert_eq!(
        (first.active_calls, first.consecutive_failures),
        (0, 1),
        "the silent first trunk released the call and took a strike"
    );
    assert_eq!(
        sbc.trunk_manager
            .get_state(&backup_id)
            .unwrap()
            .active_calls,
        1,
        "the backup now carries it"
    );
    assert_eq!(
        sbc.metrics
            .trunk_series(TRUNK_NAME)
            .unwrap()
            .calls
            .get(&("outbound".to_string(), "failover")),
        Some(&1)
    );
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
    let s = sbc.trunk_manager.state_by_name(TRUNK_NAME).unwrap();
    assert_eq!(s.active_calls, 0, "charged to the source trunk, released");
    assert_eq!(s.total_calls, 1);
    assert_eq!(
        s.consecutive_failures, 0,
        "our 404 is not the trunk's failure"
    );
    assert_eq!(
        sbc.metrics
            .trunk_series(TRUNK_NAME)
            .unwrap()
            .calls
            .get(&("inbound".to_string(), "failed")),
        Some(&1),
        "inbound refusals stay out of the outbound ASR"
    );
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

    // A ringing callee (180 relayed) is bounded by Timer C (3 min), not by
    // the setup timeout: a long ring is not a silent trunk.
    let mut sbc = SbcBuilder::new().setup_timeout(Duration::ZERO).build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    sbc.handle_response(
        response("180 Ringing", "z9hG4bKaaa", 3, "INVITE", ""),
        trunk_addr(),
        rsip::Transport::Udp,
        None,
    )
    .await
    .unwrap();
    assert!(drain(&mut call.caller_rx)[0].starts_with("SIP/2.0 180 Ringing"));
    sbc.check_setup_timeouts().await;
    assert!(alive(&sbc).await, "still ringing within Timer C");
    assert!(drain(&mut call.caller_rx).is_empty());
    assert!(drain(&mut call.callee_rx).is_empty());
}

/// A clustered trunk may CANCEL with the truncated Call-ID it uses on its
/// ACK/BYE: matched by suffix when the source is trunk-related.
#[tokio::test]
async fn cancel_with_a_truncated_call_id_from_the_trunk_matches_by_suffix() {
    let mut sbc = SbcBuilder::new().build();
    let spec = CallSpec {
        call_id: "14823298-118e8248-104858689_65703785@host".into(),
        ..CallSpec::default()
    };
    let mut call = add_call(&mut sbc, spec.clone()).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let short = CallSpec {
        call_id: "104858689_65703785@host".into(),
        ..spec.clone()
    };
    sbc.handle_cancel(
        cancel_from_caller(&short),
        "203.0.113.77:5060".parse().unwrap(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();

    let out = drain(&mut rx);
    assert_eq!(
        out.len(),
        2,
        "200 to the CANCEL, 487 to the INVITE: {:?}",
        out
    );
    assert!(out[0].starts_with("SIP/2.0 200 OK\r\n"));
    assert!(out[1].starts_with("SIP/2.0 487 Request Terminated\r\n"));
    assert!(!call_alive(&sbc, &spec.call_id).await);
    assert_eq!(sbc.media.stats().allocated_ports, 0);
    let to_trunk = drain(&mut call.callee_rx);
    assert_eq!(
        to_trunk.len(),
        1,
        "the live attempt is CANCELed: {:?}",
        to_trunk
    );
    assert!(to_trunk[0].starts_with("CANCEL "));

    // From a non-trunk source the truncated Call-ID is unknown → 481.
    let mut sbc = SbcBuilder::new().build();
    let _call = add_call(&mut sbc, spec.clone()).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    sbc.handle_cancel(
        cancel_from_caller(&short),
        "198.51.100.7:5060".parse().unwrap(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1);
    assert!(out[0].starts_with("SIP/2.0 481 "), "{}", out[0]);
    assert!(call_alive(&sbc, &spec.call_id).await);
}

/// The INVITE cannot be sent anywhere (no listener, no other trunk): the
/// caller gets a 503 for its INVITE and nothing is left behind.
#[tokio::test]
async fn invite_that_cannot_be_forwarded_is_answered_503_and_released() {
    let mut sbc = SbcBuilder::new().build();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    sbc.handle_invite(
        invite_from_local("+33612345678", ""),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();

    let out = drain(&mut rx);
    assert_eq!(out.len(), 2, "100 Trying then 503: {:?}", out);
    assert!(out[0].starts_with("SIP/2.0 100 Trying\r\n"));
    assert!(
        out[1].starts_with("SIP/2.0 503 Service Unavailable\r\n"),
        "{}",
        out[1]
    );
    assert!(out[1].contains("Via: SIP/2.0/UDP 127.0.0.1:5080;branch=z9hG4bKloc1;rport\r\n"));
    assert!(out[1].contains("CSeq: 1 INVITE\r\n"));
    assert!(out[1].contains("Call-ID: cid-out-1\r\n"));
    assert!(out[1].contains("To: <sip:+33612345678@127.0.0.1>;tag=sbc-"));

    assert!(sbc.b2bua.calls_locked().await.is_empty(), "no orphan call");
    assert_eq!(sbc.media.stats().allocated_ports, 0, "no orphan ports");
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].disconnect_reason, "rejected-503");
    assert_eq!(cdrs[0].direction, "outbound");
    assert_eq!(cdrs[0].trunk_id.as_deref(), Some(TRUNK_NAME));
    assert_eq!(cdrs[0].caller, "alice");
    assert_eq!(cdrs[0].callee, "+33612345678");

    // A UDP retransmission of that INVITE only gets the 503 again.
    sbc.handle_invite(
        invite_from_local("+33612345678", ""),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let again = drain(&mut rx);
    assert_eq!(again.len(), 1, "replayed final only: {:?}", again);
    assert!(again[0].starts_with("SIP/2.0 503 "));
    assert_eq!(
        sbc.cdr.get_recent(10).await.unwrap().len(),
        1,
        "no second call"
    );
    assert!(sbc.b2bua.calls_locked().await.is_empty());
}

/// RFC 3261 §17.2.1: a retransmitted INVITE (lost 100 Trying) is absorbed
/// while the first copy's call lives; a new transaction is a new call.
#[tokio::test]
async fn retransmitted_invite_is_absorbed_while_the_call_is_ringing() {
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
    let first = drain(&mut rx);
    assert_eq!(first.len(), 2, "100 then 404: {:?}", first);

    sbc.handle_invite(
        invite_from_trunk("+33999000111", 70),
        trunk_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let again = drain(&mut rx);
    assert_eq!(again.len(), 1, "the last response only: {:?}", again);
    assert!(again[0].starts_with("SIP/2.0 404 Not Found\r\n"));
    assert_eq!(
        sbc.cdr.get_recent(10).await.unwrap().len(),
        1,
        "one call, one CDR"
    );

    // Same Call-ID but a new branch/CSeq: a new INVITE transaction.
    let fresh = request(
        rsip::SipMessage::Request(invite_from_trunk("+33999000111", 70))
            .to_string()
            .replace("branch=z9hG4bKtrk1", "branch=z9hG4bKtrk2")
            .replace("CSeq: 1 INVITE", "CSeq: 2 INVITE"),
    );
    sbc.handle_invite(fresh, trunk_addr(), rsip::Transport::Udp, Some(&tx))
        .await
        .unwrap();
    let third = drain(&mut rx);
    assert_eq!(third.len(), 2, "processed anew: {:?}", third);
    assert_eq!(sbc.cdr.get_recent(10).await.unwrap().len(), 2);
}

/// RFC 3261 §8.2.2.3: an extension we do not implement cannot be required.
#[tokio::test]
async fn invite_requiring_an_unsupported_extension_is_answered_420() {
    let mut sbc = SbcBuilder::new().build();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    sbc.handle_invite(
        invite_from_local(
            "+33612345678",
            "Require: 100rel, timer\r\nSupported: 100rel\r\n",
        ),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1, "420 only, no 100 Trying: {:?}", out);
    assert!(
        out[0].starts_with("SIP/2.0 420 Bad Extension\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("Unsupported: 100rel\r\n"), "{}", out[0]);
    assert!(
        !out[0].contains("Unsupported: 100rel, timer"),
        "timer IS supported"
    );
    assert!(sbc.b2bua.calls_locked().await.is_empty());
    assert_eq!(sbc.media.stats().allocated_ports, 0);
}

/// RFC 3261 §8.2.1: a method the SBC does not implement gets 405 + Allow.
#[tokio::test]
async fn unsupported_method_is_answered_405_with_allow() {
    let mut sbc = SbcBuilder::new().build();
    register_trunk_ip(&sbc).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let subscribe = request(
        "SUBSCRIBE sip:alice@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKsub1\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:bob@203.0.113.9>;tag=s1\r\n\
         To: <sip:alice@127.0.0.1>\r\n\
         Call-ID: cid-sub-1\r\n\
         CSeq: 1 SUBSCRIBE\r\n\
         Event: presence\r\n\
         Content-Length: 0\r\n\r\n"
            .to_string(),
    );
    sbc.handle_request(subscribe, trunk_addr(), rsip::Transport::Udp, Some(&tx))
        .await
        .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1, "{:?}", out);
    assert!(
        out[0].starts_with("SIP/2.0 405 Method Not Allowed\r\n"),
        "{}",
        out[0]
    );
    assert!(
        out[0].contains(&format!(
            "Allow: {}\r\n",
            crate::sip_builder::ALLOWED_METHODS
        )),
        "{}",
        out[0]
    );
    assert!(out[0].contains("CSeq: 1 SUBSCRIBE\r\n"));
}

/// A 200 OK to a relayed INFO never reaches the INVITE logic.
#[tokio::test]
async fn response_to_a_relayed_info_is_dropped() {
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;
    let media_id = sbc.b2bua.get_media_session_id(&call.uuid).await.unwrap();

    sbc.handle_response(
        response("200 OK", "z9hG4bKinfo", 9, "INFO", ""),
        trunk_addr(),
        rsip::Transport::Udp,
        None,
    )
    .await
    .unwrap();

    assert!(
        drain(&mut call.caller_rx).is_empty(),
        "nothing relayed to the caller"
    );
    assert!(
        drain(&mut call.callee_rx).is_empty(),
        "no ACK toward the trunk"
    );
    assert!(alive(&sbc).await);
    assert_eq!(
        sbc.b2bua.get_media_session_id(&call.uuid).await.as_deref(),
        Some(media_id.as_str())
    );
}

/// What actually leaves toward the trunk: unsupported extensions stripped
/// from Supported, one hop consumed, the session-timer offer in place.
#[tokio::test]
async fn forwarded_invite_carries_only_supported_extensions() {
    let mut sbc = SbcBuilder::new().identity("127.0.0.1", 5060).build();
    sbc.start(&udp_loopback(), None).await.unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut trunk = crate::routing::TrunkConfig::new("loop".to_string());
    trunk.host = "127.0.0.1".to_string();
    trunk.port = peer_addr.port();
    sbc.add_trunk(trunk);
    assert!(sbc.trunk_manager.disable_trunk(&trunk_id(&sbc)));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    sbc.handle_invite(
        invite_from_local(
            "+33612345678",
            "Supported: 100rel, timer, replaces\r\nAllow: INVITE, ACK, PRACK\r\n",
        ),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();

    let to_caller = drain(&mut rx);
    assert_eq!(to_caller.len(), 1, "100 Trying: {:?}", to_caller);
    assert!(to_caller[0].starts_with("SIP/2.0 100 Trying\r\n"));

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
        .await
        .expect("the INVITE reaches the trunk")
        .unwrap();
    let invite = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(invite.starts_with("INVITE sip:"), "{}", invite);
    assert!(!invite.contains("100rel"), "100rel stripped: {}", invite);
    assert!(
        !invite.contains("replaces"),
        "replaces stripped: {}",
        invite
    );
    assert_eq!(invite.matches("Supported:").count(), 1, "{}", invite);
    assert!(invite.contains("Supported: timer\r\n"), "{}", invite);
    assert!(invite.contains("Session-Expires: 1800\r\n"), "{}", invite);
    assert!(invite.contains("Max-Forwards: 69\r\n"), "{}", invite);
    assert!(
        invite.contains("Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK")
            && !invite.contains("z9hG4bKloc1"),
        "topology hidden: the SBC's own Via: {}",
        invite
    );
    assert!(invite.contains("Record-Route: "), "{}", invite);
    assert!(
        invite.find("Supported:").unwrap() < invite.find("Content-Length:").unwrap(),
        "{}",
        invite
    );
    assert!(call_alive(&sbc, "cid-out-1").await);
}

/// Digest REGISTER: challenge, success, retransmission, replay, stale
/// nonce (re-challenge with stale=true, no strike), wrong password (403 +
/// strike).
#[tokio::test]
async fn register_digest_stale_nonce_is_rechallenged_and_replays_are_refused() {
    const REALM: &str = "sip.example.com";
    let mut sbc = SbcBuilder::new()
        .digest_users(REALM, &[("alice", "s3cret")])
        .build();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let auth_events = |sbc: &Sbc| {
        sbc.security
            .recent_events()
            .iter()
            .filter(|e| matches!(e, crate::security::SecurityEvent::AuthFailure { .. }))
            .count()
    };

    // 1. No credentials → 401 with a fresh challenge (not stale)
    sbc.handle_request(
        register_request("alice", REALM, 1, ""),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1, "{:?}", out);
    assert!(
        out[0].starts_with("SIP/2.0 401 Unauthorized\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("WWW-Authenticate: Digest realm=\"sip.example.com\", nonce=\""));
    assert!(!out[0].contains("stale=true"));
    let nonce = nonce_of(&out[0]);

    // 2. Valid credentials → 200, binding stored
    let authorized = register_request(
        "alice",
        REALM,
        2,
        &authorization_line("alice", REALM, "s3cret", &nonce, "00000001"),
    );
    sbc.handle_request(
        authorized.clone(),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1, "{:?}", out);
    assert!(out[0].starts_with("SIP/2.0 200 OK\r\n"), "{}", out[0]);
    assert_eq!(
        sbc.register_handler
            .lookup("sip:alice@sip.example.com")
            .await
            .unwrap()
            .len(),
        1
    );

    // 3. The same message again (UDP retransmission): still 200, no strike
    sbc.handle_request(authorized, local_addr(), rsip::Transport::Udp, Some(&tx))
        .await
        .unwrap();
    let out = drain(&mut rx);
    assert!(
        out[0].starts_with("SIP/2.0 200 OK\r\n"),
        "retransmission accepted: {}",
        out[0]
    );
    assert_eq!(auth_events(&sbc), 0);

    // 4. Same nonce and nc from a different request (another Contact): replay →
    //    401 stale=true, no strike (only the password holder can produce it)
    let replay = request(
        rsip::SipMessage::Request(register_request(
            "alice",
            REALM,
            3,
            &authorization_line("alice", REALM, "s3cret", &nonce, "00000001"),
        ))
        .to_string()
        .replace(
            "Contact: <sip:alice@127.0.0.1:5080>",
            "Contact: <sip:alice@198.51.100.7:5060>",
        ),
    );
    sbc.handle_request(replay, local_addr(), rsip::Transport::Udp, Some(&tx))
        .await
        .unwrap();
    let out = drain(&mut rx);
    assert!(
        out[0].starts_with("SIP/2.0 401 Unauthorized\r\n"),
        "{}",
        out[0]
    );
    assert!(
        out[0].contains("stale=true"),
        "re-challenged, never banned: {}",
        out[0]
    );
    assert_eq!(
        auth_events(&sbc),
        0,
        "a replay proves the password is known"
    );

    // 5. Cached nonce that expired: 401 stale=true, no strike
    sbc.auth.as_ref().unwrap().backdate_nonce(&nonce, 301).await;
    sbc.handle_request(
        register_request(
            "alice",
            REALM,
            4,
            &authorization_line("alice", REALM, "s3cret", &nonce, "00000002"),
        ),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(
        out[0].starts_with("SIP/2.0 401 Unauthorized\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("stale=true"), "{}", out[0]);
    assert_eq!(auth_events(&sbc), 0, "a stale nonce is not a strike");
    assert_eq!(
        sbc.metrics
            .auth_stale_challenges_total
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );

    // 6. Retry on the fresh challenge → 200
    let fresh = nonce_of(&out[0]);
    sbc.handle_request(
        register_request(
            "alice",
            REALM,
            5,
            &authorization_line("alice", REALM, "s3cret", &fresh, "00000001"),
        ),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    assert!(drain(&mut rx)[0].starts_with("SIP/2.0 200 OK\r\n"));

    // 7. Wrong password on a valid nonce → 403 + strike
    sbc.handle_request(
        register_request(
            "alice",
            REALM,
            6,
            &authorization_line("alice", REALM, "wrong", &fresh, "00000002"),
        ),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(
        out[0].starts_with("SIP/2.0 403 Forbidden\r\n"),
        "{}",
        out[0]
    );
    assert_eq!(auth_events(&sbc), 1);

    // 8. Not a Digest header at all → 400, no strike
    sbc.handle_request(
        register_request("alice", REALM, 7, "Authorization: Bearer nope\r\n"),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(
        out[0].starts_with("SIP/2.0 400 Bad Request\r\n"),
        "{}",
        out[0]
    );
    assert_eq!(auth_events(&sbc), 1);
}

fn identity_events(sbc: &Sbc) -> Vec<(String, String, String)> {
    sbc.security
        .recent_events()
        .into_iter()
        .filter_map(|e| match e {
            crate::security::SecurityEvent::IdentityMismatch {
                user,
                claimed,
                method,
                ..
            } => Some((user, claimed, method)),
            _ => None,
        })
        .collect()
}

fn strike_count(sbc: &Sbc) -> usize {
    sbc.security
        .recent_events()
        .iter()
        .filter(|e| matches!(e, crate::security::SecurityEvent::AuthFailure { .. }))
        .count()
}

/// Register `user` from `source` on an SBC with Digest on (401 → 200).
async fn register(sbc: &mut Sbc, user: &str, password: &str, realm: &str, source: SocketAddr) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    sbc.handle_request(
        register_request(user, realm, 1, ""),
        source,
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(out[0].starts_with("SIP/2.0 401 "), "{}", out[0]);
    let nonce = nonce_of(&out[0]);
    sbc.handle_request(
        register_request(
            user,
            realm,
            2,
            &authorization_line(user, realm, password, &nonce, "00000001"),
        ),
        source,
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(out[0].starts_with("SIP/2.0 200 OK"), "{}", out[0]);
}

/// RFC 3261 §10.3 step 5: alice's password binds alice's AOR, nobody else's.
#[tokio::test]
async fn register_for_another_users_aor_is_forbidden() {
    const REALM: &str = "sip.example.com";
    let mut sbc = SbcBuilder::new()
        .digest_users(REALM, &[("alice", "s3cret"), ("bob", "b0b")])
        .build();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Challenge, then alice authenticates for bob's AOR
    sbc.handle_request(
        register_request_for("alice", "sip:bob@sip.example.com", REALM, 1, ""),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let nonce = nonce_of(&drain(&mut rx)[0]);
    sbc.handle_request(
        register_request_for(
            "alice",
            "sip:bob@sip.example.com",
            REALM,
            2,
            &authorization_line("alice", REALM, "s3cret", &nonce, "00000001"),
        ),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(
        out[0].starts_with("SIP/2.0 403 Forbidden\r\n"),
        "{}",
        out[0]
    );
    assert!(sbc
        .register_handler
        .lookup("sip:bob@sip.example.com")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        identity_events(&sbc),
        vec![(
            "alice".to_string(),
            "sip:bob@sip.example.com".to_string(),
            "REGISTER".to_string()
        )]
    );
    assert_eq!(strike_count(&sbc), 0, "a valid credential is never banned");

    // Own user on a foreign domain: reported but allowed until the
    // operator lists served_domains (phones registered against a LAN IP or
    // a DNS alias keep working after an upgrade)
    let events_before = identity_events(&sbc).len();
    sbc.handle_request(
        register_request_for("alice", "sip:alice@evil.example", REALM, 3, ""),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let nonce = nonce_of(&drain(&mut rx)[0]);
    sbc.handle_request(
        register_request_for(
            "alice",
            "sip:alice@evil.example",
            REALM,
            4,
            &authorization_line("alice", REALM, "s3cret", &nonce, "00000001"),
        ),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    assert!(drain(&mut rx)[0].starts_with("SIP/2.0 200 OK"));
    assert_eq!(identity_events(&sbc).len(), events_before + 1, "reported");

    // With served_domains configured, a foreign host is refused
    let mut closed = SbcBuilder::new()
        .digest_users(REALM, &[("alice", "s3cret")])
        .identity_policy(IdentityPolicy {
            served_domains: vec!["sip.example.com".into()],
            ..IdentityPolicy::default()
        })
        .build();
    closed
        .handle_request(
            register_request_for("alice", "sip:alice@evil.example", REALM, 1, ""),
            local_addr(),
            rsip::Transport::Udp,
            Some(&tx),
        )
        .await
        .unwrap();
    let nonce = nonce_of(&drain(&mut rx)[0]);
    closed
        .handle_request(
            register_request_for(
                "alice",
                "sip:alice@evil.example",
                REALM,
                2,
                &authorization_line("alice", REALM, "s3cret", &nonce, "00000001"),
            ),
            local_addr(),
            rsip::Transport::Udp,
            Some(&tx),
        )
        .await
        .unwrap();
    assert!(drain(&mut rx)[0].starts_with("SIP/2.0 403 "));

    // Own user at the SBC's loopback address (Linphone-style IP AOR): fine
    sbc.handle_request(
        register_request_for("alice", "sip:alice@127.0.0.1", REALM, 5, ""),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let nonce = nonce_of(&drain(&mut rx)[0]);
    sbc.handle_request(
        register_request_for(
            "alice",
            "sip:alice@127.0.0.1",
            REALM,
            6,
            &authorization_line("alice", REALM, "s3cret", &nonce, "00000001"),
        ),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    assert!(drain(&mut rx)[0].starts_with("SIP/2.0 200 OK"));

    // register_aor_check = log: reported, allowed
    let mut lenient = SbcBuilder::new()
        .digest_users(REALM, &[("alice", "s3cret")])
        .identity_policy(IdentityPolicy {
            enforce_register_aor: false,
            ..IdentityPolicy::default()
        })
        .build();
    lenient
        .handle_request(
            register_request_for("alice", "sip:bob@sip.example.com", REALM, 1, ""),
            local_addr(),
            rsip::Transport::Udp,
            Some(&tx),
        )
        .await
        .unwrap();
    let nonce = nonce_of(&drain(&mut rx)[0]);
    lenient
        .handle_request(
            register_request_for(
                "alice",
                "sip:bob@sip.example.com",
                REALM,
                2,
                &authorization_line("alice", REALM, "s3cret", &nonce, "00000001"),
            ),
            local_addr(),
            rsip::Transport::Udp,
            Some(&tx),
        )
        .await
        .unwrap();
    assert!(drain(&mut rx)[0].starts_with("SIP/2.0 200 OK"));
    assert_eq!(identity_events(&lenient).len(), 1, "still reported");
}

/// A registered source presents its own From, or nothing.
#[tokio::test]
async fn invite_from_a_registered_source_must_carry_its_own_from() {
    const REALM: &str = "sip.example.com";
    let phone: SocketAddr = "10.0.0.9:5080".parse().unwrap();
    let mut sbc = SbcBuilder::new()
        .digest_users(REALM, &[("alice", "s3cret"), ("bob", "b0b")])
        .build();
    register(&mut sbc, "alice", "s3cret", REALM, phone).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // From bob, from alice's phone: refused, flagged, not a scanner strike
    sbc.handle_invite(
        invite_from_user("bob", REALM, "+33612345678", ""),
        phone,
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1, "403 only: {:?}", out);
    assert!(
        out[0].starts_with("SIP/2.0 403 Forbidden\r\n"),
        "{}",
        out[0]
    );
    assert!(sbc.b2bua.calls_locked().await.is_empty());
    assert_eq!(sbc.media.stats().allocated_ports, 0);
    assert_eq!(
        identity_events(&sbc),
        vec![("alice".to_string(), "bob".to_string(), "INVITE".to_string())]
    );
    assert_eq!(strike_count(&sbc), 0);

    // From alice: admitted (100 Trying; the forward fails in the harness → 503)
    sbc.handle_invite(
        invite_from_user("alice", REALM, "+33612345678", ""),
        phone,
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(out[0].starts_with("SIP/2.0 100 Trying\r\n"), "{:?}", out);
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(
        cdrs[0].caller, "alice",
        "attributed to the verified identity"
    );
}

/// An unregistered source claiming a local user must prove it (407), as
/// a REGISTER would; then it is that user.
#[tokio::test]
async fn unregistered_source_claiming_a_local_user_is_challenged_407() {
    const REALM: &str = "sip.example.com";
    let stranger: SocketAddr = "198.51.100.7:5060".parse().unwrap();
    let mut sbc = SbcBuilder::new()
        .digest_users(REALM, &[("alice", "s3cret")])
        .build();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    sbc.handle_invite(
        invite_from_user("alice", REALM, "+33612345678", ""),
        stranger,
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1, "{:?}", out);
    assert!(
        out[0].starts_with("SIP/2.0 407 Proxy Authentication Required\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("Proxy-Authenticate: Digest realm=\"sip.example.com\", nonce=\""));
    assert!(out[0].contains("CSeq: 1 INVITE\r\n"));
    assert_eq!(strike_count(&sbc), 0, "a challenge is not a strike");
    assert!(
        sbc.b2bua.calls_locked().await.is_empty(),
        "no state before proof"
    );
    let nonce = nonce_of(&out[0]);
    let uri = format!("sip:+33612345678@{}", REALM);

    // Wrong password: 403 + strike
    sbc.handle_invite(
        invite_from_user_tx(
            "alice",
            REALM,
            "+33612345678",
            &proxy_authorization_line("alice", REALM, "wrong", &nonce, &uri, "00000001"),
            2,
        ),
        stranger,
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(
        out[0].starts_with("SIP/2.0 403 Forbidden\r\n"),
        "{}",
        out[0]
    );
    assert_eq!(strike_count(&sbc), 1);

    // Right password: admitted as alice
    sbc.handle_invite(
        invite_from_user_tx(
            "alice",
            REALM,
            "+33612345678",
            &proxy_authorization_line("alice", REALM, "s3cret", &nonce, &uri, "00000002"),
            3,
        ),
        stranger,
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(out[0].starts_with("SIP/2.0 100 Trying\r\n"), "{:?}", out);
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].caller, "alice");
    assert_eq!(cdrs[0].source_ip, "198.51.100.7");

    // Proving to be alice while presenting bob: refused, flagged
    let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();
    sbc.handle_invite(
        invite_from_user_tx("bob", REALM, "+33612345678", "", 4),
        stranger,
        rsip::Transport::Udp,
        Some(&tx2),
    )
    .await
    .unwrap();
    let out = drain(&mut rx2);
    assert!(
        out[0].starts_with("SIP/2.0 403 "),
        "bob is nobody here → scanner: {}",
        out[0]
    );
}

/// Nobody but a trunk (or a host of its /24) calls our registered users.
#[tokio::test]
async fn unknown_source_reaches_a_registered_user_only_from_a_trunk_subnet() {
    const REALM: &str = "sip.example.com";
    let phone: SocketAddr = "10.0.0.9:5080".parse().unwrap();
    let mut sbc = SbcBuilder::new()
        .digest_users(REALM, &[("bob", "b0b")])
        .build();
    register(&mut sbc, "bob", "b0b", REALM, phone).await;
    register_trunk_ip(&sbc).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let call_bob = |tx| invite_from_trunk_tx("sip:+33699000000@example.net", "bob", 70, tx);

    // Random Internet host: 403 + strike
    sbc.handle_invite(
        call_bob(1),
        "198.51.100.7:5060".parse().unwrap(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(out[0].starts_with("SIP/2.0 403 "), "{}", out[0]);
    assert_eq!(strike_count(&sbc), 1);

    // Sibling host of the trunk's /24: a trunk
    sbc.handle_invite(
        call_bob(2),
        "203.0.113.42:5060".parse().unwrap(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(out[0].starts_with("SIP/2.0 100 Trying\r\n"), "{:?}", out);
    assert_eq!(strike_count(&sbc), 1);
}

/// A trunk that presents one of our users is flagged (and refused when
/// `trunk_local_from = reject`); the call is never attributed to the user.
#[tokio::test]
async fn trunk_invite_presenting_a_local_user_is_flagged() {
    const REALM: &str = "sip.example.com";
    let mut sbc = SbcBuilder::new()
        .digest_users(REALM, &[("alice", "s3cret")])
        .build();
    register_trunk_ip(&sbc).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    sbc.handle_invite(
        invite_from_trunk_as("sip:alice@sip.example.com", "+33999000111", 70),
        trunk_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(
        out[0].starts_with("SIP/2.0 100 Trying\r\n"),
        "relayed: {:?}",
        out
    );
    assert_eq!(
        identity_events(&sbc),
        vec![(
            "trunk".to_string(),
            "sip:alice@sip.example.com".to_string(),
            "INVITE".to_string()
        )]
    );
    assert_eq!(
        sbc.b2bua.active_calls_for_user("alice").await,
        0,
        "never counted against alice"
    );

    let mut strict = SbcBuilder::new()
        .digest_users(REALM, &[("alice", "s3cret")])
        .identity_policy(IdentityPolicy {
            reject_trunk_local_from: true,
            ..IdentityPolicy::default()
        })
        .build();
    register_trunk_ip(&strict).await;
    strict
        .handle_invite(
            invite_from_trunk_as("sip:alice@sip.example.com", "+33999000111", 70),
            trunk_addr(),
            rsip::Transport::Udp,
            Some(&tx),
        )
        .await
        .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 1);
    assert!(out[0].starts_with("SIP/2.0 403 "), "{}", out[0]);
    assert_eq!(strike_count(&strict), 0, "a trunk is never banned for it");

    // A PSTN caller whose number is not a local user: nothing flagged
    sbc.handle_invite(
        invite_from_trunk_tx("sip:+33612345678@203.0.113.9", "+33999000111", 70, 2),
        trunk_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let _ = drain(&mut rx);
    assert_eq!(identity_events(&sbc).len(), 1);
}

/// A registered user's asserted identities never reach the trunk; its
/// verified From does.
#[tokio::test]
async fn local_users_asserted_identity_headers_never_reach_the_trunk() {
    const REALM: &str = "sip.example.com";
    let phone: SocketAddr = "10.0.0.9:5080".parse().unwrap();
    let mut sbc = SbcBuilder::new()
        .identity("127.0.0.1", 5060)
        .digest_users(REALM, &[("alice", "s3cret")])
        .build();
    sbc.start(&udp_loopback(), None).await.unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut trunk = crate::routing::TrunkConfig::new("loop".to_string());
    trunk.host = "127.0.0.1".to_string();
    trunk.port = peer_addr.port();
    sbc.add_trunk(trunk);
    assert!(sbc.trunk_manager.disable_trunk(&trunk_id(&sbc)));
    register(&mut sbc, "alice", "s3cret", REALM, phone).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    sbc.handle_invite(
        invite_from_user(
            "alice",
            REALM,
            "+33612345678",
            "P-Asserted-Identity: <sip:+33100000000@sip.example.com>\r\nP-Preferred-Identity: <sip:ceo@sip.example.com>\r\nRemote-Party-ID: <sip:boss@sip.example.com>;party=calling\r\nProxy-Authorization: Digest username=\"alice\", realm=\"sip.example.com\", nonce=\"n\", uri=\"sip:x\", response=\"00\"\r\n",
        ),
        phone,
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert!(out[0].starts_with("SIP/2.0 100 Trying\r\n"), "{:?}", out);

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
        .await
        .expect("the INVITE reaches the trunk")
        .unwrap();
    let invite = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(invite.starts_with("INVITE sip:"), "{}", invite);
    assert!(!invite.contains("P-Asserted-Identity"), "{}", invite);
    assert!(!invite.contains("P-Preferred-Identity"), "{}", invite);
    assert!(!invite.contains("Remote-Party-ID"), "{}", invite);
    assert!(
        !invite.to_lowercase().contains("authorization"),
        "the user's Digest never travels to the carrier: {}",
        invite
    );
    assert!(
        invite.contains("From: <sip:alice@sip.example.com>;tag=alice-tag\r\n"),
        "the verified From is what the trunk sees: {}",
        invite
    );
}

/// A destination the SBC itself blocks is billed as refused by the SBC on
/// an outbound attempt, and the final reaches a retransmitted INVITE.
#[tokio::test]
async fn blocked_destination_is_refused_by_the_sbc_and_billed_outbound() {
    let mut sbc = SbcBuilder::new().build();
    sbc.security
        .destinations
        .add_rule(crate::security::DestinationRule {
            id: "t-premium".into(),
            prefix: "+33899".into(),
            deny: true,
            user: None,
            description: "premium".into(),
            enabled: true,
        });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    sbc.handle_invite(
        invite_from_local("+33899000000", ""),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let out = drain(&mut rx);
    assert_eq!(out.len(), 2, "100 then 403: {:?}", out);
    assert!(
        out[1].starts_with("SIP/2.0 403 Forbidden\r\n"),
        "{}",
        out[1]
    );
    let cdrs = sbc.cdr.get_recent(10).await.unwrap();
    assert_eq!(cdrs.len(), 1);
    assert_eq!(cdrs[0].disconnect_reason, "rejected-403");
    assert_eq!(
        cdrs[0].hangup_by, "sbc",
        "the SBC refused it, not the far end"
    );
    assert_eq!(
        cdrs[0].direction, "outbound",
        "known before any trunk was picked"
    );
    assert_eq!(cdrs[0].sip_code, Some(403));

    // The same INVITE again (lost 403) gets the 403 again, not a new call.
    sbc.handle_invite(
        invite_from_local("+33899000000", ""),
        local_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let again = drain(&mut rx);
    assert_eq!(again.len(), 1, "{:?}", again);
    assert!(again[0].starts_with("SIP/2.0 403 "));
    assert_eq!(sbc.cdr.get_recent(10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn trunk_state_and_metrics_follow_real_calls() {
    let mut sbc = SbcBuilder::new().build();
    let tid = trunk_id(&sbc);
    let trunk_cfg = sbc.trunk_manager.get_trunk(&tid).unwrap();
    let state = |sbc: &Sbc| sbc.trunk_manager.get_state(&tid).unwrap();
    let series = |sbc: &Sbc| sbc.metrics.trunk_series(TRUNK_NAME).unwrap();
    let outbound = |sbc: &Sbc, outcome: &'static str| {
        series(sbc)
            .calls
            .get(&("outbound".to_string(), outcome))
            .copied()
            .unwrap_or(0)
    };

    // 1. An answered call is counted on the trunk while it lives; the 200
    //    OK resets an earlier failure; the BYE releases it and counts the
    //    outcome and the timing histograms.
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    assert_eq!(state(&sbc).active_calls, 1);
    assert_eq!(series(&sbc).active_calls, 1);
    sbc.trunk_manager
        .update_state(&tid, |s| s.record_trunk_failure());
    assert_eq!(state(&sbc).consecutive_failures, 1);
    connect(&mut sbc, &mut call).await;
    assert_eq!(
        state(&sbc).consecutive_failures,
        0,
        "200 OK resets failures"
    );
    sbc.handle_bye(
        bye_from_caller(&call.spec, 4),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();
    let s = state(&sbc);
    assert_eq!((s.active_calls, s.total_calls), (0, 1));
    assert_eq!(series(&sbc).active_calls, 0);
    assert_eq!(outbound(&sbc, "answered"), 1);
    assert_eq!(sbc.metrics.call_setup_seconds.count(), 1);
    assert_eq!(sbc.metrics.call_duration_seconds.count(), 1);

    // 2. 503 Retry-After from the trunk: relayed to the caller, the trunk
    //    is parked for that long (the router skips it) and the outcome is
    //    a failure.
    let mut call2 = add_call(&mut sbc, CallSpec::numbered(2)).await;
    assert_eq!(state(&sbc).active_calls, 1);
    sbc.handle_response(
        response_for(
            &call2.spec,
            "503 Service Unavailable",
            &call2.spec.branch,
            call2.spec.cseq,
            "INVITE",
            "Retry-After: 120\r\n",
            "",
        ),
        trunk_addr(),
        rsip::Transport::Udp,
        None,
    )
    .await
    .unwrap();
    let to_caller = drain(&mut call2.caller_rx);
    assert!(
        to_caller.iter().any(|m| m.starts_with("SIP/2.0 503 ")),
        "{:?}",
        to_caller
    );
    let s = state(&sbc);
    assert_eq!(s.active_calls, 0, "released on the final");
    assert_eq!(s.consecutive_failures, 1);
    let parked = s
        .unavailable_for(std::time::Instant::now())
        .unwrap_or_default();
    assert!(parked > Duration::from_secs(100), "parked for {:?}", parked);
    assert!(!s.can_accept_call(&trunk_cfg), "no new call routed there");
    assert_eq!(outbound(&sbc, "failed"), 1);
    assert_eq!(
        sbc.metrics.call_setup_seconds.count(),
        1,
        "setup time is measured on answered calls only"
    );

    // 3. 486 Busy Here is the callee's answer, not the trunk's failure:
    //    relayed, counted as rejected (not answered, for ASR), no cooldown.
    //    (The park from step 2 survives a 200 OK: only a re-enable lifts it.)
    sbc.trunk_manager.update_state(&tid, |s| s.record_success());
    assert!(!state(&sbc).can_accept_call(&trunk_cfg), "still parked");
    sbc.trunk_manager
        .update_state(&tid, |s| s.clear_cooldowns());
    assert!(
        state(&sbc).can_accept_call(&trunk_cfg),
        "re-enable forgives"
    );
    let mut call3 = add_call(&mut sbc, CallSpec::numbered(3)).await;
    sbc.handle_response(
        response_for(
            &call3.spec,
            "486 Busy Here",
            &call3.spec.branch,
            call3.spec.cseq,
            "INVITE",
            "",
            "",
        ),
        trunk_addr(),
        rsip::Transport::Udp,
        None,
    )
    .await
    .unwrap();
    assert!(drain(&mut call3.caller_rx)
        .iter()
        .any(|m| m.starts_with("SIP/2.0 486 ")));
    let s = state(&sbc);
    assert_eq!((s.active_calls, s.consecutive_failures), (0, 0));
    assert!(s.disabled_until.is_none());
    assert_eq!(outbound(&sbc, "rejected"), 1);
    assert_eq!(outbound(&sbc, "failed"), 1, "unchanged");

    // 3b. Three 603 Declines in a row (a 6xx, so a failover candidate would
    //     be tried) never cool the trunk: not in the strike set.
    for n in 10..13 {
        let mut c = add_call(&mut sbc, CallSpec::numbered(n)).await;
        sbc.handle_response(
            response_for(
                &c.spec,
                "603 Decline",
                &c.spec.branch,
                c.spec.cseq,
                "INVITE",
                "",
                "",
            ),
            trunk_addr(),
            rsip::Transport::Udp,
            None,
        )
        .await
        .unwrap();
        drain(&mut c.caller_rx);
    }
    let s = state(&sbc);
    assert_eq!(s.consecutive_failures, 0, "603 is the callee's answer");
    assert!(s.can_accept_call(&trunk_cfg));
    assert_eq!(outbound(&sbc, "rejected"), 4);

    // 4. A CANCEL is its own outcome.
    let mut call4 = add_call(&mut sbc, CallSpec::numbered(4)).await;
    sbc.handle_cancel(
        cancel_from_caller(&call4.spec),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call4.caller_tx),
    )
    .await
    .unwrap();
    drain(&mut call4.caller_rx);
    assert_eq!(state(&sbc).active_calls, 0);
    assert_eq!(outbound(&sbc, "cancelled"), 1);

    // Exposition: the series carry the trunk label.
    let out = sbc.metrics.render_prometheus();
    assert!(
        out.contains(&format!(
            "sbc_trunk_calls_total{{trunk=\"{}\",direction=\"outbound\",outcome=\"answered\"}} 1\n",
            TRUNK_NAME
        )),
        "{}",
        out
    );
    assert!(out.contains(&format!(
        "sbc_trunk_active_calls{{trunk=\"{}\"}} 0\n",
        TRUNK_NAME
    )));
}

// ── Logging: the `call` span ─────────────────────────────────────────────────

fn sbc_lines(lines: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    lines
        .iter()
        .filter(|l| {
            l["target"]
                .as_str()
                .is_some_and(|t| t.starts_with("sbc_core::"))
        })
        .collect()
}

#[tokio::test]
async fn every_log_line_of_a_dispatched_message_carries_the_call_span() {
    let buf = log_capture::Buf::default();
    let _guard = log_capture::install(buf.clone());
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;
    buf.clear();

    // The BYE goes through dispatch: every line of its handling is in the span.
    feed(
        &mut sbc,
        rsip::SipMessage::Request(bye_from_caller(&call.spec, 4)),
        caller_addr(),
        Some(&call.caller_tx),
    )
    .await
    .unwrap();
    let lines = buf.lines();
    let ours = sbc_lines(&lines);
    assert!(!ours.is_empty());
    for l in &ours {
        assert_eq!(l["span"]["name"], "call", "{}", l);
        assert_eq!(l["span"]["uuid"], call.uuid.as_str(), "{}", l);
        assert_eq!(l["span"]["call_id"], "cid-1", "{}", l);
        assert_eq!(l["span"]["trunk"], TRUNK_NAME, "{}", l);
    }
    assert!(
        ours.iter()
            .any(|l| l["message"].as_str().is_some_and(|m| m.starts_with("CDR:"))),
        "the CDR line is inside the span"
    );
    assert!(!alive(&sbc).await);
}

#[tokio::test]
async fn a_new_inbound_invite_records_uuid_trunk_and_direction_as_they_are_known() {
    let buf = log_capture::Buf::default();
    let _guard = log_capture::install(buf.clone());
    let mut sbc = SbcBuilder::new().build();
    register_trunk_ip(&sbc).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    feed(
        &mut sbc,
        rsip::SipMessage::Request(invite_from_trunk("+33999000111", 70)),
        trunk_addr(),
        Some(&tx),
    )
    .await
    .unwrap();
    assert!(drain(&mut rx).iter().any(|m| m.starts_with("SIP/2.0 404 ")));
    let lines = buf.lines();
    let ours = sbc_lines(&lines);
    assert!(
        ours.iter().all(|l| l["span"]["call_id"] == "cid-in-1"),
        "{:#?}",
        ours
    );
    let first = ours.first().unwrap();
    assert!(
        first["span"]["uuid"].is_null(),
        "uuid unknown before the call exists: {}",
        first
    );
    let recorded: Vec<_> = ours
        .iter()
        .filter(|l| l["span"]["uuid"].is_string())
        .collect();
    assert!(!recorded.is_empty(), "lines after creation carry the uuid");
    let last = recorded.last().unwrap();
    assert_eq!(last["span"]["trunk"], TRUNK_NAME, "{}", last);
    assert_eq!(last["span"]["direction"], "inbound", "{}", last);
}

#[tokio::test]
async fn trunk_task_traffic_has_no_span_and_no_info_line() {
    let buf = log_capture::Buf::default();
    let _guard = log_capture::install(buf.clone());
    let mut sbc = SbcBuilder::new().build();
    register_trunk_ip(&sbc).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let options = request(
        "OPTIONS sip:127.0.0.1:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKopt1\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:ping@203.0.113.9>;tag=o1\r\n\
         To: <sip:127.0.0.1>\r\n\
         Call-ID: opt-1\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n"
            .to_string(),
    );
    feed(
        &mut sbc,
        rsip::SipMessage::Request(options),
        trunk_addr(),
        Some(&tx),
    )
    .await
    .unwrap();
    assert!(drain(&mut rx)[0].starts_with("SIP/2.0 200 OK"));
    let hc = rsip::SipMessage::try_from(
        "SIP/2.0 200 OK\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKhc1\r\n\
         From: <sip:healthcheck@127.0.0.1>;tag=h1\r\n\
         To: <sip:203.0.113.9:5060>;tag=t1\r\n\
         Call-ID: hc-genesys-1\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n",
    )
    .unwrap();
    feed(&mut sbc, hc, trunk_addr(), None).await.unwrap();
    let lines = buf.lines();
    let ours = sbc_lines(&lines);
    assert!(!ours.is_empty());
    for l in &ours {
        assert!(
            l.get("span").is_none(),
            "no call span for trunk traffic: {}",
            l
        );
        assert_ne!(l["level"], "INFO", "no info noise every 30 s: {}", l);
    }
}

#[tokio::test]
async fn a_normal_call_stays_within_the_info_budget() {
    let buf = log_capture::Buf::default();
    let _guard = log_capture::install(buf.clone());
    let mut sbc = SbcBuilder::new().build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    buf.clear();
    connect(&mut sbc, &mut call).await;
    feed(
        &mut sbc,
        rsip::SipMessage::Request(bye_from_caller(&call.spec, 4)),
        caller_addr(),
        Some(&call.caller_tx),
    )
    .await
    .unwrap();
    let lines = buf.lines();
    let info: Vec<_> = sbc_lines(&lines)
        .into_iter()
        .filter(|l| l["level"] == "INFO")
        .collect();
    assert!(
        info.len() <= 10,
        "{} INFO lines from answer to CDR (budget 10): {:#?}",
        info.len(),
        info.iter()
            .map(|l| l["message"].clone())
            .collect::<Vec<_>>()
    );
    for l in &info {
        let msg = l["message"].as_str().unwrap_or("");
        assert!(!msg.contains('\n'), "no bodies at info: {}", msg);
    }
}

// ── Reload ───────────────────────────────────────────────────────────────────

fn write_temp_toml(cfg: &SbcConfig) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sbc-reload-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sbc.toml");
    std::fs::write(&path, toml::to_string(cfg).unwrap()).unwrap();
    path
}

/// `security.max_call_duration = 0` is documented as "unlimited": it must
/// not be clamped to the 60 s floor that protects the other values.
#[tokio::test]
async fn max_call_duration_zero_means_unlimited() {
    use crate::sbc::runtime_config::ReloadSource;
    let mut sbc = SbcBuilder::new().build();
    let mut cfg = SbcConfig::default();
    cfg.security.max_call_duration = 0;
    let path = write_temp_toml(&cfg);
    sbc.set_config_path(path.to_string_lossy().into_owned());
    let report = sbc.reload_config(ReloadSource::Api).await.unwrap();
    assert!(report.ok, "{:?}", report);
    assert_eq!(sbc.max_call_duration, Duration::MAX);

    // A 30 s value is still floored at 60 s (a typo must not cut calls).
    cfg.security.max_call_duration = 30;
    std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();
    assert!(sbc.reload_config(ReloadSource::Api).await.unwrap().ok);
    assert_eq!(sbc.max_call_duration, Duration::from_secs(60));
}

#[tokio::test]
async fn reload_applies_every_reload_class_key_from_the_toml() {
    use crate::sbc::runtime_config::ReloadSource;
    let mut sbc = SbcBuilder::new().build();
    let mut cfg = SbcConfig::default();
    cfg.security.rate_limit_per_ip = 7;
    cfg.security.rtp_timeout = 45;
    cfg.security.invite_timeout = 9;
    cfg.security.max_call_duration = 600;
    cfg.security.call_setup_timeout = 30;
    cfg.security.session_timer_enabled = true;
    cfg.security.session_expires = 14400;
    cfg.security.min_se = 90;
    cfg.security.trunk_local_from = "reject".into();
    cfg.security.features.ban.max_failures = 2;
    cfg.security.features.destinations.default_action = "deny".into();
    cfg.security.features.user_limits.enabled = false;
    cfg.security
        .features
        .user_limits
        .default_max_concurrent_calls = 2;
    cfg.security
        .features
        .user_limits
        .default_max_calls_per_minute = 3;
    let path = write_temp_toml(&cfg);
    sbc.set_config_path(path.to_string_lossy().into_owned());
    let mut events = sbc.events().subscribe();

    let report = sbc.reload_config(ReloadSource::Api).await.unwrap();
    assert!(report.ok && !report.hydrated);
    assert!(report.restart_required.is_empty(), "{:?}", report);
    for key in [
        "security.rate_limit_per_ip",
        "security.rtp_timeout",
        "security.invite_timeout",
        "security.max_call_duration",
        "security.call_setup_timeout",
        "security.session_timer",
        "security.identity",
        "security.ban",
        "security.destinations",
        "security.user_limits",
    ] {
        assert!(
            report.applied.iter().any(|k| k == key),
            "{} in {:?}",
            key,
            report.applied
        );
    }
    assert_eq!(sbc.dos.config().requests_per_second, 7);
    assert_eq!(sbc.media.rtp_timeout(), 45);
    assert_eq!(sbc.invite_timeout, Duration::from_secs(9));
    assert_eq!(sbc.max_call_duration, Duration::from_secs(600));
    assert_eq!(sbc.call_setup_timeout, Duration::from_secs(30));
    assert_eq!(sbc.session_timer, Some((14400, 90)));
    assert!(sbc.identity_policy.reject_trunk_local_from);
    assert_eq!(sbc.security.bans.config().max_failures, 2);
    assert!(sbc.security.destinations.default_action_deny());
    assert!(!sbc.security.user_limits.is_enabled());
    assert_eq!(sbc.security.user_limits.defaults(), (2, 3));
    assert_eq!(sbc.runtime_config().effective().security.rtp_timeout, 45);
    assert!(matches!(
        events.try_recv(),
        Ok(crate::events::SbcEvent::ConfigChanged { ref entity, ref action, .. }) if entity == "runtime" && action == "reloaded"
    ));

    // A second reload of the same file applies nothing new.
    let again = sbc.reload_config(ReloadSource::Sighup).await.unwrap();
    assert!(again.applied.is_empty(), "{:?}", again.applied);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn reload_reports_restart_required_and_a_broken_file_changes_nothing() {
    use crate::sbc::runtime_config::ReloadSource;
    let mut sbc = SbcBuilder::new().build();
    let mut cfg = SbcConfig::default();
    cfg.security.sip_realm = "other.example".into();
    cfg.management.api_port += 1;
    let path = write_temp_toml(&cfg);
    sbc.set_config_path(path.to_string_lossy().into_owned());
    let report = sbc.reload_config(ReloadSource::Api).await.unwrap();
    assert_eq!(
        report.restart_required,
        vec!["management.api_port", "security.sip_realm"]
    );
    assert_eq!(
        sbc.runtime_config().effective().security.sip_realm,
        SbcConfig::default().security.sip_realm,
        "restart keys keep the boot value"
    );

    let before = sbc.max_call_duration;
    std::fs::write(&path, "[security]\nmax_call_duration = \"x\"\n").unwrap();
    let mut events = sbc.events().subscribe();
    let err = sbc.reload_config(ReloadSource::Sighup).await.unwrap_err();
    assert!(err.to_string().contains("parse"), "{}", err);
    assert_eq!(sbc.max_call_duration, before);
    let last = sbc.runtime_config().last_reload().unwrap();
    assert!(!last.ok && last.error.is_some());
    assert_eq!(sbc.metrics.config_reloads.lock().unwrap()["error"], 1);
    assert!(matches!(
        events.try_recv(),
        Ok(crate::events::SbcEvent::ConfigChanged { ref action, .. }) if action == "reload_failed"
    ));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn reload_keeps_api_set_user_limit_defaults_over_the_toml() {
    use crate::sbc::runtime_config::ReloadSource;
    let mut sbc = SbcBuilder::new().build();
    let store = sbc_storage::ConfigStore::open_memory().await.unwrap();
    store
        .set_setting(super::hydrate::SETTING_DEFAULT_CONCURRENT, "9")
        .await
        .unwrap();
    store
        .set_setting(super::hydrate::SETTING_DEFAULT_CPM, "99")
        .await
        .unwrap();
    sbc.config_store = Some(Arc::new(store));
    let mut cfg = SbcConfig::default();
    cfg.security
        .features
        .user_limits
        .default_max_concurrent_calls = 4;
    cfg.security
        .features
        .user_limits
        .default_max_calls_per_minute = 10;
    let path = write_temp_toml(&cfg);
    sbc.set_config_path(path.to_string_lossy().into_owned());
    let report = sbc.reload_config(ReloadSource::Api).await.unwrap();
    assert!(report.hydrated);
    assert_eq!(
        sbc.security.user_limits.defaults(),
        (9, 99),
        "the store wins"
    );
    assert!(!report.applied.iter().any(|k| k == "security.user_limits"));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

// ── Registrar ────────────────────────────────────────────────────────────────

/// Send `req` from `source`, return what the SBC answered.
async fn register_raw(sbc: &mut Sbc, req: rsip::Request, source: SocketAddr) -> Vec<String> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    sbc.handle_request(req, source, rsip::Transport::Udp, Some(&tx))
        .await
        .unwrap();
    drain(&mut rx)
}

fn registrations(sbc: &Sbc) -> u64 {
    sbc.metrics
        .active_registrations
        .load(std::sync::atomic::Ordering::Relaxed)
}

#[tokio::test]
async fn register_below_min_expires_is_423_with_min_expires() {
    let mut sbc = SbcBuilder::new().build();
    let aor = "sip:alice@sip.example.com";
    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            1,
            "c-1",
            "Contact: <sip:alice@127.0.0.1:5080>\r\n",
            "Expires: 10\r\n",
            "",
        ),
        local_addr(),
    )
    .await;
    assert!(
        out[0].starts_with("SIP/2.0 423 Interval Too Brief\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("Min-Expires: 60\r\n"), "{}", out[0]);
    assert!(out[0].contains("CSeq: 1 REGISTER\r\n"));
    assert!(sbc.register_handler.lookup(aor).await.unwrap().is_empty());
    assert_eq!(registrations(&sbc), 0);
    // The contact parameter form too.
    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            2,
            "c-1",
            "Contact: <sip:alice@127.0.0.1:5080>;expires=10\r\n",
            "",
            "",
        ),
        local_addr(),
    )
    .await;
    assert!(out[0].starts_with("SIP/2.0 423 "), "{}", out[0]);
    // Retry at the minimum.
    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            3,
            "c-1",
            "Contact: <sip:alice@127.0.0.1:5080>\r\n",
            "Expires: 60\r\n",
            "",
        ),
        local_addr(),
    )
    .await;
    assert!(out[0].starts_with("SIP/2.0 200 OK"), "{}", out[0]);
    assert!(
        out[0].contains("<sip:alice@127.0.0.1:5080>;expires=60\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("Expires: 60\r\n"));
    assert_eq!(registrations(&sbc), 1);
}

#[tokio::test]
async fn register_above_max_expires_is_clamped_and_a_query_lists_bindings() {
    let mut sbc = SbcBuilder::new()
        .register_policy(crate::register::RegisterPolicy {
            max_expires: 1800,
            ..Default::default()
        })
        .build();
    let aor = "sip:alice@sip.example.com";
    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            1,
            "c-1",
            "Contact: <sip:alice@127.0.0.1:5080>\r\n",
            "Expires: 86400\r\n",
            "",
        ),
        local_addr(),
    )
    .await;
    assert!(
        out[0].contains("<sip:alice@127.0.0.1:5080>;expires=1800\r\n"),
        "{}",
        out[0]
    );
    assert!(out[0].contains("Expires: 1800\r\n"));
    // Query: no Contact, no Expires → the bindings, no Expires header.
    let out = register_raw(
        &mut sbc,
        register_request_with(aor, "sip.example.com", 2, "c-1", "", "", ""),
        local_addr(),
    )
    .await;
    assert!(out[0].starts_with("SIP/2.0 200 OK"), "{}", out[0]);
    assert!(
        out[0].contains("Contact: <sip:alice@127.0.0.1:5080>;expires="),
        "{}",
        out[0]
    );
    assert!(!out[0].contains("\r\nExpires:"), "{}", out[0]);
    assert_eq!(registrations(&sbc), 1);
}

#[tokio::test]
async fn two_phones_behind_one_nat_keep_their_own_bindings() {
    let mut sbc = SbcBuilder::new().build();
    let mut events = sbc.events().subscribe();
    let aor = "sip:bob@sip.example.com";
    let nat_a: SocketAddr = "10.0.0.9:5080".parse().unwrap();
    let nat_b: SocketAddr = "10.0.0.9:5081".parse().unwrap();
    register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            1,
            "c-a",
            "Contact: <sip:bob@192.168.1.10:5060>\r\n",
            "Expires: 3600\r\n",
            "",
        ),
        nat_a,
    )
    .await;
    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            1,
            "c-b",
            "Contact: <sip:bob@192.168.1.11:5060>\r\n",
            "Expires: 3600\r\n",
            "",
        ),
        nat_b,
    )
    .await;
    assert!(
        out[0].contains("<sip:bob@192.168.1.10:5060>;expires="),
        "{}",
        out[0]
    );
    assert!(
        out[0].contains("<sip:bob@192.168.1.11:5060>;expires="),
        "{}",
        out[0]
    );
    assert_eq!(sbc.register_handler.lookup(aor).await.unwrap().len(), 2);
    assert_eq!(registrations(&sbc), 2);
    assert_eq!(
        sbc.metrics
            .registrations_total
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );

    // Phone A unregisters its own contact only.
    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            2,
            "c-a",
            "Contact: <sip:bob@192.168.1.10:5060>;expires=0\r\n",
            "",
            "",
        ),
        nat_a,
    )
    .await;
    assert!(out[0].starts_with("SIP/2.0 200 OK"), "{}", out[0]);
    assert!(!out[0].contains("192.168.1.10"), "{}", out[0]);
    assert!(out[0].contains("<sip:bob@192.168.1.11:5060>;expires="));
    assert_eq!(registrations(&sbc), 1);
    let mut seen_unregistered = false;
    while let Ok(e) = events.try_recv() {
        if let crate::events::SbcEvent::Unregistered {
            contact, reason, ..
        } = e
        {
            assert_eq!(contact, "sip:bob@192.168.1.10:5060");
            assert_eq!(reason, "client");
            seen_unregistered = true;
        }
    }
    assert!(seen_unregistered);
}

#[tokio::test]
async fn nat_rebinding_moves_the_inbound_call_to_the_new_port() {
    let mut sbc = SbcBuilder::new().build();
    sbc.start(&udp_loopback(), None).await.unwrap();
    let phone = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let phone_addr = phone.local_addr().unwrap();
    // The harness trunk INVITE targets sip:bob@127.0.0.1:5060 — the AOR bob registers.
    let aor = "sip:bob@127.0.0.1:5060";
    let old: SocketAddr = "127.0.0.1:5099".parse().unwrap();
    register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "127.0.0.1",
            1,
            "c-1",
            "Contact: <sip:bob@192.168.1.10:5060>\r\n",
            "Expires: 3600\r\n",
            "",
        ),
        old,
    )
    .await;
    register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "127.0.0.1",
            2,
            "c-1",
            "Contact: <sip:bob@192.168.1.10:5060>\r\n",
            "Expires: 3600\r\n",
            "",
        ),
        phone_addr,
    )
    .await;
    let bindings = sbc.register_handler.lookup(aor).await.unwrap();
    assert_eq!(bindings.len(), 1, "same contact = one binding");
    assert_eq!(
        bindings[0].received_port,
        phone_addr.port(),
        "source follows the newest REGISTER"
    );

    register_trunk_ip(&sbc).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    sbc.handle_invite(
        invite_from_trunk("bob", 70),
        trunk_addr(),
        rsip::Transport::Udp,
        Some(&tx),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), phone.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the INVITE never reached the phone; trunk got {:?}",
                drain(&mut rx)
            )
        })
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("INVITE "));
}

#[tokio::test]
async fn contact_params_and_sip_instance_do_not_fork_the_binding() {
    let mut sbc = SbcBuilder::new().build();
    let aor = "sip:alice@sip.example.com";
    register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            1,
            "c-1",
            "Contact: <sip:alice@127.0.0.1:5080>;expires=1800\r\n",
            "",
            "",
        ),
        local_addr(),
    )
    .await;
    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            2,
            "c-1",
            "Contact: <sip:alice@127.0.0.1:5080>;expires=3600\r\n",
            "",
            "",
        ),
        local_addr(),
    )
    .await;
    assert_eq!(sbc.register_handler.lookup(aor).await.unwrap().len(), 1);
    assert_eq!(out[0].matches("expires=").count(), 1, "{}", out[0]);

    // +sip.instance: a new URI from a new port refreshes the one binding.
    let inst = "Contact: <sip:carol@10.0.0.9:5060>;+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-00000000abcd>\";reg-id=1\r\n";
    let carol = "sip:carol@sip.example.com";
    register_raw(
        &mut sbc,
        register_request_with(
            carol,
            "sip.example.com",
            1,
            "c-c",
            inst,
            "Expires: 3600\r\n",
            "",
        ),
        "10.0.0.9:5060".parse().unwrap(),
    )
    .await;
    let inst2 = "Contact: <sip:carol@10.0.0.9:6100>;+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-00000000abcd>\";reg-id=1\r\n";
    let out = register_raw(
        &mut sbc,
        register_request_with(
            carol,
            "sip.example.com",
            2,
            "c-c",
            inst2,
            "Expires: 3600\r\n",
            "",
        ),
        "10.0.0.9:6100".parse().unwrap(),
    )
    .await;
    let bindings = sbc.register_handler.lookup(carol).await.unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].contact, "sip:carol@10.0.0.9:6100");
    assert!(
        out[0].contains(
            ";+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-00000000abcd>\";reg-id=1"
        ),
        "{}",
        out[0]
    );
}

#[tokio::test]
async fn wildcard_register_rules_and_unparsable_contact() {
    let mut sbc = SbcBuilder::new().build();
    let mut events = sbc.events().subscribe();
    let aor = "sip:alice@sip.example.com";
    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            1,
            "c-1",
            "Contact: <sip:alice@127.0.0.1:5080>\r\nContact: <sip:alice@127.0.0.1:5090>\r\n",
            "Expires: 3600\r\n",
            "",
        ),
        local_addr(),
    )
    .await;
    assert!(
        out[0].contains("5080>;expires=") && out[0].contains("5090>;expires="),
        "{}",
        out[0]
    );
    assert_eq!(registrations(&sbc), 2);

    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            2,
            "c-1",
            "Contact: *\r\n",
            "Expires: 3600\r\n",
            "",
        ),
        local_addr(),
    )
    .await;
    assert!(out[0].starts_with("SIP/2.0 400 Bad Request"), "{}", out[0]);
    assert_eq!(registrations(&sbc), 2);

    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            3,
            "c-1",
            "Contact: *\r\n",
            "Expires: 0\r\n",
            "",
        ),
        local_addr(),
    )
    .await;
    assert!(out[0].starts_with("SIP/2.0 200 OK"), "{}", out[0]);
    assert!(!out[0].contains("Contact:"), "{}", out[0]);
    assert_eq!(registrations(&sbc), 0);
    let mut wildcard = 0;
    while let Ok(e) = events.try_recv() {
        if let crate::events::SbcEvent::Unregistered { reason, .. } = e {
            if reason == "wildcard" {
                wildcard += 1;
            }
        }
    }
    assert_eq!(wildcard, 2);

    let out = register_raw(
        &mut sbc,
        register_request_with(
            aor,
            "sip.example.com",
            4,
            "c-1",
            "Contact: garbage<<\r\n",
            "Expires: 3600\r\n",
            "",
        ),
        local_addr(),
    )
    .await;
    assert!(out[0].starts_with("SIP/2.0 400 Bad Request"), "{}", out[0]);
    assert_eq!(registrations(&sbc), 0);
}

// ── CDRs in the store ────────────────────────────────────────────────────────

#[tokio::test]
async fn full_call_with_a_store_writes_the_cdr_to_sqlite() {
    let store = Arc::new(sbc_storage::ConfigStore::open_memory().await.unwrap());
    let mut sbc = SbcBuilder::new().cdr_store(store.clone()).build();
    let mut call = add_call(&mut sbc, CallSpec::default()).await;
    connect(&mut sbc, &mut call).await;
    sbc.handle_bye(
        bye_from_caller(&call.spec, 4),
        caller_addr(),
        rsip::Transport::Udp,
        Some(&call.caller_tx),
    )
    .await
    .unwrap();
    sbc.cdr.flush().await;
    let (rows, more) = store
        .query_cdrs(&sbc_storage::CdrFilter {
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "{:?}", rows);
    assert!(!more);
    let row = &rows[0];
    assert_eq!(row.sip_code, Some(200));
    assert_eq!(row.direction, "outbound");
    assert_eq!(row.trunk_id.as_deref(), Some(TRUNK_NAME));
    assert_eq!(row.uuid, call.uuid);
    assert!(row.answered_at.is_some());
    assert_eq!(
        sbc.cdr.get_recent(10).await.unwrap().len(),
        1,
        "the cache stays synchronous"
    );
    assert_eq!(sbc.cdr.backend(), "sqlite");
    assert!(
        sbc.metrics
            .last_cdr_written_time
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0,
        "stamped after the durable commit"
    );
    sbc.cdr.close(Duration::from_secs(2)).await;
}
