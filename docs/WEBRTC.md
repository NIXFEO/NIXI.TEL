# WebRTC Gateway

The SBC terminates WebRTC on one leg and standard SIP/RTP on the other,
acting as a full B2BUA + media gateway between browsers and PSTN trunks.

## Architecture

```
Browser (SIP.js/JsSIP)                    SBC                        Trunk/PSTN
──────────────────────                 ─────────                   ────────────
SIP over WSS (RFC 7118)  ───────────►  WSS listener
INVITE + SAVPF SDP                     detect WebRTC SDP
                                       ICE (host candidates +
ICE checks ◄──────────────────────►    learned peer address)
DTLS handshake ◄──────────────────►    DTLS-SRTP termination
SRTP/Opus ◄───────────────────────►    decrypt + transcode  ◄────► RTP/G.711
                                       Opus ↔ PCMU/PCMA
```

- **Signaling**: SIP over WebSocket (RFC 7118), WS and WSS listeners.
  Responses and in-dialog requests to a browser reuse its inbound WS
  connection (a browser behind NAT cannot accept connections).
- **Media**: the SBC is an ICE endpoint (host candidates; the browser's
  address is learned from its STUN checks — this makes the SBC
  *trickle-tolerant* without implementing trickle itself), terminates
  DTLS-SRTP, and transcodes Opus ↔ G.711 toward the trunk.
- **Both directions** are supported: browser → PSTN and PSTN → browser
  (the SBC generates the WebRTC SDP offer for the browser leg).

## Supported / not supported

| Feature | Status |
|---|---|
| SIP over WS / WSS (RFC 7118) | ✅ |
| DTLS-SRTP (browser leg) | ✅ |
| SDES-SRTP | ✅ |
| Opus ↔ PCMU/PCMA transcoding | ✅ |
| rtcp-mux | ✅ |
| Trickle ICE from the browser | ✅ tolerated (complete SDP answered) |
| DTMF RFC 4733 with PT re-mapping between legs | ✅ |
| WS disconnect cleanup (BYE + unregister ≤1s) | ✅ |
| TURN server embedded in the SBC | ❌ use external coturn (see below) |
| SBC-initiated outbound WS connections | ❌ by design (peer is behind NAT) |
| Video | ❌ audio only |
| WebRTC DataChannel | ❌ (feature-gated stub) |

## TURN

The SBC runs on a public IP and never needs TURN for itself. Browsers
behind symmetric NAT need a client-side TURN server: run
[coturn](https://github.com/coturn/coturn) and list it in the client's
`iceServers`. The `[media.webrtc] turn_*` config keys are reserved and
currently unused.

## Certificates

WSS requires a certificate the browser trusts (e.g. Let's Encrypt).
Configure `cert_file`/`key_file` on the WSS listener. A certbot renewal
hook can `POST /api/v1/reload` (or send SIGHUP) after renewal.

## Demo client

See [`examples/webrtc-client/`](../examples/webrtc-client/README.md) —
register, call PSTN or another browser, DTMF keypad, no build step.
