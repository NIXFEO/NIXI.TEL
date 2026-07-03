# WebRTC Demo Client

A minimal browser softphone (SIP.js from CDN, no build step) to test the SBC's
WebRTC gateway: SIP over WSS, DTLS-SRTP media, Opus↔G.711 transcoding to PSTN.

## Prerequisites

1. **A WSS listener with a real certificate.** Browsers refuse WSS to
   self-signed certs. In the SBC config:

   ```toml
   [[network.listeners]]
   transport = "WSS"
   bind_address = "0.0.0.0"
   bind_port = 8443
   cert_file = "/etc/letsencrypt/live/sip.example.com/fullchain.pem"
   key_file  = "/etc/letsencrypt/live/sip.example.com/privkey.pem"
   ```

2. **A SIP user** (via the API):

   ```bash
   curl -X POST https://…:8080/api/v1/users \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"username":"alice","password":"s3cret"}'
   ```

3. **WebRTC enabled** in `[media.webrtc]` (`enabled = true`).

## Run

Serve this directory over HTTPS (getUserMedia requires a secure context):

```bash
cd examples/webrtc-client
python3 -m http.server 8000
# then open https://<your-host>:8000 behind any TLS proxy, or use localhost:
# http://localhost:8000 (localhost counts as a secure context)
```

Fill in the WSS URL (`wss://sip.example.com:8443`), SIP URI
(`sip:alice@sip.example.com`) and password → **Register** → dial a PSTN
number or another registered user → **Call**. The keypad sends RFC 4733
DTMF once the call is established.

## TURN (browsers behind strict NAT)

The SBC itself never needs TURN (it runs on a public IP), so it does not
embed a TURN server. If your users sit behind symmetric NAT/firewalls,
run [coturn](https://github.com/coturn/coturn):

```bash
turnserver -a -u demo:secret -r sip.example.com
```

and add it to the ICE servers field:

```json
[{"urls":"stun:stun.l.google.com:19302"},
 {"urls":"turn:turn.example.com:3478","username":"demo","credential":"secret"}]
```

## Test flow

1. Register two browsers (alice, bob) → browser ↔ browser call.
2. Call a PSTN number → browser → SBC (DTLS-SRTP/Opus) → trunk (RTP/G.711).
3. Press keypad digits against an IVR to validate DTMF end-to-end.
4. Kill the tab mid-call: the SBC sends BYE to the other leg within ~1s
   and the registration is removed until the client re-registers.
