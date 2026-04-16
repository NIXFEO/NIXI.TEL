#!/bin/bash
# =============================================================================
# SBC Comprehensive Codec×Transport Test Suite
# =============================================================================
set +e  # Don't exit on errors (tests may fail, that's expected)

SBC_IP="127.0.0.1"
SBC_SIP_PORT=5060
SBC_TLS_PORT=5061
SBC_WSS_PORT=8443
LOCAL_IP="127.0.0.1"
UAS_PORT=5080  # DefaultTrunk points here
UAC_PORT=6060
CALL_DURATION=2000  # ms
TIMEOUT=15
RESULTS_DIR="/tmp/sbc_test_results_$(date +%Y%m%d_%H%M%S)"
SCEN="/tmp/sbc_test_sc"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0

mkdir -p "$RESULTS_DIR" "$SCEN"

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); ((TOTAL++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); ((TOTAL++)); }
log_header(){ echo -e "\n${YELLOW}═══ $1 ═══${NC}"; }

# ── Generate UAC scenario ────────────────────────────────────────────────────
gen_uac() {
    local file=$1 codec_list=$2 rtpmap=$3 fmtp=${4:-} transport=${5:-UDP}
    cat > "$SCEN/$file" << EOF
<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="UAC">
  <send retrans="500">
    <![CDATA[
      INVITE sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/${transport} [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 INVITE
      Contact: <sip:alice@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=alice 53655765 2353687637 IN IP4 [local_ip]
      s=SBC Test
      c=IN IP4 [local_ip]
      t=0 0
      m=audio [media_port] RTP/AVP ${codec_list}
${rtpmap}
${fmtp}
      a=sendrecv
    ]]>
  </send>
  <recv response="100" optional="true" />
  <recv response="180" optional="true" />
  <recv response="200" rtd="true" />
  <send>
    <![CDATA[
      ACK sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/${transport} [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 1 ACK
      Max-Forwards: 70
      Content-Length: 0
    ]]>
  </send>
  <pause milliseconds="${CALL_DURATION}" />
  <send retrans="500">
    <![CDATA[
      BYE sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/${transport} [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 2 BYE
      Max-Forwards: 70
      Content-Length: 0
    ]]>
  </send>
  <recv response="200" crlf="true" />
</scenario>
EOF
}

# ── Generate UAS scenario ────────────────────────────────────────────────────
gen_uas() {
    local file=$1 codec_list=$2 rtpmap=$3 fmtp=${4:-}
    cat > "$SCEN/$file" << EOF
<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="UAS">
  <recv request="INVITE" crlf="true" />
  <send>
    <![CDATA[
      SIP/2.0 180 Ringing
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:bob@[local_ip]:[local_port]>
      Content-Length: 0
    ]]>
  </send>
  <pause milliseconds="300" />
  <send retrans="500">
    <![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:bob@[local_ip]:[local_port]>
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=bob 54321 54321 IN IP4 [local_ip]
      s=SBC Test
      c=IN IP4 [local_ip]
      t=0 0
      m=audio [media_port] RTP/AVP ${codec_list}
${rtpmap}
${fmtp}
      a=sendrecv
    ]]>
  </send>
  <recv request="ACK" crlf="true" />
  <recv request="BYE" />
  <send>
    <![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:]
      [last_Call-ID:]
      [last_CSeq:]
      Content-Length: 0
    ]]>
  </send>
</scenario>
EOF
}

# ── Run one call test ─────────────────────────────────────────────────────────
run_test() {
    local name=$1 uac_file=$2 uas_file=$3 uac_t=${4:-u1} uas_port=${5:-$UAS_PORT} remote_port=${6:-$SBC_SIP_PORT}

    pkill sipp 2>/dev/null || true; sleep 0.5

    # Start UAS
    sipp -sf "$SCEN/$uas_file" -i $LOCAL_IP -p $uas_port -m 1 -timeout ${TIMEOUT}s -bg > /dev/null 2>&1 &
    local uas_pid=$!
    sleep 1

    # Start UAC
    local rc=0
    local transport_flag=""
    if [ "$uac_t" != "u1" ]; then
        transport_flag="-t $uac_t"
    fi
    sipp ${SBC_IP}:${remote_port} \
        -sf "$SCEN/$uac_file" \
        -i $LOCAL_IP -p $UAC_PORT \
        $transport_flag \
        -m 1 -timeout ${TIMEOUT}s \
        > "$RESULTS_DIR/${name}.log" 2>&1 || rc=$?

    wait $uas_pid 2>/dev/null || true
    sleep 0.5

    if [ $rc -eq 0 ]; then
        log_pass "$name"
    else
        log_fail "$name (exit=$rc)"
        # Show last few lines of log for debugging
        tail -3 "$RESULTS_DIR/${name}.log" 2>/dev/null | head -3
    fi
    return 0
}

# ═════════════════════════════════════════════════════════════════════════════
log_header "SBC Codec×Transport Test Suite"
echo -e "${BLUE}SBC:${NC} ${SBC_IP}:${SBC_SIP_PORT}  ${BLUE}Results:${NC} ${RESULTS_DIR}"

# Baseline metrics
curl -sf "http://127.0.0.1:9090/metrics" > "$RESULTS_DIR/metrics_before.txt" 2>/dev/null || true

# ═════════════════════════════════════════════════════════════════════════════
log_header "SECTION 1: SIP↔SIP Codec Combinations (UDP)"

# ── Test 1: PCMU → PCMU ──
gen_uac uac1.xml "0" "      a=rtpmap:0 PCMU/8000"
gen_uas uas1.xml "0" "      a=rtpmap:0 PCMU/8000"
run_test "01_PCMU→PCMU" uac1.xml uas1.xml

# ── Test 2: PCMA → PCMA ──
gen_uac uac2.xml "8" "      a=rtpmap:8 PCMA/8000"
gen_uas uas2.xml "8" "      a=rtpmap:8 PCMA/8000"
run_test "02_PCMA→PCMA" uac2.xml uas2.xml

# ── Test 3: PCMU → PCMA (transcoding) ──
gen_uac uac3.xml "0" "      a=rtpmap:0 PCMU/8000"
gen_uas uas3.xml "8" "      a=rtpmap:8 PCMA/8000"
run_test "03_PCMU→PCMA" uac3.xml uas3.xml

# ── Test 4: PCMA → PCMU (transcoding) ──
gen_uac uac4.xml "8" "      a=rtpmap:8 PCMA/8000"
gen_uas uas4.xml "0" "      a=rtpmap:0 PCMU/8000"
run_test "04_PCMA→PCMU" uac4.xml uas4.xml

# ── Test 5: PCMU → Opus (transcoding) ──
gen_uac uac5.xml "0" "      a=rtpmap:0 PCMU/8000"
gen_uas uas5.xml "111" "      a=rtpmap:111 opus/48000/2" "      a=fmtp:111 minptime=20;useinbandfec=1"
run_test "05_PCMU→Opus" uac5.xml uas5.xml

# ── Test 6: PCMA → Opus (transcoding) ──
gen_uac uac6.xml "8" "      a=rtpmap:8 PCMA/8000"
gen_uas uas6.xml "111" "      a=rtpmap:111 opus/48000/2" "      a=fmtp:111 minptime=20;useinbandfec=1"
run_test "06_PCMA→Opus" uac6.xml uas6.xml

# ── Test 7: Opus → PCMU (transcoding) ──
gen_uac uac7.xml "111" "      a=rtpmap:111 opus/48000/2" "      a=fmtp:111 minptime=20;useinbandfec=1"
gen_uas uas7.xml "0" "      a=rtpmap:0 PCMU/8000"
run_test "07_Opus→PCMU" uac7.xml uas7.xml

# ── Test 8: Opus → PCMA (transcoding) ──
gen_uac uac8.xml "111" "      a=rtpmap:111 opus/48000/2" "      a=fmtp:111 minptime=20;useinbandfec=1"
gen_uas uas8.xml "8" "      a=rtpmap:8 PCMA/8000"
run_test "08_Opus→PCMA" uac8.xml uas8.xml

# ── Test 9: Opus → Opus (passthrough) ──
gen_uac uac9.xml "111" "      a=rtpmap:111 opus/48000/2" "      a=fmtp:111 minptime=20;useinbandfec=1"
gen_uas uas9.xml "111" "      a=rtpmap:111 opus/48000/2" "      a=fmtp:111 minptime=20;useinbandfec=1"
run_test "09_Opus→Opus" uac9.xml uas9.xml

# ═════════════════════════════════════════════════════════════════════════════
log_header "SECTION 2: Multi-Codec Negotiation"

# ── Test 10: PCMU+PCMA offer → PCMU answer ──
gen_uac uac10.xml "0 8" "      a=rtpmap:0 PCMU/8000\n      a=rtpmap:8 PCMA/8000"
gen_uas uas10.xml "0" "      a=rtpmap:0 PCMU/8000"
run_test "10_multi_G711→PCMU" uac10.xml uas10.xml

# ── Test 11: PCMU+Opus offer → Opus answer ──
gen_uac uac11.xml "0 111" "      a=rtpmap:0 PCMU/8000\n      a=rtpmap:111 opus/48000/2" "      a=fmtp:111 minptime=20"
gen_uas uas11.xml "111" "      a=rtpmap:111 opus/48000/2" "      a=fmtp:111 minptime=20"
run_test "11_multi_PCMU+Opus→Opus" uac11.xml uas11.xml

# ── Test 12: All codecs offer → PCMA answer ──
gen_uac uac12.xml "111 0 8" "      a=rtpmap:111 opus/48000/2\n      a=rtpmap:0 PCMU/8000\n      a=rtpmap:8 PCMA/8000" "      a=fmtp:111 minptime=20"
gen_uas uas12.xml "8" "      a=rtpmap:8 PCMA/8000"
run_test "12_multi_all→PCMA" uac12.xml uas12.xml

# ═════════════════════════════════════════════════════════════════════════════
log_header "SECTION 3: Transport Combinations"

# ── Test 13: TCP caller → UDP callee ──
gen_uac uac13.xml "0" "      a=rtpmap:0 PCMU/8000" "" "TCP"
gen_uas uas13.xml "0" "      a=rtpmap:0 PCMU/8000"
run_test "13_TCP→UDP_PCMU" uac13.xml uas13.xml "t1"

# ── Test 14: TLS caller → UDP callee ──
gen_uac uac14.xml "0" "      a=rtpmap:0 PCMU/8000" "" "TLS"
gen_uas uas14.xml "0" "      a=rtpmap:0 PCMU/8000"
# TLS needs special handling
pkill sipp 2>/dev/null || true; sleep 0.5
sipp -sf "$SCEN/uas14.xml" -i $LOCAL_IP -p $UAS_PORT -m 1 -timeout ${TIMEOUT}s -bg > /dev/null 2>&1 &
TLS_UAS=$!
sleep 1
sipp ${SBC_IP}:${SBC_TLS_PORT} \
    -sf "$SCEN/uac14.xml" \
    -i $LOCAL_IP -p $UAC_PORT \
    -t l1 -tls_cert /etc/sbc/certs/fullchain.pem -tls_key /etc/sbc/certs/privkey.pem \
    -m 1 -timeout ${TIMEOUT}s \
    > "$RESULTS_DIR/14_TLS.log" 2>&1 && TLS_RC=0 || TLS_RC=$?
wait $TLS_UAS 2>/dev/null || true
[ $TLS_RC -eq 0 ] && log_pass "14_TLS→UDP_PCMU" || log_fail "14_TLS→UDP_PCMU (exit=$TLS_RC)"

# ═════════════════════════════════════════════════════════════════════════════
log_header "SECTION 4: SRTP Secure Media"

# ── Test 15: SRTP PCMU → SRTP PCMU ──
cat > "$SCEN/uac_srtp.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="UAC SRTP">
  <send retrans="500">
    <![CDATA[
      INVITE sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 INVITE
      Contact: <sip:alice@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=alice 53655765 2353687637 IN IP4 [local_ip]
      s=SRTP Test
      c=IN IP4 [local_ip]
      t=0 0
      m=audio [media_port] RTP/SAVP 0
      a=rtpmap:0 PCMU/8000
      a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9tele01234567
      a=sendrecv
    ]]>
  </send>
  <recv response="100" optional="true" />
  <recv response="180" optional="true" />
  <recv response="200" rtd="true" />
  <send>
    <![CDATA[
      ACK sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 1 ACK
      Max-Forwards: 70
      Content-Length: 0
    ]]>
  </send>
  <pause milliseconds="2000" />
  <send retrans="500">
    <![CDATA[
      BYE sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 2 BYE
      Max-Forwards: 70
      Content-Length: 0
    ]]>
  </send>
  <recv response="200" crlf="true" />
</scenario>
EOF

cat > "$SCEN/uas_srtp.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="UAS SRTP">
  <recv request="INVITE" crlf="true" />
  <send>
    <![CDATA[
      SIP/2.0 180 Ringing
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:bob@[local_ip]:[local_port]>
      Content-Length: 0
    ]]>
  </send>
  <pause milliseconds="300" />
  <send retrans="500">
    <![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:bob@[local_ip]:[local_port]>
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=bob 54321 54321 IN IP4 [local_ip]
      s=SRTP Test
      c=IN IP4 [local_ip]
      t=0 0
      m=audio [media_port] RTP/SAVP 0
      a=rtpmap:0 PCMU/8000
      a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:YXNkZmFzZGZhc2RmYXNkZmFzZGZhc2Rm0123456789AB
      a=sendrecv
    ]]>
  </send>
  <recv request="ACK" crlf="true" />
  <recv request="BYE" />
  <send>
    <![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:]
      [last_Call-ID:]
      [last_CSeq:]
      Content-Length: 0
    ]]>
  </send>
</scenario>
EOF

run_test "15_SRTP_PCMU→PCMU" uac_srtp.xml uas_srtp.xml

# ── Test 16: SRTP PCMU → SRTP Opus (encrypted + transcoding) ──
cat > "$SCEN/uas_srtp_opus.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="UAS SRTP Opus">
  <recv request="INVITE" crlf="true" />
  <send>
    <![CDATA[
      SIP/2.0 180 Ringing
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:bob@[local_ip]:[local_port]>
      Content-Length: 0
    ]]>
  </send>
  <pause milliseconds="300" />
  <send retrans="500">
    <![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:bob@[local_ip]:[local_port]>
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=bob 54321 54321 IN IP4 [local_ip]
      s=SRTP Opus Test
      c=IN IP4 [local_ip]
      t=0 0
      m=audio [media_port] RTP/SAVP 111
      a=rtpmap:111 opus/48000/2
      a=fmtp:111 minptime=20;useinbandfec=1
      a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:YXNkZmFzZGZhc2RmYXNkZmFzZGZhc2Rm0123456789AB
      a=sendrecv
    ]]>
  </send>
  <recv request="ACK" crlf="true" />
  <recv request="BYE" />
  <send>
    <![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:]
      [last_Call-ID:]
      [last_CSeq:]
      Content-Length: 0
    ]]>
  </send>
</scenario>
EOF

run_test "16_SRTP_PCMU→Opus" uac_srtp.xml uas_srtp_opus.xml

# ═════════════════════════════════════════════════════════════════════════════
log_header "SECTION 5: Signaling Tests"

# ── Test 17: OPTIONS (UDP) ──
OPTS=$(sipsak -s "sip:test@${SBC_IP}:${SBC_SIP_PORT}" -v 2>&1 || true)
echo "$OPTS" | grep -qE "200|404|405|501" && log_pass "17_OPTIONS_UDP" || log_fail "17_OPTIONS_UDP"

# ── Test 18: OPTIONS (TCP) ──
OPTS_T=$(sipsak -s "sip:test@${SBC_IP}:${SBC_SIP_PORT}" -T -v 2>&1 || true)
echo "$OPTS_T" | grep -qE "200|404|405|501" && log_pass "18_OPTIONS_TCP" || log_fail "18_OPTIONS_TCP"

# ── Test 19: REGISTER with auth ──
cat > "$SCEN/register.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="Register">
  <send retrans="500">
    <![CDATA[
      REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[remote_ip]>;tag=[call_number]
      To: "alice" <sip:alice@[remote_ip]>
      Call-ID: [call_id]
      CSeq: 1 REGISTER
      Contact: <sip:alice@[local_ip]:[local_port]>
      Max-Forwards: 70
      Expires: 3600
      Content-Length: 0
    ]]>
  </send>
  <recv response="401" auth="true" />
  <send retrans="500">
    <![CDATA[
      REGISTER sip:[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[remote_ip]>;tag=[call_number]
      To: "alice" <sip:alice@[remote_ip]>
      Call-ID: [call_id]
      CSeq: 2 REGISTER
      Contact: <sip:alice@[local_ip]:[local_port]>
      [authentication username=alice password=alice2026]
      Max-Forwards: 70
      Expires: 3600
      Content-Length: 0
    ]]>
  </send>
  <recv response="200" />
</scenario>
EOF

pkill sipp 2>/dev/null || true; sleep 0.5
sipp ${SBC_IP}:${SBC_SIP_PORT} \
    -sf "$SCEN/register.xml" \
    -i $LOCAL_IP -p 6055 \
    -m 1 -timeout ${TIMEOUT}s \
    > "$RESULTS_DIR/19_register.log" 2>&1 && REG_RC=0 || REG_RC=$?
[ $REG_RC -eq 0 ] && log_pass "19_REGISTER_auth" || log_fail "19_REGISTER_auth (exit=$REG_RC)"

# ═════════════════════════════════════════════════════════════════════════════
log_header "SECTION 6: Error Handling"

# ── Test 20: Bad SDP ──
cat > "$SCEN/bad_sdp.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="Bad SDP">
  <send retrans="500">
    <![CDATA[
      INVITE sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 INVITE
      Contact: <sip:alice@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Type: application/sdp
      Content-Length: [len]

      THIS IS NOT VALID SDP
    ]]>
  </send>
  <recv response="." />
</scenario>
EOF

pkill sipp 2>/dev/null || true; sleep 0.5
sipp ${SBC_IP}:${SBC_SIP_PORT} \
    -sf "$SCEN/bad_sdp.xml" \
    -i $LOCAL_IP -p $UAC_PORT \
    -m 1 -timeout 5s \
    > "$RESULTS_DIR/20_bad_sdp.log" 2>&1 || true
# SBC should not crash
systemctl is-active sbc > /dev/null 2>&1 && log_pass "20_bad_sdp_no_crash" || log_fail "20_bad_sdp_SBC_CRASHED"

# ═════════════════════════════════════════════════════════════════════════════
log_header "SECTION 7: Load Test (10 concurrent)"

gen_uac uac_load.xml "0" "      a=rtpmap:0 PCMU/8000"
gen_uas uas_load.xml "0" "      a=rtpmap:0 PCMU/8000"

pkill sipp 2>/dev/null || true; sleep 0.5

sipp -sf "$SCEN/uas_load.xml" -i $LOCAL_IP -p $UAS_PORT -m 10 -timeout 30s -bg > /dev/null 2>&1 &
LOAD_UAS=$!
sleep 1

sipp ${SBC_IP}:${SBC_SIP_PORT} \
    -sf "$SCEN/uac_load.xml" \
    -i $LOCAL_IP -p $UAC_PORT \
    -m 10 -r 5 -timeout 30s \
    > "$RESULTS_DIR/21_load.log" 2>&1 && LOAD_RC=0 || LOAD_RC=$?
wait $LOAD_UAS 2>/dev/null || true
[ $LOAD_RC -eq 0 ] && log_pass "21_load_10_concurrent" || log_fail "21_load_10_concurrent (exit=$LOAD_RC)"

# ═════════════════════════════════════════════════════════════════════════════
log_header "FINAL: Post-test Checks"

# Metrics after
curl -sf "http://127.0.0.1:9090/metrics" > "$RESULTS_DIR/metrics_after.txt" 2>/dev/null || true
echo -e "${BLUE}Metrics:${NC}"
grep "sbc_" "$RESULTS_DIR/metrics_after.txt" 2>/dev/null || echo "  (no metrics)"

# SBC still alive?
systemctl is-active sbc > /dev/null 2>&1 && log_pass "SBC_alive_after_tests" || log_fail "SBC_CRASHED"

# ═════════════════════════════════════════════════════════════════════════════
log_header "SUMMARY"
echo ""
echo -e "  ${GREEN}PASSED: $PASS${NC}"
echo -e "  ${RED}FAILED: $FAIL${NC}"
echo -e "  TOTAL:  $TOTAL"
echo ""
echo "  Results: $RESULTS_DIR"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "  ${GREEN}══ ALL TESTS PASSED ✓ ══${NC}"
    exit 0
else
    echo -e "  ${RED}══ $FAIL TESTS FAILED ══${NC}"
    exit 1
fi
