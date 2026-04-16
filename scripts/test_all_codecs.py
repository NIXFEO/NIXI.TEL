#!/usr/bin/env python3
"""
SBC Comprehensive Codec×Transport Test Suite
Tests all codec combinations via SIPp UAC/UAS through the SBC B2BUA.
"""

import subprocess, os, sys, time, signal, tempfile, socket

SBC_IP = "127.0.0.1"
SBC_PORT = 5060
SBC_TLS = 5061
UAS_PORT = 5080  # DefaultTrunk target
UAC_PORT_BASE = 6060
TIMEOUT = 20  # seconds per test
CALL_DUR = 1000  # ms
INTER_TEST_DELAY = 1.5  # seconds between tests for B2BUA cleanup

SCEN_DIR = tempfile.mkdtemp(prefix="sbc_test_")
PASS = 0; FAIL = 0; TOTAL = 0

# ── SIPp scenario templates ──────────────────────────────────────────────────

def uac_xml(codec_list, rtpmap_lines, fmtp="", transport="UDP", profile="RTP/AVP"):
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="UAC">
  <send retrans="500"><![CDATA[
      INVITE sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/{transport} [local_ip]:[local_port];branch=[branch]
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
      m=audio [media_port] {profile} {codec_list}
{rtpmap_lines}
{fmtp}
      a=sendrecv
  ]]></send>
  <recv response="100" optional="true" />
  <recv response="180" optional="true" />
  <recv response="200" rtd="true" />
  <send><![CDATA[
      ACK sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/{transport} [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 1 ACK
      Max-Forwards: 70
      Content-Length: 0
  ]]></send>
  <pause milliseconds="{CALL_DUR}" />
  <send retrans="500"><![CDATA[
      BYE sip:bob@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/{transport} [local_ip]:[local_port];branch=[branch]
      From: "alice" <sip:alice@[local_ip]:[local_port]>;tag=[call_number]
      To: "bob" <sip:bob@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 2 BYE
      Max-Forwards: 70
      Content-Length: 0
  ]]></send>
  <recv response="200" crlf="true" />
</scenario>"""


def uas_xml(codec_list, rtpmap_lines, fmtp="", profile="RTP/AVP"):
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="UAS">
  <recv request="INVITE" crlf="true" />
  <send><![CDATA[
      SIP/2.0 180 Ringing
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:bob@[local_ip]:[local_port]>
      Content-Length: 0
  ]]></send>
  <pause milliseconds="300" />
  <send retrans="500"><![CDATA[
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
      m=audio [media_port] {profile} {codec_list}
{rtpmap_lines}
{fmtp}
      a=sendrecv
  ]]></send>
  <recv request="ACK" crlf="true" />
  <recv request="BYE" />
  <send><![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:]
      [last_Call-ID:]
      [last_CSeq:]
      Content-Length: 0
  ]]></send>
</scenario>"""


# Codec definitions
PCMU = ("0", "      a=rtpmap:0 PCMU/8000", "")
PCMA = ("8", "      a=rtpmap:8 PCMA/8000", "")
OPUS = ("111", "      a=rtpmap:111 opus/48000/2", "      a=fmtp:111 minptime=20;useinbandfec=1")
MULTI_G711 = ("0 8", "      a=rtpmap:0 PCMU/8000\n      a=rtpmap:8 PCMA/8000", "")
MULTI_ALL = ("111 0 8", "      a=rtpmap:111 opus/48000/2\n      a=rtpmap:0 PCMU/8000\n      a=rtpmap:8 PCMA/8000", "      a=fmtp:111 minptime=20")


def kill_sipp():
    """Kill all sipp processes and wait for port cleanup.
    IMPORTANT: Never use fuser -k on SBC ports as it could kill the SBC itself.
    """
    subprocess.run(["pkill", "-9", "-f", "sipp"], capture_output=True)
    time.sleep(1)
    subprocess.run(["pkill", "-9", "-f", "sipp"], capture_output=True)
    time.sleep(1)


def wait_for_port_free(port, timeout=5):
    """Wait until no sipp process is binding to the given port.
    We check by trying to bind ourselves (UDP).
    """
    for _ in range(timeout * 5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.close()
            return True
        except OSError:
            # Port still in use, kill any remaining sipp
            subprocess.run(["pkill", "-9", "-f", "sipp"], capture_output=True)
            time.sleep(0.2)
    return False


def check_sbc_alive():
    """Check if SBC is responding via OPTIONS on UDP."""
    try:
        result = subprocess.run(
            ["sipsak", "-s", f"sip:test@{SBC_IP}:{SBC_PORT}", "-v"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        return any(p in output for p in ["200", "404", "405", "501"])
    except:
        return False


def write_scenario(name, content):
    path = os.path.join(SCEN_DIR, name)
    with open(path, "w") as f:
        f.write(content)
    return path


def run_test(name, caller_codec, callee_codec, transport="UDP", profile="RTP/AVP",
             caller_profile=None, callee_profile=None, remote_port=None):
    global PASS, FAIL, TOTAL
    TOTAL += 1

    c_pt, c_rtpmap, c_fmtp = caller_codec
    b_pt, b_rtpmap, b_fmtp = callee_codec
    cp = caller_profile or profile
    bp = callee_profile or profile
    rp = remote_port or SBC_PORT

    uac_path = write_scenario(f"uac_{TOTAL}.xml", uac_xml(c_pt, c_rtpmap, c_fmtp, transport, cp))
    uas_path = write_scenario(f"uas_{TOTAL}.xml", uas_xml(b_pt, b_rtpmap, b_fmtp, bp))

    kill_sipp()
    if not wait_for_port_free(UAS_PORT):
        print(f"  \033[33m[WARN]\033[0m Port {UAS_PORT} still in use after cleanup")

    # Use unique UAC port per test to avoid port conflicts
    uac_port = UAC_PORT_BASE + TOTAL * 2

    # Start UAS (callee)
    uas_proc = subprocess.Popen(
        ["sipp", "-sf", uas_path, "-i", SBC_IP, "-p", str(UAS_PORT),
         "-m", "1", "-timeout", f"{TIMEOUT}s"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # Give UAS time to bind

    # Start UAC (caller)
    uac_cmd = ["sipp", f"{SBC_IP}:{rp}",
               "-sf", uac_path, "-i", SBC_IP, "-p", str(uac_port),
               "-m", "1", "-timeout", f"{TIMEOUT}s"]
    if transport == "TCP":
        uac_cmd.extend(["-t", "t1"])
    elif transport == "TLS":
        uac_cmd.extend(["-t", "l1",
                        "-tls_cert", "/etc/sbc/certs/fullchain.pem",
                        "-tls_key", "/etc/sbc/certs/privkey.pem"])

    result = None
    try:
        result = subprocess.run(uac_cmd, capture_output=True, text=True, timeout=TIMEOUT+5)
        rc = result.returncode
    except subprocess.TimeoutExpired:
        rc = -1

    # Wait for UAS
    try:
        uas_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        uas_proc.kill()

    if rc == 0:
        PASS += 1
        print(f"  \033[32m[PASS]\033[0m {name}")
    else:
        FAIL += 1
        print(f"  \033[31m[FAIL]\033[0m {name} (exit={rc})")
        if result and result.stderr:
            for line in result.stderr.strip().split('\n')[-3:]:
                if line.strip():
                    print(f"         {line.strip()}")

    # Inter-test delay for B2BUA session cleanup
    time.sleep(INTER_TEST_DELAY)


def run_signaling_test(name, tool_cmd, expect_pattern):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    try:
        result = subprocess.run(tool_cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
        if any(p in output for p in expect_pattern):
            PASS += 1
            print(f"  \033[32m[PASS]\033[0m {name}")
        else:
            FAIL += 1
            print(f"  \033[31m[FAIL]\033[0m {name}")
    except Exception as e:
        FAIL += 1
        print(f"  \033[31m[FAIL]\033[0m {name} ({e})")


# ═══════════════════════════════════════════════════════════════════════════════
print("\n\033[1;33m═══ SBC Comprehensive Codec×Transport Test Suite ═══\033[0m")
print(f"  SBC: {SBC_IP}:{SBC_PORT}  Scenarios: {SCEN_DIR}")
print()

# Fetch baseline metrics
import urllib.request
try:
    metrics_before = urllib.request.urlopen("http://127.0.0.1:9090/metrics", timeout=3).read().decode()
except:
    metrics_before = ""

# ── SECTION 1: SIP↔SIP Same Codec (passthrough) ─────────────────────────────
print("\033[1;33m═══ SECTION 1: SIP↔SIP Same Codec (passthrough) ═══\033[0m")
run_test("01 PCMU → PCMU", PCMU, PCMU)
run_test("02 PCMA → PCMA", PCMA, PCMA)
run_test("03 Opus → Opus", OPUS, OPUS)

# ── SECTION 2: SIP↔SIP Cross-Codec (transcoding) ────────────────────────────
print("\n\033[1;33m═══ SECTION 2: SIP↔SIP Cross-Codec (transcoding) ═══\033[0m")
run_test("04 PCMU → PCMA", PCMU, PCMA)
run_test("05 PCMA → PCMU", PCMA, PCMU)
run_test("06 PCMU → Opus", PCMU, OPUS)
run_test("07 PCMA → Opus", PCMA, OPUS)
run_test("08 Opus → PCMU", OPUS, PCMU)
run_test("09 Opus → PCMA", OPUS, PCMA)

# ── SECTION 3: Multi-Codec Negotiation ───────────────────────────────────────
print("\n\033[1;33m═══ SECTION 3: Multi-Codec Negotiation ═══\033[0m")
run_test("10 PCMU+PCMA → PCMU", MULTI_G711, PCMU)
run_test("11 All → PCMA", MULTI_ALL, PCMA)
run_test("12 All → Opus", MULTI_ALL, OPUS)

# ── SECTION 4: Transport Combinations ────────────────────────────────────────
print("\n\033[1;33m═══ SECTION 4: Transport Combinations ═══\033[0m")
run_test("13 TCP → UDP (PCMU)", PCMU, PCMU, transport="TCP")
run_test("14 TLS → UDP (PCMU)", PCMU, PCMU, transport="TLS", remote_port=SBC_TLS)

# ── SECTION 5: SRTP Secure Media ────────────────────────────────────────────
print("\n\033[1;33m═══ SECTION 5: SRTP Secure Media ═══\033[0m")
SRTP_PCMU = ("0", "      a=rtpmap:0 PCMU/8000\n      a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9tele01234567", "")
SRTP_PCMU_B = ("0", "      a=rtpmap:0 PCMU/8000\n      a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:YXNkZmFzZGZhc2RmYXNkZmFzZGZhc2Rm0123456789AB", "")
SRTP_OPUS = ("111", "      a=rtpmap:111 opus/48000/2\n      a=fmtp:111 minptime=20;useinbandfec=1\n      a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:YXNkZmFzZGZhc2RmYXNkZmFzZGZhc2Rm0123456789AB", "")

run_test("15 SRTP PCMU → SRTP PCMU", SRTP_PCMU, SRTP_PCMU_B, profile="RTP/SAVP")
run_test("16 SRTP PCMU → SRTP Opus", SRTP_PCMU, SRTP_OPUS,
         caller_profile="RTP/SAVP", callee_profile="RTP/SAVP")

# ── SECTION 6: Signaling Tests ──────────────────────────────────────────────
print("\n\033[1;33m═══ SECTION 6: Signaling Tests ═══\033[0m")
kill_sipp()
run_signaling_test("17 OPTIONS UDP",
    ["sipsak", "-s", f"sip:test@{SBC_IP}:{SBC_PORT}", "-v"],
    ["200", "404", "405", "501"])
run_signaling_test("18 OPTIONS TCP",
    ["sipsak", "-s", f"sip:test@{SBC_IP}:{SBC_PORT}", "-T", "-v"],
    ["200", "404", "405", "501"])

# ── SECTION 7: Error Handling ────────────────────────────────────────────────
print("\n\033[1;33m═══ SECTION 7: Error Handling ═══\033[0m")
# Bad SDP
bad_path = write_scenario("bad_sdp.xml", """<?xml version="1.0" encoding="UTF-8" ?>
<scenario name="Bad SDP">
  <send retrans="500"><![CDATA[
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
  ]]></send>
  <recv response="." />
</scenario>""")
subprocess.run(["sipp", f"{SBC_IP}:{SBC_PORT}", "-sf", bad_path,
                "-i", SBC_IP, "-p", "6090", "-m", "1", "-timeout", "5s"],
               capture_output=True, timeout=10)
time.sleep(1)
# Check SBC is still alive via OPTIONS probe (more reliable than systemctl)
sbc_alive = check_sbc_alive()
TOTAL += 1
if sbc_alive:
    PASS += 1
    print(f"  \033[32m[PASS]\033[0m 19 Bad SDP - SBC survives")
else:
    FAIL += 1
    print(f"  \033[31m[FAIL]\033[0m 19 Bad SDP - SBC CRASHED!")

# ── SECTION 8: Load Test ────────────────────────────────────────────────────
print("\n\033[1;33m═══ SECTION 8: Load Test (10 concurrent calls) ═══\033[0m")
kill_sipp()
wait_for_port_free(UAS_PORT)
uac_path = write_scenario("load_uac.xml", uac_xml("0", "      a=rtpmap:0 PCMU/8000"))
uas_path = write_scenario("load_uas.xml", uas_xml("0", "      a=rtpmap:0 PCMU/8000"))

uas_proc = subprocess.Popen(
    ["sipp", "-sf", uas_path, "-i", SBC_IP, "-p", str(UAS_PORT),
     "-m", "10", "-timeout", "60s"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(2)

try:
    result = subprocess.run(
        ["sipp", f"{SBC_IP}:{SBC_PORT}", "-sf", uac_path,
         "-i", SBC_IP, "-p", "6090",
         "-m", "10", "-r", "3", "-timeout", "60s"],
        capture_output=True, text=True, timeout=65
    )
    rc = result.returncode
except subprocess.TimeoutExpired:
    rc = -1

try:
    uas_proc.wait(timeout=10)
except subprocess.TimeoutExpired:
    uas_proc.kill()

TOTAL += 1
if rc == 0:
    PASS += 1
    print(f"  \033[32m[PASS]\033[0m 20 Load: 10 concurrent PCMU calls @ 3 CPS")
else:
    FAIL += 1
    print(f"  \033[31m[FAIL]\033[0m 20 Load: 10 concurrent calls (exit={rc})")

# ── FINAL ────────────────────────────────────────────────────────────────────
print("\n\033[1;33m═══ Post-Test Metrics ═══\033[0m")
try:
    metrics_after = urllib.request.urlopen("http://127.0.0.1:9090/metrics", timeout=3).read().decode()
    for line in metrics_after.strip().split('\n'):
        if line.startswith('sbc_'):
            print(f"  {line}")
except:
    print("  (metrics unavailable)")

# Final SBC check via OPTIONS (more reliable than systemctl)
time.sleep(1)
sbc_alive = check_sbc_alive()
TOTAL += 1
if sbc_alive:
    PASS += 1
    print(f"\n  \033[32m[PASS]\033[0m SBC alive after all tests")
else:
    FAIL += 1
    print(f"\n  \033[31m[FAIL]\033[0m SBC CRASHED during tests!")

# ── Summary ──────────────────────────────────────────────────────────────────
print(f"\n\033[1;33m═══ SUMMARY ═══\033[0m")
print(f"  \033[32mPASSED: {PASS}\033[0m")
print(f"  \033[31mFAILED: {FAIL}\033[0m")
print(f"  TOTAL:  {TOTAL}")
print()

if FAIL == 0:
    print(f"  \033[32m══ ALL {TOTAL} TESTS PASSED ✓ ══\033[0m")
else:
    print(f"  \033[31m══ {FAIL}/{TOTAL} TESTS FAILED ══\033[0m")

# Cleanup
kill_sipp()
sys.exit(0 if FAIL == 0 else 1)
