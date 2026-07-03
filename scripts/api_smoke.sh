#!/usr/bin/env bash
# Post-deploy smoke test for the SBC management API.
# Usage: api_smoke.sh [BASE_URL] — token read from $SBC_API_TOKEN or production.toml.
set -u

BASE="${1:-http://127.0.0.1:8080}"
TOKEN="${SBC_API_TOKEN:-$(grep api_auth_token /opt/sbc/config/production.toml 2>/dev/null | cut -d'"' -f2)}"
AUTH=(-H "Authorization: Bearer ${TOKEN}")
FAIL=0

check() {
    local desc="$1" expected="$2"; shift 2
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$@")
    if [ "$code" = "$expected" ]; then
        echo "OK   $desc ($code)"
    else
        echo "FAIL $desc (got $code, want $expected)"
        FAIL=1
    fi
}

check "health (public)"            200 "$BASE/health"
check "ready (public)"             200 "$BASE/ready"
check "stats without token -> 401" 401 "$BASE/api/v1/stats"
check "stats with token"           200 "${AUTH[@]}" "$BASE/api/v1/stats"
check "metrics"                    200 "${AUTH[@]}" "$BASE/metrics"
check "calls"                      200 "${AUTH[@]}" "$BASE/api/v1/calls"
check "registrations"              200 "${AUTH[@]}" "$BASE/api/v1/registrations"
check "trunks"                     200 "${AUTH[@]}" "$BASE/api/v1/trunks"
check "users"                      200 "${AUTH[@]}" "$BASE/api/v1/users"
check "dids"                       200 "${AUTH[@]}" "$BASE/api/v1/dids"
check "routes"                     200 "${AUTH[@]}" "$BASE/api/v1/routes"
check "acl rules"                  200 "${AUTH[@]}" "$BASE/api/v1/acl/rules"
check "cdrs"                       200 "${AUTH[@]}" "$BASE/api/v1/cdrs?limit=5"
check "alerts"                     200 "${AUTH[@]}" "$BASE/api/v1/alerts"
check "export"                     200 "${AUTH[@]}" "$BASE/api/v1/export"
check "legacy /api/status"         200 "${AUTH[@]}" "$BASE/api/status"

# SSE: expect a 200 and the event-stream content type within 2s
SSE_CT=$(curl -s -m 2 -o /dev/null -w "%{content_type}" "${AUTH[@]}" "$BASE/api/v1/events" || true)
case "$SSE_CT" in
    text/event-stream*) echo "OK   SSE events (content-type: $SSE_CT)";;
    *) echo "FAIL SSE events (content-type: $SSE_CT)"; FAIL=1;;
esac

exit $FAIL
