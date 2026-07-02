#!/usr/bin/env bash
# Manual security test matrix for the STREAMIX brique.
# Exercises: auth, session tokens, HLS key tokens, and stream encryption.
# Run from anywhere: bash scripts/security-test.sh
set -uo pipefail

BASE=https://localhost:3001
HLS_BASE=https://localhost:8443
EMAIL=${STREAMIX_TEST_EMAIL:-demo@streamix.local}
PASSWORD=${STREAMIX_TEST_PASSWORD:-StreamixDemo123!}

pass=0
fail=0

check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS - $name (HTTP $actual)"
    pass=$((pass+1))
  else
    echo "FAIL - $name (expected $expected, got $actual)"
    fail=$((fail+1))
  fi
}

echo "== 1. /key with no token at all -> must be denied =="
code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/key")
check "key without token" 403 "$code"

echo "== 2. /key with a garbage token -> must be denied =="
code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/key" -H "Authorization: Bearer garbage")
check "key with garbage token" 403 "$code"

echo "== 3. /token with no session -> must be denied =="
code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/token")
check "token without session" 401 "$code"

echo "== 4. login with wrong password -> must be denied =="
code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"wrong-password\"}")
check "login wrong password" 401 "$code"

echo "== 5. login with correct credentials -> must succeed =="
login_json=$(curl -sk -X POST "$BASE/auth/login" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
session_token=$(echo "$login_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('session_token',''))")
check "login success" 1 "$([ -n "$session_token" ] && echo 1 || echo 0)"

echo "== 6. exchange session for HLS key token -> must succeed =="
token_json=$(curl -sk "$BASE/token" -H "Authorization: Bearer $session_token")
hls_token=$(echo "$token_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))")
check "hls token issued" 1 "$([ -n "$hls_token" ] && echo 1 || echo 0)"

echo "== 7. use HLS token to fetch the AES key -> must succeed, 16 bytes =="
size=$(curl -sk "$BASE/key" -H "Authorization: Bearer $hls_token" -o /tmp/streamix-test-key.bin -w "%{size_download}")
check "key size 16 bytes" 16 "$size"

echo "== 8. raw .ts segment must NOT be a valid MPEG-TS (proves it's encrypted) =="
curl -sk "$HLS_BASE/hls/segment_000.ts" -o /tmp/streamix-test-segment.ts
first_byte=$(xxd -p -l1 /tmp/streamix-test-segment.ts)
check "segment not starting with sync byte 0x47" 1 "$([ "$first_byte" != "47" ] && echo 1 || echo 0)"

echo "== 9. decrypting the segment with the fetched key must produce valid MPEG-TS =="
key_hex=$(xxd -p /tmp/streamix-test-key.bin | tr -d '\n')
openssl enc -d -aes-128-cbc -K "$key_hex" -iv "00000000000000000000000000000000" \
  -in /tmp/streamix-test-segment.ts -out /tmp/streamix-test-decrypted.ts 2>/dev/null
decrypted_first_byte=$(xxd -p -l1 /tmp/streamix-test-decrypted.ts)
check "decrypted segment starts with sync byte 0x47" 47 "$decrypted_first_byte"

echo "== 10. expired/garbage session token still rejected after login (independent check) =="
code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/token" -H "Authorization: Bearer $session_token.tampered")
check "tampered session token rejected" 401 "$code"

rm -f /tmp/streamix-test-key.bin /tmp/streamix-test-segment.ts /tmp/streamix-test-decrypted.ts

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
