#!/usr/bin/env bash
# Integration test for the wasmexec server
set -uo pipefail

BASE="http://localhost:${PORT:-8000}"
PASS=0
FAIL=0

check() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Upload echo.wasm ==="
RESP=$(curl -s -X PUT --data-binary @test/echo.wasm "$BASE/blobs")
HASH=$(echo "$RESP" | grep -o '"hash":"[^"]*"' | cut -d'"' -f4)
echo "  hash: $HASH"
check "upload returns hash" 64 "${#HASH}"

echo "=== GET blob back ==="
curl -s -o /tmp/echo_back.wasm "$BASE/blobs/$HASH"
check "round-trip" "$(sha256sum test/echo.wasm | cut -c1-64)" "$(sha256sum /tmp/echo_back.wasm | cut -c1-64)"

echo "=== Execute echo.wasm ==="
OUT=$(curl -s -X POST -d 'hello world' "$BASE/execute/$HASH")
check "echo output" "hello world" "$OUT"

echo "=== Upload reverse.wasm ==="
RESP2=$(curl -s -X PUT --data-binary @test/reverse.wasm "$BASE/blobs")
HASH2=$(echo "$RESP2" | grep -o '"hash":"[^"]*"' | cut -d'"' -f4)
echo "  hash: $HASH2"

echo "=== Execute reverse.wasm ==="
OUT2=$(curl -s -X POST -d 'abcdef' "$BASE/execute/$HASH2")
check "reverse output" "fedcba" "$OUT2"

echo "=== GET nonexistent blob ==="
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/blobs/0000000000000000000000000000000000000000000000000000000000000000")
check "404 for missing" "404" "$CODE"

echo "=== Execute nonexistent blob ==="
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'test' "$BASE/execute/0000000000000000000000000000000000000000000000000000000000000000")
check "404 for missing wasm" "404" "$CODE"

echo "=== Upload duplicate blob ==="
RESP3=$(curl -s -X PUT --data-binary @test/echo.wasm "$BASE/blobs")
HASH3=$(echo "$RESP3" | grep -o '"hash":"[^"]*"' | cut -d'"' -f4)
check "idempotent upload" "$HASH" "$HASH3"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
