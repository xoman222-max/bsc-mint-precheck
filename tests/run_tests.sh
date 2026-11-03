#!/usr/bin/env bash
# Live read-only tests against BSC mainnet. Never signs or sends.
set -u; cd "$(dirname "$0")/.."
PY=${PY:-$( [ -x /workspace/venv_eth/bin/python ] && echo /workspace/venv_eth/bin/python || echo python3 )}
pass=0; fail=0
t(){ name=$1; expect=$2; shift 2; out=$($PY precheck.py "$@" --no-save 2>&1); if echo "$out" | head -1 | grep -qE "$expect"; then echo "PASS $name"; pass=$((pass+1)); else echo "FAIL $name"; echo "$out" | head -5; fail=$((fail+1)); fi; }
t "sold-out ERC721 (Xuanwu Sigil)" "已售罄" 0xe397A4776F9e7cDC016C332b15756325E4AAc84B
t "verified ERC721 owner-only (Pancake Squad)" "僅owner" 0x0a8901b0E25DEb55A87524f0cC164E9644020EBA
t "EIP-1967 proxy (USDC BSC)" "結論" 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d
t "price mismatch (CatalystLabsX)" "價格不符|免費|實際價格|模擬|可以mint" 0xDe4Db9388297e65A758A1dAF116368Ffc4F9E475
t "failure: EOA not contract" "不是合約" 0x000000000000000000000000000000000000dEaD
t "URL scan (anthrobit.fun)" "結論" anthrobit.fun
out=$($PY precheck.py 0x$(printf 'a%.0s' {1..64}) 2>&1); echo "$out" | grep -q "拒絕" && { echo "PASS refuses key-like input"; pass=$((pass+1)); } || { echo "FAIL key guard"; fail=$((fail+1)); }
$PY -c "import precheck as P
try: P.RPC().batch([('eth_sendRawTransaction',['0x'])]); print('FAIL guard')
except PermissionError: print('PASS rpc send guard')" | tee /dev/stderr | grep -q PASS && pass=$((pass+1)) || fail=$((fail+1))
$PY tests/test_custom_entry.py 2>&1 | tee /dev/stderr | grep -q PASS && pass=$((pass+1)) || fail=$((fail+1))
echo "passed=$pass failed=$fail"; [ $fail -eq 0 ]
