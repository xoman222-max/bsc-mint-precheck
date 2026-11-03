#!/usr/bin/env python3
"""Seed history.db from past mint data on the box. Imports ONLY public contract features + outcome labels.
Never imports tx hashes, wallet addresses, order ids, keys or tokens. Outcomes marked 'historical_unverified'."""
import json, glob, os, sys, hashlib, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import precheck as P
SRC = sys.argv[1] if len(sys.argv) > 1 else "/workspace"
if SRC.endswith(".jsonl"):  # import sanitized public seed (repo installs)
    n = 0
    with P.db() as c:
        c.execute("DELETE FROM projects WHERE origin='seed'")
        for line in open(SRC):
            r = json.loads(line)
            c.execute("""INSERT INTO projects(address,name,impl,bytecode_hash,selector_hash,selectors,standard,mint_method,mint_selector,getters,outcome,origin,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (r["address"], r.get("name"), r.get("impl"), r["bytecode_hash"], r["selector_hash"], json.dumps(r["selectors"]),
              r.get("standard"), r.get("mint_method"), r.get("mint_selector"), json.dumps(r.get("getters") or []), r.get("outcome"), "seed", P.now(), P.now())); n += 1
    print(f"seeded {n} projects from {SRC}"); sys.exit()
def load(f):
    try: return json.load(open(f))
    except Exception: return None
items = {}
seen = load(os.path.join(SRC, "agent_mint_seen.json")) or {}
for k, v in (seen.get("activities") or {}).items():
    c = v.get("contract")
    if not (c and re.fullmatch(r"0x[0-9a-fA-F]{40}", c)): continue
    st = v.get("status", "")
    outcome = "success" if st.startswith(("minted", "claimed")) else "fail" if "sold_out" in st or "fail" in st else "skipped" if st.startswith("skipped") else "unknown"
    reason = v.get("cost") or v.get("free_quota") or (v.get("note") or "")[:160]
    items[c.lower()] = {"name": v.get("name") or k, "url": v.get("url"), "outcome": outcome, "status": st, "reason": reason if outcome != "success" else None}
for f in glob.glob(os.path.join(SRC, "pv_*.json")):
    d = (load(f) or {}).get("data") or {}; p = d.get("parsedTx") or {}; c = p.get("contractAddress")
    if not c: continue
    s = d.get("simulationResult") or {}
    it = items.setdefault(c.lower(), {"name": os.path.basename(f)[3:-5], "outcome": "unknown", "status": "preview"})
    it["mint_selector"] = p.get("action")
    if s.get("simulationErrorDetail"): it.setdefault("reason", str(s["simulationErrorDetail"])[:160])
rpc = P.RPC(); addrs = list(items)
codes = rpc.batch([("eth_getCode", [a, "latest"]) for a in addrs])
impls = rpc.batch([("eth_getStorageAt", [a, P.SLOT_1967_IMPL, "latest"]) for a in addrs])
need = {a: P.dec_addr(r["result"]) for a, r in zip(addrs, impls) if r and r.get("result") and int(r["result"], 16)}
icodes = dict(zip(need, rpc.batch([("eth_getCode", [i, "latest"]) for i in need.values()]))) if need else {}
allsels = set(); rows = []
for a, r in zip(addrs, codes):
    code = (icodes.get(a) or r or {}).get("result") or "0x"
    if len(code) <= 2: continue
    sels, _ = P.selectors_from_bytecode(code); allsels |= set(sels)
    rows.append((a, code, sels))
names = P.lookup_sigs(sorted(allsels))
n = 0
with P.db() as c:
    c.execute("DELETE FROM projects WHERE origin='seed'")
    for a, code, sels in rows:
        it = items[a]; ms = it.get("mint_selector")
        mm = names.get(ms) if ms else next((names.get(s) for s in sels if s in {P.sel(x) for x in P.MINT_SIGS}), None)
        getters = [g for g in P.GETTERS if P.sel(g + "()") in sels]
        c.execute("""INSERT INTO projects(address,url,name,impl,bytecode_hash,selector_hash,selectors,standard,mint_method,mint_selector,
          getters,outcome,failure_reason,notes,origin,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (a, it.get("url"), it["name"], need.get(a), hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()[:16],
           hashlib.sha256(",".join(sels).encode()).hexdigest()[:16], json.dumps(sels), None, mm, ms, json.dumps(getters),
           "historical_unverified:" + it["outcome"], it.get("reason"), "imported status=" + it.get("status", ""), "seed", P.now(), P.now()))
        n += 1
print(f"seeded {n} projects ({len(items)} candidates, {len(items)-n} without code on BSC)")
