#!/usr/bin/env python3
"""BSC Mint pre-check toolkit. READ-ONLY: never signs, never broadcasts, never approves, never pays,
never loads private keys. Simulation only via eth_call / eth_estimateGas."""
import sys, os, re, json, time, hashlib, sqlite3, argparse, datetime, concurrent.futures as cf
import requests
try:
    from eth_utils import keccak
except ImportError:
    from Crypto.Hash import keccak as _k
    def keccak(b): h = _k.new(digest_bits=256); h.update(b); return h.digest()

# ---------------- SAFETY GUARD ----------------
FORBIDDEN_METHODS = {"eth_sendTransaction", "eth_sendRawTransaction", "eth_sign", "personal_sign",
                     "eth_signTransaction", "eth_signTypedData", "eth_signTypedData_v4", "wallet_addEthereumChain"}
ALLOWED_METHODS = {"eth_call", "eth_estimateGas", "eth_getCode", "eth_getStorageAt", "eth_getBalance",
                   "eth_blockNumber", "eth_chainId", "eth_getTransactionCount", "eth_gasPrice", "eth_getBlockByNumber",
                   "eth_getTransactionByHash", "eth_getTransactionReceipt"}
for _k_ in list(os.environ):
    if re.search(r"PRIV|MNEMONIC|SEED|SECRET", _k_, re.I):
        pass  # never read; we do not touch these variables

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "data", "history.db")
RPCS = [u for u in os.environ.get("BSC_RPCS", "").split(",") if u] + [
    "https://bsc-dataseed.bnbchain.org", "https://bsc-dataseed1.defibit.io", "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed1.ninicoin.io", "https://1rpc.io/bnb"]
DUMMY = "0x000000000000000000000000000000000000dEaD"
UA = {"User-Agent": "Mozilla/5.0 bsc-mint-precheck (read-only)"}

def sel(sig): return "0x" + keccak(sig.encode()).hex()[:8]

class RPC:
    def __init__(s): s.i = 0; s.calls = 0
    def batch(s, reqs):
        for r in reqs:
            if r[0] in FORBIDDEN_METHODS or r[0] not in ALLOWED_METHODS:
                raise PermissionError(f"blocked non-read-only RPC method {r[0]}")
        out = [None] * len(reqs)
        for chunk in range(0, len(reqs), 40):
            part = reqs[chunk:chunk + 40]
            body = [{"jsonrpc": "2.0", "id": j, "method": m, "params": p} for j, (m, p) in enumerate(part)]
            last = None
            for t in range(len(RPCS)):
                url = RPCS[(s.i + t) % len(RPCS)]
                try:
                    r = requests.post(url, json=body, timeout=15, headers=UA); s.calls += 1
                    js = r.json()
                    if not isinstance(js, list): raise ValueError(str(js)[:200])
                    for x in js: out[chunk + x["id"]] = x
                    s.i = (s.i + t) % len(RPCS); break
                except Exception as e: last = e
            else: raise RuntimeError(f"all RPCs failed: {last}")
        return out
    def one(s, m, p):
        return s.batch([(m, p)])[0]

# ---------------- ABI helpers ----------------
def w(x): return hex(int(x))[2:].rjust(64, "0") if not isinstance(x, str) else x.lower().replace("0x", "").rjust(64, "0")
def dec_uint(h):
    try: return int(h[:66], 16) if h and h != "0x" else None
    except: return None
def dec_str(h):
    try:
        b = bytes.fromhex(h[2:])
        if len(b) >= 64:
            off = int.from_bytes(b[:32], "big"); ln = int.from_bytes(b[off:off+32], "big")
            if ln < 1000: return b[off+32:off+32+ln].decode("utf-8", "replace")
        return b.rstrip(b"\0").decode("utf-8", "replace").strip("\0") or None
    except: return None
def dec_addr(h): return "0x" + h[-40:] if h and len(h) >= 42 else None
def decode_revert(data):
    if not data or data == "0x": return "(no revert data)"
    if data.startswith("0x08c379a0"): return "Error: " + (dec_str("0x" + data[10:]) or "?")
    if data.startswith("0x4e487b71"): return f"Panic(0x{int(data[10:74],16):x})"
    return "custom error " + data[:10] + ((" = " + lookup_sigs([data[:10]]).get(data[:10], "?")) if len(data) >= 10 else "")

_sigcache = {}
def lookup_sigs(sels):
    need = [x for x in sels if x not in _sigcache]
    for i in range(0, len(need), 60):
        part = need[i:i+60]
        try:
            r = requests.get("https://api.openchain.xyz/signature-database/v1/lookup",
                             params={"function": ",".join(part), "filter": "true"}, timeout=12).json()
            for k, v in (r.get("result", {}).get("function") or {}).items():
                _sigcache[k] = v[0]["name"] if v else None
        except Exception: pass
    for x in [x for x in need if not _sigcache.get(x)][:40]:  # fallback: 4byte.directory
        try:
            r = requests.get("https://www.4byte.directory/api/v1/signatures/", params={"hex_signature": x}, timeout=8).json()
            res = sorted(r.get("results") or [], key=lambda z: z.get("id", 0))
            if res: _sigcache[x] = res[0]["text_signature"]
        except Exception: pass
    return {x: _sigcache.get(x) for x in sels}

def selectors_from_bytecode(code):
    b = bytes.fromhex(code[2:]); i = 0; found = set(); ops = []
    while i < len(b):
        op = b[i]
        if 0x60 <= op <= 0x7f:
            n = op - 0x5f; ops.append((op, b[i+1:i+1+n])); i += 1 + n
        else: ops.append((op, None)); i += 1
    for j, (op, v) in enumerate(ops):
        if op == 0x63 and v and len(v) == 4:
            nxt = [o for o, _ in ops[j+1:j+4]]
            if 0x14 in nxt or (j > 0 and ops[j-1][0] in (0x80, 0x81)):  # EQ nearby / DUP before
                found.add("0x" + v.hex())
    opset = {op for op, _ in ops}
    return sorted(found), {"delegatecall": 0xf4 in opset, "selfdestruct": 0xff in opset,
                           "call": 0xf1 in opset, "create2": 0xf5 in opset}

# ---------------- knowledge ----------------
GETTERS = {  # name -> kind
 "name": "str", "symbol": "str", "totalSupply": "uint", "maxSupply": "uint", "MAX_SUPPLY": "uint", "maxTokens": "uint",
 "collectionSize": "uint", "totalMinted": "uint", "publicMinted": "uint", "MAX_PUBLIC": "uint", "cap": "uint", "decimals": "uint", "price": "uint", "mintPrice": "uint", "cost": "uint",
 "publicPrice": "uint", "PRICE": "uint", "MINT_PRICE": "uint", "publicSalePrice": "uint", "mintFee": "uint", "fee": "uint",
 "maxPerWallet": "uint", "MAX_PER_WALLET": "uint", "maxMintPerWallet": "uint", "maxPerTx": "uint", "maxMintAmount": "uint",
 "walletLimit": "uint", "freeSupply": "uint", "freeMinted": "uint", "freeMintsRemaining": "uint", "remaining": "uint",
 "paused": "bool", "saleActive": "bool", "isPublicSaleOpen": "bool", "publicSaleActive": "bool", "mintActive": "bool",
 "isMintActive": "bool", "mintEnabled": "bool", "saleIsActive": "bool", "isActive": "bool", "mintOpen": "bool",
 "startTime": "uint", "endTime": "uint", "mintStart": "uint", "mintEnd": "uint", "publicSaleStartTime": "uint", "saleStart": "uint",
 "merkleRoot": "b32", "whitelistMerkleRoot": "b32", "signer": "addr", "owner": "addr", "admin": "addr",
 "treasury": "addr", "withdrawAddress": "addr", "feeRecipient": "addr", "paymentToken": "addr", "token": "addr", "registry": "addr"}
WALLET_GETTERS = {"balanceOf(address)": "uint", "numberMinted(address)": "uint", "mintedCount(address)": "uint",
                  "minted(address)": "uint", "mintCount(address)": "uint", "hasMinted(address)": "bool", "claimed(address)": "bool",
                  "whitelist(address)": "bool", "allowlist(address)": "uint", "isWhitelisted(address)": "bool"}
# signature -> arg template ; q=qty, w=wallet
MINT_SIGS = {"mint()": "", "mint(uint256)": "q", "publicMint()": "", "publicMint(uint256)": "q", "mintTo(address)": "w",
 "mintTo(address,uint256)": "wq", "mint(address,uint256)": "wq", "mint(address)": "w", "claim()": "", "claim(uint256)": "q",
 "freeMint()": "", "freeMint(uint256)": "q", "safeMint(address)": "w", "safeMint(address,uint256)": "wq",
 "purchase(uint256)": "q", "buy(uint256)": "q", "mintPublic(uint256)": "q", "mintNFT()": "", "mintNFT(uint256)": "q",
 "allowlistMint(uint256,bytes32[])": "q[]", "whitelistMint(uint256,bytes32[])": "q[]", "presaleMint(uint256,bytes32[])": "q[]",
 "mint(uint256,bytes32[])": "q[]", "claim(bytes32[])": "[]", "mintWithSignature(uint256,bytes)": "qS", "mint(uint256,bytes)": "qS",
 "mint(bytes)": "S", "claim(address,uint256,bytes32[])": "wq[]", "mintAgent()": "", "register()": ""}
OWNER_POWERS = ["setPrice(uint256)", "setMintPrice(uint256)", "setCost(uint256)", "withdraw()", "withdraw(address)",
 "withdrawAll()", "pause()", "unpause()", "setPaused(bool)", "upgradeTo(address)", "upgradeToAndCall(address,bytes)",
 "setBaseURI(string)", "transferOwnership(address)", "setMerkleRoot(bytes32)", "setSigner(address)", "mintFor(address,uint256)",
 "ownerMint(address,uint256)", "setApprovalForAll(address,bool)", "approve(address,uint256)", "transferFrom(address,address,uint256)",
 "blacklist(address)", "setBlacklist(address,bool)", "setTax(uint256)", "setFee(uint256)"]
IFACES = {"ERC721": "0x80ac58cd", "ERC1155": "0xd9b67a26", "ERC721Metadata": "0x5b5e139f", "ERC165": "0x01ffc9a7"}
SLOT_1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
SLOT_1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1179d6a7ce1e8c03d0c1"
SLOT_OZ_LEGACY = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
SLOT_1822 = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"

# ---------------- entry candidates (custom-named mint functions) ----------------
EXCLUDE_NAMES = re.compile(r"^(transfer|transferFrom|safeTransferFrom|approve|setApprovalForAll|increaseAllowance|decreaseAllowance|"
    r"renounceOwnership|transferOwnership|acceptOwnership|upgradeTo|upgradeToAndCall|initialize|multicall|permit|burn|burnFrom|"
    r"pause|unpause|grantRole|revokeRole|renounceRole|rescue\w*|recover\w*|airdrop\w*|ownerMint|devMint|teamMint|reserve\w*|"
    r"set\w*|withdraw\w*|update\w*|toggle\w*|enable\w*|disable\w*|flip\w*|admin\w*|owner\w*|emergency\w*|sweep\w*|"
    r"batchTransfer\w*|safeBatchTransferFrom|cancel\w*|add\w*|remove\w*|change\w*|configure\w*|lock\w*|unlock\w*)$", re.I)
HINT_NAMES = re.compile(r"(mint|claim|buy|take|gift|get|purchase|join|participate|enter|register|redeem|drop|open|public|free|sale)", re.I)

def _parse_sig(sig):
    m = re.match(r"^(\w+)\((.*)\)$", sig or ""); 
    return (m.group(1), [x for x in m.group(2).split(",") if x]) if m else (None, None)

def entry_candidates(abi=None, known=None, views=(), standard_hits=()):
    """List possible user entry functions. abi (verified) wins; else known selector->signature map from bytecode lookup.
    Returns ranked list of dicts. These are CANDIDATES ONLY - need human/site confirmation."""
    fns = []
    if abi:
        for it in abi:
            if it.get("type") != "function": continue
            mut = it.get("stateMutability") or ("payable" if it.get("payable") else "view" if it.get("constant") else "nonpayable")
            if mut in ("view", "pure"): continue
            ins = it.get("inputs") or []
            sig = f"{it['name']}({','.join(i['type'] for i in ins)})"
            fns.append({"signature": sig, "name": it["name"], "types": [i["type"] for i in ins],
                        "argnames": [i.get("name") or "" for i in ins], "payable": mut == "payable", "source": "abi"})
    else:
        for s, n in (known or {}).items():
            nm, ty = _parse_sig(n)
            if nm is None or n in views: continue
            fns.append({"signature": n, "name": nm, "types": ty, "argnames": [], "payable": None, "source": "4byte/openchain"})
    out = []
    for f in fns:
        nm = f["name"]
        if EXCLUDE_NAMES.match(nm) or nm.startswith(("_", "is", "has")): continue
        if f["source"] != "abi" and (nm in GETTERS or re.match(r"^(get[A-Z_]|tokenURI|supportsInterface|balanceOf|ownerOf|allowance)", nm)
                or re.search(r"(ed|By|Of|Open|Active|Price|Count|Limit|Supply|Status|Time|URI|Root)$", nm)): continue  # likely view
        if f["types"] and set(f["types"]) <= {"address"} and len(f["types"]) >= 2: continue  # transfer-like
        score, why = 0, []
        if f["payable"]: score += 3; why.append("payable")
        if HINT_NAMES.search(nm): score += 2; why.append("名稱像入口")
        an = " ".join(f["argnames"]).lower()
        if re.search(r"qty|quantity|amount|count|num|_n\b|times", an) or (f["types"] in (["uint256"], ["uint8"], ["uint16"], ["uint32"]) ): score += 1; why.append("數量/金額參數")
        if "bytes32[]" in f["types"] or "proof" in an: score += 1; why.append("merkle proof 參數")
        if f["signature"] in standard_hits: score += 2; why.append("標準 mint 名稱")
        out.append({**f, "score": score, "why": why})
    out.sort(key=lambda c: (-c["score"], c["signature"]))
    return out

def simple_args(types, wallet, qty):
    """Encode only trivially fillable args (uint=qty, address=wallet). None if not auto-fillable."""
    enc = ""
    for t in types:
        if re.fullmatch(r"uint\d*", t): enc += w(qty)
        elif t == "address": enc += w(wallet)
        elif t == "bool": enc += w(1)
        else: return None
    return enc

def simulate_candidates(cands, rpc, addr, W, qty, price, limit=6):
    """read-only eth_call + eth_estimateGas only (RPC class still blocks send/sign)."""
    for c in cands[:limit]:
        args = simple_args(c["types"], W, qty)
        if args is None: c["sim"] = "略過（參數無法自動填）"; continue
        data = sel(c["signature"]) + args
        vals = [0] + ([price * qty] if price and c["payable"] is not False else [])
        for v in vals:
            tx = {"from": W, "to": addr, "data": data, "value": hex(v)}
            rr = rpc.batch([("eth_call", [tx, "latest"]), ("eth_estimateGas", [tx])])
            ret = rr[0].get("result") or "0x"
            if not rr[0].get("error") and rr[1].get("result") and c["source"] != "abi" and v == 0 and len(ret) > 2:
                c["sim"] = "eth_call 有回傳值，可能是 view 函式"; break
            if not rr[0].get("error") and rr[1].get("result"):
                c["sim"] = f"eth_call+estimateGas 通過 (value={v/1e18} BNB)"; c["pass_value"] = v; c["score"] += 3; c["why"].append("模擬通過"); break
            e = rr[0].get("error") or rr[1].get("error") or {}
            d = e.get("data") if isinstance(e.get("data"), str) else ""
            c["sim"] = "失敗 " + str(decode_revert(d) if d else e.get("message"))
    cands.sort(key=lambda c: (-c["score"], c["signature"]))
    return cands

PRICE_ERR = re.compile(r"wrong (bnb )?amount|insufficient|incorrect (value|payment|price)|invalid (value|price|amount)|value", re.I)
def price_override(sims, ec, price):
    """If standard sims failed with a price error but a candidate passed read-only at a different value, describe it."""
    if any(s.get("ok") for s in sims): return None
    if not any(PRICE_ERR.search(str(s.get("revert") or "")) for s in sims): return None
    ok = [c for c in ec if c.get("pass_value") is not None and c["pass_value"] != (price or 0)]
    if not ok: return None
    v = ok[0]["pass_value"]
    head = "可能目前免費" if v == 0 else f"實際價格可能為 {v/1e18} BNB"
    return f"{head}（{ok[0]['signature']} 以 {v/1e18} BNB 模擬通過，getter 價格 {(price or 0)/1e18} BNB 失敗），需官網確認"

CANDIDATE_NOTE = "以下為「候選入口函式」，依提示排序，需人工/官網確認才是真正的 mint 入口；本工具不簽名、不送出。"

# ---------------- DB ----------------
SCHEMA = """CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, address TEXT, url TEXT, name TEXT, impl TEXT,
 bytecode_hash TEXT, selector_hash TEXT, selectors TEXT, source_hash TEXT, standard TEXT, mint_method TEXT, mint_selector TEXT,
 price_wei TEXT, params TEXT, getters TEXT, outcome TEXT, failure_reason TEXT, notes TEXT, origin TEXT, timings TEXT,
 created_at TEXT, updated_at TEXT);
CREATE INDEX IF NOT EXISTS ix_addr ON projects(address); CREATE INDEX IF NOT EXISTS ix_bch ON projects(bytecode_hash);"""
def db():
    c = sqlite3.connect(DB); c.executescript(SCHEMA); c.row_factory = sqlite3.Row; return c
def now(): return datetime.datetime.now().astimezone().isoformat(timespec="seconds")

def match_history(feat):
    best = None
    with db() as c:
        for r in c.execute("SELECT * FROM projects WHERE selectors IS NOT NULL AND selectors!=''"):
            if r["address"] and feat["address"] and r["address"].lower() == feat["address"].lower() and r["origin"] == "precheck":
                continue
            score, why = 0.0, []
            if r["bytecode_hash"] and r["bytecode_hash"] == feat["bytecode_hash"]: score = 1.0; why.append("bytecode 完全相同")
            if feat.get("impl") and r["impl"] and r["impl"].lower() == feat["impl"].lower(): score = max(score, 0.98); why.append("同一實作合約")
            if feat.get("source_hash") and r["source_hash"] == feat["source_hash"]: score = max(score, 0.97); why.append("原始碼相同")
            a, b = set(json.loads(r["selectors"])), set(feat["selectors"])
            if a and b:
                j = len(a & b) / len(a | b)
                if j > score: score = j; why = why + [f"selector Jaccard {j:.2f}"]
            if not best or score > best["score"]:
                best = {"score": round(score, 3), "why": why, "id": r["id"], "address": r["address"], "name": r["name"],
                        "mint_method": r["mint_method"], "getters": json.loads(r["getters"] or "[]"), "outcome": r["outcome"],
                        "failure_reason": r["failure_reason"]}
    return best

# ---------------- URL ----------------
def scan_url(url, T):
    t = time.time(); out = {"url": url, "addresses": [], "chain_ids": [], "functions": [], "prices": [], "times": [],
                            "approval_flags": [], "bundles": 0, "errors": []}
    try: html = requests.get(url, timeout=20, headers=UA).text
    except Exception as e: out["errors"].append(str(e)); T["fetch"] = round(time.time()-t, 3); return out
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)', html)
    srcs = [requests.compat.urljoin(url, s) for s in srcs][:25]
    texts = [html]
    with cf.ThreadPoolExecutor(8) as ex:
        for r in ex.map(lambda u: requests.get(u, timeout=20, headers=UA).text if True else "", srcs):
            texts.append(r)
    out["bundles"] = len(srcs); blob = "\n".join(texts)
    addrs = {}
    for a in re.findall(r"0x[a-fA-F0-9]{40}(?![a-fA-F0-9])", blob):
        if int(a, 16) > 0xffff: addrs[a.lower()] = addrs.get(a.lower(), 0) + 1
    out["addresses"] = sorted(addrs, key=lambda k: -addrs[k])[:30]
    out["chain_ids"] = sorted(set(re.findall(r"chainId['\"]?\s*[:=]\s*['\"]?(0x38|56|97|0x61|1|8453)\b", blob)))
    out["functions"] = sorted(set(re.findall(r"['\"]((?:public|free|allowlist|whitelist|presale)?[mM]int\w{0,20}|claim\w{0,15})['\"]", blob)))[:40]
    out["prices"] = sorted(set(re.findall(r"(?:price|cost|mintPrice)['\"]?\s*[:=]\s*['\"]?([0-9.]+(?:e1?8)?)", blob)))[:15]
    out["times"] = sorted(set(re.findall(r"(?:start|open|launch)\w*['\"]?\s*[:=]\s*['\"]?(1[6-9]\d{8})\b", blob, re.I)))[:10]
    for kw in ["setApprovalForAll", "increaseAllowance", "permit", "approve", "eth_sign", "signTypedData", "transferFrom", "MaxUint256", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]:
        if kw in blob: out["approval_flags"].append(kw)
    T["fetch"] = round(time.time()-t, 3); return out

# ---------------- core ----------------
def sourcify(addr):
    try:
        r = requests.get(f"https://sourcify.dev/server/v2/contract/56/{addr}?fields=abi,sources,deployment", timeout=15, headers=UA)
        if r.status_code == 200:
            j = r.json(); src = json.dumps(j.get("sources") or {}, sort_keys=True)
            return {"abi": j.get("abi"), "source_hash": hashlib.sha256(src.encode()).hexdigest()[:16] if j.get("sources") else None,
                    "deployment": j.get("deployment"), "via": "sourcify"}
    except Exception: pass
    key = os.environ.get("ETHERSCAN_API_KEY") or os.environ.get("BSCSCAN_API_KEY")
    if key:
        try:
            j = requests.get("https://api.etherscan.io/v2/api", params={"chainid": 56, "module": "contract", "action": "getsourcecode",
                             "address": addr, "apikey": key}, timeout=15).json()
            res = (j.get("result") or [{}])[0]
            if res.get("ABI", "").startswith("["):
                return {"abi": json.loads(res["ABI"]), "source_hash": hashlib.sha256(res.get("SourceCode", "").encode()).hexdigest()[:16],
                        "via": "etherscan-v2", "name": res.get("ContractName")}
        except Exception: pass
    return None

def precheck(addr, wallet=None, qty=1, url_info=None, T=None):
    T = T if T is not None else {}; rpc = RPC(); rep = {"address": addr, "wallet": wallet or None, "qty": qty, "warnings": []}
    W = wallet or DUMMY
    t = time.time()
    r = rpc.batch([("eth_getCode", [addr, "latest"]), ("eth_getStorageAt", [addr, SLOT_1967_IMPL, "latest"]),
                   ("eth_getStorageAt", [addr, SLOT_1967_BEACON, "latest"]), ("eth_getStorageAt", [addr, SLOT_1822, "latest"]),
                   ("eth_getStorageAt", [addr, SLOT_1967_ADMIN, "latest"]), ("eth_blockNumber", []), ("eth_getBalance", [addr, "latest"]),
                   ("eth_gasPrice", []), ("eth_getStorageAt", [addr, SLOT_OZ_LEGACY, "latest"])])
    code = r[0].get("result") or "0x"
    rep["is_contract"] = len(code) > 2; rep["block"] = dec_uint(r[5].get("result")); rep["contract_balance_bnb"] = (dec_uint(r[6].get("result")) or 0) / 1e18
    gasprice = dec_uint(r[7].get("result")) or 10**8
    if not rep["is_contract"]:
        T["rpc"] = round(time.time()-t, 3); rep["conclusion"] = "不是合約"; return rep
    proxy, impl = None, None
    m = re.fullmatch(r"0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3", code.lower())
    if m: proxy, impl = "EIP-1167 minimal clone", "0x" + m.group(1)
    for idx, kind in ((1, "EIP-1967"), (3, "EIP-1822"), (8, "OZ legacy (zeppelinos) proxy")):
        v = r[idx].get("result")
        if not impl and v and int(v, 16): proxy, impl = kind, dec_addr(v)
    bv = r[2].get("result")
    if not impl and bv and int(bv, 16):
        beacon = dec_addr(bv); proxy = "EIP-1967 beacon"
        impl = dec_addr(rpc.one("eth_call", [{"to": beacon, "data": sel("implementation()")}, "latest"]).get("result"))
    admin = dec_addr(r[4].get("result")) if r[4].get("result") and int(r[4]["result"], 16) else None
    rep["proxy"] = {"type": proxy, "implementation": impl, "admin_slot": admin}
    logic = rpc.one("eth_getCode", [impl, "latest"]).get("result") if impl else code
    sels_, ops = selectors_from_bytecode(logic)
    if impl: sels_ = sorted(set(sels_) | set(selectors_from_bytecode(code)[0]))
    T["rpc"] = round(time.time()-t, 3)

    t = time.time()
    with cf.ThreadPoolExecutor(2) as ex:
        fsrc = ex.submit(sourcify, impl or addr); fsig = ex.submit(lookup_sigs, sels_)
        ver = fsrc.result(); sigmap = fsig.result()
    if ver is None and impl: ver = sourcify(addr)
    rep["verified"] = bool(ver and ver.get("abi")); rep["verified_via"] = ver and ver.get("via")
    abi_sigs = {}; views = set()
    if ver and ver.get("abi"):
        for it in ver["abi"]:
            if it.get("type") == "function":
                s = f"{it['name']}({','.join(i['type'] for i in it['inputs'])})"; abi_sigs[sel(s)] = s
                if it.get("stateMutability") in ("view", "pure") or it.get("constant"): views.add(s)
    names = dict(sigmap); names.update(abi_sigs)
    known = {s: n for s, n in names.items() if n}
    unknown = [s for s in sels_ if not names.get(s)]
    rep["selectors"] = {"count": len(sels_), "known": known, "unknown": unknown}
    rep["opcodes"] = ops
    feat = {"address": addr, "impl": impl, "bytecode_hash": hashlib.sha256(bytes.fromhex(logic[2:])).hexdigest()[:16],
            "selectors": sels_, "source_hash": ver and ver.get("source_hash")}
    feat["selector_hash"] = hashlib.sha256(",".join(sels_).encode()).hexdigest()[:16]
    rep["features"] = {k: v for k, v in feat.items() if k != "selectors"}
    T["abi"] = round(time.time()-t, 3)

    t = time.time(); hist = match_history(feat); T["match"] = round(time.time()-t, 3)
    rep["history_match"] = hist if hist and hist["score"] >= 0.5 else None
    familiar = bool(hist and hist["score"] >= 0.8) or rep["verified"]

    # ---- parallel getters (one batch) ----
    t = time.time(); present = set(sels_) | set(abi_sigs)
    calls = []; ctx = []
    getter_names = list(GETTERS)
    if rep["history_match"]: getter_names = list(dict.fromkeys((rep["history_match"]["getters"] or []) + getter_names))
    for g in getter_names:
        s = sel(g + "()")
        if s in present or not sels_:
            calls.append(("eth_call", [{"to": addr, "data": s}, "latest"])); ctx.append(("g", g))
    for g in WALLET_GETTERS:
        s = sel(g)
        if s in present and wallet:
            calls.append(("eth_call", [{"to": addr, "data": s + w(wallet)}, "latest"])); ctx.append(("wg", g))
    for n, iid in IFACES.items():
        calls.append(("eth_call", [{"to": addr, "data": sel("supportsInterface(bytes4)") + iid[2:].ljust(64, "0")}, "latest"])); ctx.append(("if", n))
    if wallet: calls.append(("eth_getBalance", [wallet, "latest"])); ctx.append(("wb", None))
    res = rpc.batch(calls); G, WG, IF = {}, {}, {}
    for (k, n), x in zip(ctx, res):
        v = x.get("result") if x else None
        if k == "g" and v and v != "0x":
            kind = GETTERS[n]
            G[n] = dec_str(v) if kind == "str" else dec_addr(v) if kind == "addr" else (v[:66] if kind == "b32" else
                   bool(dec_uint(v)) if kind == "bool" else dec_uint(v))
        elif k == "wg" and v and v != "0x": WG[n] = dec_uint(v)
        elif k == "if": IF[n] = bool(v and v != "0x" and dec_uint(v) == 1)
        elif k == "wb": rep["wallet_balance_bnb"] = (dec_uint(v) or 0) / 1e18
    rep["getters"] = G; rep["wallet_reads"] = WG
    std = "ERC1155" if IF.get("ERC1155") else "ERC721" if IF.get("ERC721") else ("ERC20" if "decimals" in G and sel("transfer(address,uint256)") in present else "unknown")
    rep["standard"] = std
    price = next((G[k] for k in ("mintPrice", "price", "cost", "publicPrice", "PRICE", "MINT_PRICE", "publicSalePrice", "mintFee", "fee") if isinstance(G.get(k), int)), None)
    maxs = next((G[k] for k in ("maxSupply", "MAX_SUPPLY", "maxTokens", "collectionSize", "cap") if isinstance(G.get(k), int)), None)
    ts = G.get("totalSupply")
    rep["price_wei"] = price; rep["price_bnb"] = price / 1e18 if price is not None else None
    rep["supply"] = {"total": ts, "max": maxs, "remaining": (maxs - ts) if isinstance(maxs, int) and isinstance(ts, int) and std != "ERC20" else G.get("remaining")}
    nowts = int(time.time()); st = next((G[k] for k in ("startTime", "mintStart", "publicSaleStartTime", "saleStart") if G.get(k)), None)
    en = next((G[k] for k in ("endTime", "mintEnd") if G.get(k)), None)
    flags = {k: G[k] for k in ("paused", "saleActive", "isPublicSaleOpen", "publicSaleActive", "mintActive", "isMintActive", "mintEnabled", "saleIsActive", "isActive", "mintOpen") if k in G}
    rep["status_flags"] = {**flags, "start": st, "end": en}
    rep["requirements"] = {"merkle": bool(G.get("merkleRoot") or G.get("whitelistMerkleRoot")) and int((G.get("merkleRoot") or G.get("whitelistMerkleRoot") or "0x0"), 16) != 0,
                           "signature": bool(G.get("signer")) and G.get("signer") != "0x" + "0"*40,
                           "erc20_payment": G.get("paymentToken") or None}
    T["rpc"] = round(T["rpc"] + time.time() - t, 3)

    # ---- mint candidates & simulation ----
    t = time.time(); cands = []
    pref = rep["history_match"]["mint_method"] if rep["history_match"] else None
    for s, tmpl in MINT_SIGS.items():
        if sel(s) in present: cands.append((s, tmpl))
    for s, n in known.items():  # verified/looked-up names containing mint/claim not in table
        nm = n.split("(")[0]
        if (re.match(r"^(\w*[mM]int\w*|claim\w*)\(", n) and n not in MINT_SIGS and "owner" not in n.lower() and "admin" not in n.lower()
                and nm not in GETTERS and not re.search(r"(ed|Open|Active|Price|Count|Limit|Supply|Status|Start|End|Time|Remaining)$", nm)
                and n not in views and not re.search(r"(s|By|Nonce|Requests|Of)$", nm)
                and not nm.startswith(("reserve", "set", "is", "get", "total", "max", "cancel"))):
            cands.append((n, None))
    if pref: cands.sort(key=lambda c: c[0] != pref)
    rep["mint_candidates"] = [c[0] for c in cands]
    sims = []
    for s, tmpl in cands[:6]:
        if tmpl is None and s.endswith("()"): tmpl = ""
        if tmpl is None or "[]" in tmpl or "S" in tmpl:
            sims.append({"method": s, "skipped": "需要 merkle proof / 簽名 / 未知參數，無法自動模擬"}); continue
        data = sel(s) + "".join(w(W) if ch == "w" else w(qty) for ch in tmpl)
        value = (price or 0) * (qty if "q" in tmpl else 1)
        tx = {"from": W, "to": addr, "data": data, "value": hex(value)}
        rr = rpc.batch([("eth_call", [tx, "latest"]), ("eth_estimateGas", [tx])])
        sim = {"method": s, "calldata": data, "value_wei": value, "value_bnb": value / 1e18, "from": W}
        if rr[0].get("error"):
            e = rr[0]["error"]; sim["ok"] = False; sim["revert"] = decode_revert(e.get("data") if isinstance(e.get("data"), str) else "") if e.get("data") else e.get("message")
        else: sim["ok"] = True
        if rr[1].get("result"): sim["gas"] = dec_uint(rr[1]["result"]); sim["gas_cost_bnb"] = sim["gas"] * gasprice / 1e18
        elif rr[1].get("error"): sim["gas_error"] = rr[1]["error"].get("message")
        sims.append(sim)
        if sim.get("ok") and "gas" in sim: break
    rep["simulation"] = sims
    try:
        ec = entry_candidates(ver.get("abi") if ver else None, known, views, set(c[0] for c in cands))
        ec = simulate_candidates(ec, rpc, addr, W, qty, price) if ec else ec
    except Exception as e:
        ec = []; rep["warnings"].append(f"entry candidates error: {e}")
    rep["entry_candidates"] = {"note": CANDIDATE_NOTE, "basis": "verified ABI" if rep["verified"] else "bytecode selectors + 4byte/openchain",
                               "items": [{k: c.get(k) for k in ("signature", "payable", "score", "why", "sim", "pass_value", "source")} for c in ec[:10]]}
    T["simulate"] = round(time.time()-t, 3)

    # ---- risk ----
    t = time.time(); reasons = []; score = 0
    powers = [p for p in OWNER_POWERS if sel(p) in present]
    rep["owner_powers"] = powers
    if G.get("owner"): reasons.append(f"有 owner {G['owner']}" + ("（已放棄）" if G["owner"] == "0x" + "0"*40 else "")); score += 0 if G["owner"] == "0x"+"0"*40 else 1
    if any(p.startswith(("setPrice", "setMintPrice", "setCost")) for p in powers): reasons.append("owner 可改價格"); score += 1
    if proxy and proxy != "EIP-1167 minimal clone": reasons.append(f"可升級代理（{proxy}），邏輯可被替換"); score += 2
    if any(p in powers for p in ("pause()", "setPaused(bool)")) or "paused" in G: reasons.append("可暫停"); score += 1
    if not rep["verified"]: reasons.append("原始碼未驗證（Sourcify/Etherscan 查無）"); score += 2
    if ops.get("selfdestruct"): reasons.append("bytecode 含 SELFDESTRUCT"); score += 2
    if ops.get("delegatecall") and not proxy: reasons.append("非代理卻含 DELEGATECALL（可能是 library/multicall，需留意）"); score += 1
    if any(p.startswith(("blacklist", "setBlacklist", "setTax", "setFee")) for p in powers): reasons.append("有黑名單/稅率函式（貔貅特徵）"); score += 3
    if std == "ERC20" and price is None and cands: reasons.append("ERC20 mint/claim：注意是否要求 approve 或轉帳")
    if rep["requirements"]["erc20_payment"]: reasons.append(f"以 ERC20 付款（{G.get('paymentToken')}），會要求 approve"); score += 2
    for k in ("treasury", "withdrawAddress", "feeRecipient"):
        if G.get(k): reasons.append(f"收款地址 {k}={G[k]}")
    if price and price > 5 * 10**16: reasons.append(f"單價偏高 {price/1e18} BNB"); score += 1
    if url_info and url_info.get("approval_flags"):
        fl = [f for f in url_info["approval_flags"] if f in ("setApprovalForAll", "permit", "increaseAllowance", "eth_sign", "MaxUint256", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")]
        if fl: reasons.append("網站 JS 含授權/簽名呼叫：" + ",".join(fl[:5]) + "（mint 不應需要）"); score += 2
    if url_info and url_info.get("chain_ids") and not set(url_info["chain_ids"]) & {"56", "0x38"}:
        reasons.append(f"網站 chainId 非 BSC：{url_info['chain_ids']}"); score += 2
    if hist and hist.get("outcome") and "fail" in (hist["outcome"] or "") and hist["score"] >= 0.8:
        reasons.append(f"相似歷史專案曾失敗：{hist.get('failure_reason')}"); score += 1
    rep["risk"] = {"level": "高" if score >= 6 else "中" if score >= 3 else "低", "score": score, "reasons": reasons}
    T["risk"] = round(time.time()-t, 3)

    # ---- eligibility & conclusion ----
    elig = []
    for k in ("numberMinted(address)", "mintedCount(address)", "minted(address)", "mintCount(address)"):
        if k in WG and isinstance(G.get("maxPerWallet") or G.get("MAX_PER_WALLET") or G.get("maxMintPerWallet"), int):
            lim = G.get("maxPerWallet") or G.get("MAX_PER_WALLET") or G.get("maxMintPerWallet")
            if WG[k] >= lim: elig.append(f"已 mint {WG[k]}/{lim}，額度用完")
    if WG.get("hasMinted(address)") or WG.get("claimed(address)"): elig.append("此錢包已 mint/claim 過")
    if not wallet: elig.append("未提供 --wallet，以 dummy 地址模擬，資格未確認")
    rep["eligibility"] = elig
    ok = next((s for s in sims if s.get("ok")), None)
    rem = rep["supply"]["remaining"]
    rv = " ".join(str(x.get("revert") or "") for x in sims).lower()
    if rep["risk"]["level"] == "高": concl = "高風險"
    elif ok: concl = "可以mint（模擬通過）"
    elif re.search(r"not the owner|onlyowner|ownableunauthorized|accesscontrol|onlyminter|minter role", rv) and not re.search(r"wrong|insufficient|sold", rv): concl = "無公開mint（僅owner/minter）"
    elif price_override(sims, ec, price): concl = price_override(sims, ec, price)
    elif re.search(r"wrong (bnb )?amount|insufficient|incorrect (value|payment|price)|invalid (value|price|amount)|value", rv): concl = "價格不符（getter 讀到的價格與合約要求不同，需核對）"
    elif rem == 0 or re.search(r"sold ?out|exceed(s)? (max )?supply|max supply|soldout", rv): concl = "已售罄"
    elif flags.get("paused") is True or any(v is False for k, v in flags.items() if k != "paused") or (st and st > nowts) or re.search(r"not (started|active|open|live)|paused|notstarted|notactive|closed|not ?open", rv): concl = "未開放"
    elif any("額度" in e or "已 mint" in e for e in elig) or rep["requirements"]["merkle"] or rep["requirements"]["signature"] or re.search(r"already|whitelist|allowlist|proof|not ?eligible|limit|max ?per|notagent|not agent|unauthori[sz]ed|signature|not ?allowed", rv): concl = "不符資格/需白名單或簽名"
    elif not cands and rep["entry_candidates"]["items"]: concl = "標準 mint 名稱未命中，列出候選入口函式（需人工確認）"
    elif not cands: concl = "找不到 mint 函式（也無候選入口）"
    else: concl = "模擬失敗"
    rep["conclusion"] = concl
    rep["needs_ai_analysis"] = (not familiar) and (not cands or len(unknown) > 5)
    if rep["needs_ai_analysis"]:
        os.makedirs(os.path.join(HERE, "ai_queue"), exist_ok=True)
        p = os.path.join(HERE, "ai_queue", f"{addr.lower()}.json")
        json.dump({"address": addr, "impl": impl, "unknown_selectors": unknown, "known": known, "getters": G,
                   "sim": sims, "hint": "陌生合約：請 AI 判讀未知 selector 與 mint 流程"}, open(p, "w"), indent=1, ensure_ascii=False)
        rep["ai_summary_file"] = p
    rep["_feat"] = feat; rep["_used_getters"] = [g for g in G]
    return rep

def save(rep, url, T):
    f = rep.pop("_feat", None); ug = rep.pop("_used_getters", [])
    if not f: return
    ok = next((s for s in rep.get("simulation", []) if s.get("ok")), None)
    with db() as c:
        c.execute("""INSERT INTO projects(address,url,name,impl,bytecode_hash,selector_hash,selectors,source_hash,standard,mint_method,
          mint_selector,price_wei,params,getters,outcome,failure_reason,notes,origin,timings,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (rep["address"], url, (rep.get("getters") or {}).get("name"), f.get("impl"), f["bytecode_hash"], f["selector_hash"],
           json.dumps(f["selectors"]), f.get("source_hash"), rep.get("standard"), ok and ok["method"] or (rep.get("mint_candidates") or [None])[0],
           ok and ok["calldata"][:10], str(rep.get("price_wei")), json.dumps({"qty": rep["qty"], "value_wei": ok and ok["value_wei"]}),
           json.dumps(ug), "sim_ok" if ok else "sim_fail", None if ok else "; ".join(str(s.get("revert") or s.get("skipped")) for s in rep.get("simulation", []))[:400],
           rep["conclusion"], "precheck", json.dumps(T), now(), now()))
        rep["history_id"] = c.execute("SELECT last_insert_rowid()").fetchone()[0]

def summary(rep, T, url_info=None):
    L = []
    g = rep.get("getters", {})
    L.append(f"【結論】{rep.get('conclusion')}　{g.get('name') or ''} {('('+g['symbol']+')') if g.get('symbol') else ''}")
    L.append(f"合約 {rep['address']}  標準 {rep.get('standard')}  代理 {(rep.get('proxy') or {}).get('type') or '無'}  已驗證 {'是' if rep.get('verified') else '否'}")
    if rep.get("is_contract") is False: return "\n".join(L)
    pr = rep.get("price_bnb"); L.append(f"價格 {pr if pr is not None else '未讀到'} BNB　供應 {rep['supply']['total']}/{rep['supply']['max']} 剩 {rep['supply']['remaining']}")
    L.append(f"狀態旗標 {rep.get('status_flags')}  需求 {rep.get('requirements')}")
    L.append("資格：" + ("；".join(rep["eligibility"]) if rep["eligibility"] else "未發現限制") + (f"　錢包讀值 {rep['wallet_reads']}" if rep.get("wallet_reads") else ""))
    L.append(f"風險 {rep['risk']['level']}（{rep['risk']['score']}）：" + "；".join(rep["risk"]["reasons"]))
    for s in rep.get("simulation", [])[:4]:
        if "skipped" in s: L.append(f"模擬 {s['method']}：略過（{s['skipped']}）")
        else: L.append(f"模擬 {s['method']} value={s['value_bnb']} BNB：{'通過' if s['ok'] else '失敗 ' + str(s.get('revert'))}" + (f" gas≈{s['gas']}（≈{s['gas_cost_bnb']:.6f} BNB）" if s.get("gas") else ""))
    if not rep.get("simulation"): L.append("模擬：無可模擬的 mint 函式")
    ec = (rep.get("entry_candidates") or {}).get("items") or []
    if ec:
        L.append("候選入口：" + CANDIDATE_NOTE)
        for c in ec[:5]:
            L.append(f"  - {c['signature']}{' [payable]' if c['payable'] else ''} 分數{c['score']}（{','.join(c['why']) or '無提示'}）" + (f" 模擬：{c['sim']}" if c.get("sim") else ""))
    hm = rep.get("history_match")
    L.append(f"歷史比對：{hm['name'] or hm['address']} 相似度 {hm['score']}（{','.join(hm['why'])}，當時結果 {hm['outcome']}）— 已沿用其識別方法，數值皆即時重查" if hm else "歷史比對：無相似專案")
    if rep.get("needs_ai_analysis"): L.append(f"⚠ 陌生合約，需 AI 判讀：{rep['ai_summary_file']}")
    L.append("耗時(s) " + " ".join(f"{k}={v}" for k, v in T.items()))
    L.append("你要確認：合約地址是否為官方、價格與數量、是否需授權（不應需要）；本工具不簽名、不送出、不付款。")
    return "\n".join(L)

def main():
    ap = argparse.ArgumentParser(description="BSC mint pre-check (read-only)")
    ap.add_argument("target", nargs="?"); ap.add_argument("--wallet"); ap.add_argument("--qty", type=int, default=1)
    ap.add_argument("--json", action="store_true"); ap.add_argument("--no-save", action="store_true")
    ap.add_argument("--record", nargs=2, metavar=("ADDRESS", "OUTCOME"), help="record real outcome: success|fail|unknown")
    ap.add_argument("--reason"); ap.add_argument("--notes")
    a = ap.parse_args()
    if a.record:
        with db() as c:
            n = c.execute("UPDATE projects SET outcome=?,failure_reason=COALESCE(?,failure_reason),notes=COALESCE(?,notes),updated_at=? WHERE lower(address)=lower(?)",
                          (a.record[1], a.reason, a.notes, now(), a.record[0])).rowcount
            if not n: c.execute("INSERT INTO projects(address,outcome,failure_reason,notes,origin,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                                (a.record[0], a.record[1], a.reason, a.notes, "manual", now(), now()))
        print(f"已記錄 {a.record[0]} → {a.record[1]}（{n} 筆更新）"); return
    if not a.target: ap.error("need URL or CA")
    if a.wallet and not re.fullmatch(r"0x[0-9a-fA-F]{40}", a.wallet): ap.error("--wallet must be a public 0x address (never a key)")
    T0 = time.time(); T = {}; url_info = None; targets = []
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a.target.strip()): targets = [a.target.strip()]
    elif re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", a.target.strip()): sys.exit("看起來像私鑰/哈希，拒絕處理。請只提供合約地址或網址。")
    else:
        url = a.target if a.target.startswith("http") else "https://" + a.target
        url_info = scan_url(url, T)
        rpc = RPC(); t = time.time()
        if url_info["addresses"]:
            res = rpc.batch([("eth_getCode", [x, "latest"]) for x in url_info["addresses"]])
            targets = [x for x, r in zip(url_info["addresses"], res) if r and len(r.get("result") or "0x") > 2][:3]
        T["rpc_url_codecheck"] = round(time.time()-t, 3)
    reps = []
    if not targets:
        print("【結論】網址中找不到 BSC 上的合約地址 → 請改用網路查詢（或給 CA）")
        print(json.dumps(url_info, ensure_ascii=False, indent=1)[:2000])
    for addr in targets:
        Ti = dict(T); rep = precheck(addr, a.wallet, a.qty, url_info, Ti); Ti["total"] = round(time.time()-T0, 3)
        rep["timings"] = Ti; rep["url_scan"] = url_info; rep["checked_at"] = now()
        if not a.no_save: save(rep, url_info and url_info["url"], Ti)
        else: rep.pop("_feat", None); rep.pop("_used_getters", None)
        os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
        fn = os.path.join(HERE, "reports", f"{datetime.date.today()}-{addr.lower()}.json")
        json.dump(rep, open(fn, "w"), indent=1, ensure_ascii=False, default=str); rep["report_file"] = fn
        print(summary(rep, Ti, url_info)); print(f"完整報告：{fn}\n"); reps.append(rep)
    if a.json: print(json.dumps(reps, ensure_ascii=False, default=str))

if __name__ == "__main__":
    main()
