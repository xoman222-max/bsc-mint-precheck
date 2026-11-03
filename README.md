# bsc-mint-precheck

> **HARD SAFETY RULES** — read-only. Never sign, never send transactions, never approve, never pay, never load or ask for
> private keys/seed phrases, never connect wallets. Simulation only via `eth_call`/`eth_estimateGas` from a public or dummy
> `from` address. Enforced in code (RPC method allow-list, key-like input refused). See SAFETY.md.

Pre-check a BSC NFT/token mint from a **URL or contract address**: identifies contract, proxy, standard, mint functions,
price, supply, open status, eligibility, risk, simulates the mint, and learns from a local history DB.

## Setup
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python seed_history.py seed/public_features.jsonl   # optional: load public seed features
```
Optional env: `BSC_RPCS` (comma list, tried first), `ETHERSCAN_API_KEY` (Etherscan v2; otherwise Sourcify only).

## Usage
```bash
python3 precheck.py <url-or-CA> [--wallet 0xPUBLIC] [--qty N] [--json] [--no-save]
python3 precheck.py --record <CA> success|fail|unknown [--reason "..."] [--notes "..."]
bash tests/run_tests.sh
```
Output: Traditional Chinese summary (conclusion first) + `reports/<date>-<addr>.json`. History in `data/history.db` (SQLite).
Unfamiliar contracts write `ai_queue/<addr>.json` (unknown selectors etc.) for an AI to read.

Pipeline & timings: fetch (URL+JS bundles) → rpc (batched JSON-RPC, fallback RPCs) → abi (Sourcify/Etherscan + bytecode
selectors + openchain lookup) → match (bytecode hash / impl / source hash / selector Jaccard vs history) → simulate → risk.

## 候選入口函式 (custom-named mint, e.g. takeGift / buy)
Standard names (mint/publicMint/claim/safeMint…) are matched first. In addition — and especially when none match — the tool lists
**entry candidates**: non-view functions from the verified ABI, or (unverified) bytecode selectors resolved via openchain → 4byte.
Admin/owner, ERC20/721 transfer/approve, set*/withdraw* etc. are excluded. Ranked by: payable, qty/amount/proof args, names like
buy/take/gift/get/purchase/join/participate, and a passing read-only eth_call+estimateGas (with --wallet if given).
**These are candidates only — confirm on the official site / explorer before use.** In `--json`: `entry_candidates.items[]`
(signature, payable, score, why, sim, source). Conclusion `標準 mint 名稱未命中，列出候選入口函式（需人工確認）` replaces the old 找不到 mint 函式.
