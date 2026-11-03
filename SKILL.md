---
name: bsc-mint-precheck
description: Read-only pre-check for a BSC mint given a URL or contract address — identifies mint function, price, supply, open status, wallet eligibility, risk, and simulates via eth_call. Use first whenever a mint URL/CA is shared; research the web only if it cannot identify the contract.
---
# BSC Mint Pre-check

## When to use
Any time someone shares a BSC mint website or a contract address (CA), or a monitoring routine finds a new mint.
**Always run this toolkit first.** Only if it reports 找不到合約 / 找不到 mint 函式 / needs AI analysis, then read the
`ai_queue/<addr>.json` summary and/or research on the web.

## Safety (non-negotiable)
Read-only. Never sign, send, approve, or pay. Never ask for or load private keys/seed phrases. Never connect a wallet.
Simulation is `eth_call`/`eth_estimateGas` only. The final mint decision and any transaction belong to the human.

## CLI
```
python3 <dir>/precheck.py <url-or-CA> [--wallet 0xPUBLIC_ADDRESS] [--qty N] [--json] [--no-save]
python3 <dir>/precheck.py --record <CA> success|fail|unknown --reason "..."   # after the human reports the real outcome
bash <dir>/tests/run_tests.sh
```

## Reading the output
- First line `【結論】`: 可以mint（模擬通過） / 未開放 / 已售罄 / 不符資格/需白名單或簽名 / 價格不符 / 無公開mint（僅owner/minter） /
  高風險 / 模擬失敗 / 找不到 mint 函式 / 不是合約.
- 價格 / 供應 / 剩餘 come from live getters; 模擬 lines show calldata method, value, revert reason, gas.
- 風險 低/中/高 with reasons (owner powers, upgradeable proxy, unverified, selfdestruct/delegatecall, ERC20 payment →
  approve, site JS asking setApprovalForAll/permit, wrong chainId).
- 歷史比對: matched past project and score. The identification method is reused, but address, price and params are always
  re-queried live — never trust historical values.
- Without `--wallet`, eligibility is NOT confirmed (dummy sender).
- Timings per stage are printed and stored in the report/DB.

## Report to the human
Conclusion, price, remaining, eligibility, risk reasons, simulation result, and what they must confirm (official CA,
price/qty, no approvals needed). Mark anything unverified. Never execute the mint.
