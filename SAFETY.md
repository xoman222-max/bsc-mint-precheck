# HARD SAFETY RULES (enforced in code)
1. Read-only. Never sign, never send/broadcast transactions, never approve, never pay.
2. Never load, request, or store private keys or seed phrases. Inputs that look like a 32-byte key are refused.
3. Never connect a wallet (no WalletConnect, no Binance Agentic Wallet, no browser wallet).
4. Simulation only via `eth_call` / `eth_estimateGas` from a user-supplied public address or a dummy address.
   The RPC client has an allow-list of read methods; `eth_send*` / `eth_sign*` raise PermissionError.
5. Never print secrets. Optional `ETHERSCAN_API_KEY` is only sent to the Etherscan v2 API, never logged.
