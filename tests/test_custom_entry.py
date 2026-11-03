"""Offline test: custom-named mint functions (takeGift/buy) surface as entry candidates. Mock ABI + mock RPC; no network."""
import sys, os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import precheck as P
ABI = [
 {"type":"function","name":"takeGift","stateMutability":"payable","inputs":[{"name":"quantity","type":"uint256"}]},
 {"type":"function","name":"buy","stateMutability":"payable","inputs":[]},
 {"type":"function","name":"transfer","stateMutability":"nonpayable","inputs":[{"name":"to","type":"address"},{"name":"v","type":"uint256"}]},
 {"type":"function","name":"approve","stateMutability":"nonpayable","inputs":[{"name":"s","type":"address"},{"name":"v","type":"uint256"}]},
 {"type":"function","name":"setPrice","stateMutability":"nonpayable","inputs":[{"name":"p","type":"uint256"}]},
 {"type":"function","name":"withdraw","stateMutability":"nonpayable","inputs":[]},
 {"type":"function","name":"transferOwnership","stateMutability":"nonpayable","inputs":[{"name":"o","type":"address"}]},
 {"type":"function","name":"price","stateMutability":"view","inputs":[]},
]
class MockRPC:
    def __init__(s): s.methods = []
    def batch(s, reqs):
        s.methods += [m for m, _ in reqs]
        tx = reqs[0][1][0]
        ok = tx["data"].startswith(P.sel("takeGift(uint256)")) and int(tx["value"], 16) > 0
        return [{"result": "0x"} if ok else {"error": {"message": "execution reverted"}}, {"result": "0x5208"} if ok else {"error": {"message": "reverted"}}]
c = P.entry_candidates(ABI)
sigs = [x["signature"] for x in c]
assert "takeGift(uint256)" in sigs and "buy()" in sigs, sigs
for bad in ("transfer(address,uint256)", "approve(address,uint256)", "setPrice(uint256)", "withdraw()", "transferOwnership(address)", "price()"):
    assert bad not in sigs, bad
r = MockRPC(); c = P.simulate_candidates(c, r, "0x" + "1"*40, "0x" + "2"*40, 1, 10**16)
assert c[0]["signature"] == "takeGift(uint256)" and "模擬通過" in c[0]["why"], c[0]
assert set(r.methods) <= {"eth_call", "eth_estimateGas"}, r.methods
# unverified path: names from 4byte lookup
c2 = P.entry_candidates(None, {"0xaaaaaaaa": "takeGift(uint256)", "0xbbbbbbbb": "approve(address,uint256)"})
assert [x["signature"] for x in c2] == ["takeGift(uint256)"], c2
print("PASS custom-named entry candidates (takeGift/buy)")
# price override: standard sim fails "Wrong BNB amount", candidate passes at 0 -> free hint
sims = [{"method": "mint()", "ok": False, "revert": "Error: Wrong BNB amount"}]
ec = [{"signature": "mint()", "pass_value": 0}]
o = P.price_override(sims, ec, 10**15); assert o and o.startswith("可能目前免費"), o
assert P.price_override(sims, [{"signature": "mint()", "pass_value": 10**15}], 10**15) is None
o2 = P.price_override(sims, [{"signature": "buy()", "pass_value": 2*10**15}], 10**15); assert "0.002 BNB" in o2, o2
assert P.price_override([{"ok": True}], ec, 10**15) is None
print("PASS price override conclusion")
