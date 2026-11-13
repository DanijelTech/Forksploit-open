# Author: DanyTech
import json, urllib.request
RPC="https://etc.etcdesktop.com"
def rpc(m,p):
    b=json.dumps({"jsonrpc":"2.0","method":m,"params":p,"id":1}).encode()
    r=urllib.request.Request(RPC,data=b,headers={"Content-Type":"application/json"})
    try: return json.load(urllib.request.urlopen(r,timeout=20))
    except Exception as e: return {"error":str(e)}
T="0x9f5304DA62A5408416Ea58A17a92611019bD5ce3"
LED="0x180826b05452ce96e157f0708c43381fee64a6b8"
OWNER="0xe79aca5C8cDa44d834efa969906A377Cb987E02E"
LEDOWNER="0x941D6F2cAe269f6e72f9BaAaF2c98057eE421960"
RND="0x2222222222222222222222222222222222222222"
def t(label,to,data,frm):
    r=rpc("eth_call",[{"from":frm,"to":to,"data":data,"gas":"0x7a1200"},"latest"])
    print(f"  {label:46} ->", ("OK "+r["result"][:16]) if "result" in r else "REVERT")
def fill_empty(): return "0x884b5dc2"+"%064x"%0x20+"%064x"%0   # offset=0x20, length=0
def fill1(): return "0x884b5dc2"+"%064x"%0x20+"%064x"%1+"%064x"%int("1111111111111111111111111111111111111111",16)
print("=== fill([]) EMPTY -- loci DOSTOP od ZANKE ===")
t("TARGET.fill([]) as RANDOM", T, fill_empty(), RND)
t("TARGET.fill([]) as OWNER",  T, fill_empty(), OWNER)
t("LEDGER.fill([]) as LEDGER-OWNER", LED, fill_empty(), LEDOWNER)
t("LEDGER.fill([]) as RANDOM", LED, fill_empty(), RND)
print("=== fill([1]) ===")
t("TARGET.fill([1]) as OWNER", T, fill1(), OWNER)
t("LEDGER.fill([1]) as LEDGER-OWNER", LED, fill1(), LEDOWNER)
print("=== kontrola dostopa (dokaz, da RPC uposteva from) ===")
t("TARGET.transferOwnership as OWNER", T, "0xa6f9dae1"+"%064x"%int("3333333333333333333333333333333333333333",16), OWNER)
t("TARGET.transferOwnership as RANDOM", T, "0xa6f9dae1"+"%064x"%int("3333333333333333333333333333333333333333",16), RND)
t("TARGET.escapeHatch as OWNER", T, "0x1554611f", OWNER)
t("TARGET.escapeHatch as RANDOM", T, "0x1554611f", RND)
