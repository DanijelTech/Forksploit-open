# Author: DanyTech
import json, urllib.request
RPC="https://etc.etcdesktop.com"
def rpc(m,p):
    b=json.dumps({"jsonrpc":"2.0","method":m,"params":p,"id":1}).encode()
    r=urllib.request.Request(RPC,data=b,headers={"Content-Type":"application/json"})
    try: return json.load(urllib.request.urlopen(r,timeout=20))
    except Exception as e: return {"error":str(e)}
LED="0x180826b05452ce96e157f0708c43381fee64a6b8"
T="0x9f5304DA62A5408416Ea58A17a92611019bD5ce3"
OWNER="0xe79aca5C8cDa44d834efa969906A377Cb987E02E"   # target owner
LEDOWNER="0x941D6F2cAe269f6e72f9BaAaF2c98057eE421960"
RND="0x2222222222222222222222222222222222222222"
ATK="1111111111111111111111111111111111111111"
def fill_data(addr,amt): return "0x884b5dc2"+"%064x"%0x20+"%064x"%2+"%064x"%int(addr,16)+"%064x"%amt
def t(label,to,data,frm):
    r=rpc("eth_call",[{"from":frm,"to":to,"data":data,"gas":"0x7a1200"},"latest"])
    print(f"  {label:52} ->", "OK" if "result" in r else "REVERT")
print("=== TARGET fill: who can? ===")
t("TARGET.fill as RANDOM", T, fill_data(ATK,10**18), RND)
t("TARGET.fill as OWNER",  T, fill_data(ATK,10**18), OWNER)
t("TARGET.seal as RANDOM", T, "0x3fb27b85", RND)
print("=== LEDGER fill: who can? ===")
t("LEDGER.fill as RANDOM", LED, fill_data(ATK,10**18), RND)
t("LEDGER.fill as LEDGER-OWNER", LED, fill_data(ATK,10**18), LEDOWNER)
t("LEDGER.seal as RANDOM", LED, "0x3fb27b85", RND)
print("=== inspect LEDGER fill disasm (0x3fb27b85 or 0x884b5dc2?) ===")
code=rpc("eth_getCode",[LED,"latest"])["result"]
print("LEDGER code len:", (len(code)-2)//2, "bytes")
print(code[:200])
