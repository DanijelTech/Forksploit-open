# Author: DanyTech
import json, urllib.request
RPC="https://etc.etcdesktop.com"
def rpc(m,p):
    b=json.dumps({"jsonrpc":"2.0","method":m,"params":p,"id":1}).encode()
    r=urllib.request.Request(RPC,data=b,headers={"Content-Type":"application/json"})
    try: return json.load(urllib.request.urlopen(r,timeout=20))
    except Exception as e: return {"error":str(e)}
T="0x9f5304DA62A5408416Ea58A17a92611019bD5ce3"
OWNER="0xe79aca5C8cDa44d834efa969906A377Cb987E02E"
RND="0x2222222222222222222222222222222222222222"
def t(label,data,frm,gas="0x7a1200"):
    r=rpc("eth_call",[{"from":frm,"to":T,"data":data,"gas":gas},"latest"])
    print(f"  {label:42} ->", ("OK "+r["result"][:20]) if "result" in r else ("REVERT "+str(r.get("error"))[:60]))
# 1) no access control: getOwner, deposit
t("getOwner (view)", "0x893d20e8", RND)
t("deposit() [payable, no AC]", "0xd0e30db0", RND)
# 2) owner-only: transferOwnership(newOwner)
NEW="0x000000000000000000000000"+"3333333333333333333333333333333333333333"
t("transferOwnership as OWNER", "0xa6f9dae1"+NEW, OWNER)
t("transferOwnership as RANDOM", "0xa6f9dae1"+NEW, RND)
# 3) owner-only: escapeHatch
t("escapeHatch as OWNER", "0x1554611f", OWNER)
t("escapeHatch as RANDOM", "0x1554611f", RND)
# 4) claimRemaining (timelock) 
t("claimRemaining as RANDOM", "0xc01c1ca3", RND)
print()
print("  => ce sta 'transferOwnership as OWNER' in 'as RANDOM' ENAKO, RPC ignorira from")
