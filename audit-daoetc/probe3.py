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

def enc_fill(addr, amt):
    return "0x884b5dc2"+"%064x"%0x20+"%064x"%2+"%064x"%int(addr,16)+"%064x"%amt
data=enc_fill(ATK, 10**18)
print("calldata len:", len(data)-2, "even?", (len(data)-2)%2==0)
for label,to in [("LEDGER",LED),("TARGET",T)]:
    r=rpc("eth_call",[{"from":"0x2222222222222222222222222222222222222222","to":to,"data":data,"gas":"0x7a1200"},"latest"])
    print(f"NAKLJUCNI -> {label}.fill([atk,1e18]) :", "OK "+r["result"] if "result" in r else "REVERT "+str(r.get("error")))

print("\n===== LEDGER disassembly =====")
code=rpc("eth_getCode",[LED,"latest"])["result"]
ins=list(e.disassemble_all(bytes.fromhex(code[2:])))
open("/workspace/audit/ledger_disasm.txt","w").write("\n".join(f"{x.pc:5d} {x.name:12} {hex(x.operand) if x.operand is not None else ''}" for x in ins))
# find the fill (0x3fb27b85) and seal (0x884b5dc2?) -- resolve selectors
import urllib.request as u
for s in ["0x3fb27b85","0x884b5dc2","0x18160ddd","0x70a08231","0xe4b203ef","0x8da5cb5b","0x58451f97"]:
    try:
        req=u.Request("https://www.4byte.directory/api/v1/signatures/?hex_signature="+s,headers={"User-Agent":"x"})
        d=json.load(u.urlopen(req,timeout=8)); print(" ",s,"->",", ".join(x['text_signature'] for x in d.get('results',[])[:2]) or "?")
    except Exception as ex: print(" ",s,"err")
print("total ledger instr:", len(ins))
