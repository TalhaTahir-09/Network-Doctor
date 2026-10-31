print("Starting Engine..")
from scapy.all import IP, ICMP, sr1, conf, ls
import math
gateway = conf.route.route("0.0.0.0")[2]

def pingFn(des):
    if(des == "0.0.0.0"):
        return "Can't access router, Check physical layer"
    else:
        pkt = IP(dst=des) / ICMP()
        # print("Pkt LIST")
        # print(ls(pkt[ICMP]))

        res = sr1(pkt, timeout=5, verbose=0)
        # print("REs LIST")

        # print(ls(res[ICMP]))

        # Validation Code
        score = 0
        # IP Layer
        if(pkt.src == res.dst and pkt.dst == res.src):
            print("Source and Destination Matches!!")
            score+=1
        else:  
            print("Packet did not arrive from the requested destination")

        # ICMP Layer
        if(res.type == 0 and res.code == 0):
            print("ICMP Type and code are good")
            score+=1
            if(pkt[ICMP].id == res[ICMP].id ):
                print("Id of the packet mactches!!")
                score+=1
                if(pkt.seq == res.seq):
                    print("Packet Sequence matches!!")
                    score+=1
                else:
                    print("Packet Sequence has been manipulated")
            else:
                print("Packet id does not match")
        else:
            print("ICMP code and type are not correct")
        
        if res:
            return [bool(res), f"{math.ceil(10**3*(res.time - pkt.time))}ms"]
        else:
            return [False]

print(pingFn(gateway))
# print(f"Gateway IP: {gateway}")
# print(pingFn(gateway))
# print(pingFn("8.8.8.8"))