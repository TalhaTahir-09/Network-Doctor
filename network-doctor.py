print("Starting Engine..")
from scapy.all import IP, ICMP, sr1, conf
import math
import time

gateway = conf.route.route("0.0.0.0")[2]


def pingFn(des):

    pkt = IP(dst=des) / ICMP()

    start = time.perf_counter()
    res = sr1(pkt, timeout=5, verbose=0)
    end = time.perf_counter()

    # Handle timeout
    if res is None:
        return {
            "success": False,
            "reason": "timeout",
            "latency": None
        }

    # Check packet structure
    if not res.haslayer(IP) or not res.haslayer(ICMP):
        return {
            "success": False,
            "reason": "unexpected packet",
            "latency": None
        }

    # Validation Code
    resDict = {"success": False, "checks": {}}
    checks = {}

    # IP validation
    checks["ip"] = (
        pkt[IP].src == res[IP].dst
        and pkt[IP].dst == res[IP].src
    )

    # ICMP validation
    checks["icmp_type"] = res[ICMP].type == 0
    checks["icmp_code"] = res[ICMP].code == 0
    checks["id"] = pkt[ICMP].id == res[ICMP].id
    checks["sequence"] = pkt[ICMP].seq == res[ICMP].seq

    # Overall success
    resDict["checks"] = checks
    resDict["success"] = all(checks.values())
    resDict["latency"] = f"{math.ceil((end - start) * 1000)}ms"

    return resDict

print(pingFn(gateway))
# print(f"Gateway IP: {gateway}")
# print(pingFn(gateway))
# print(pingFn("8.8.8.8"))