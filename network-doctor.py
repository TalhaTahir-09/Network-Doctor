print("Starting Engine..")
from scapy.all import ICMP, IP, UDP, DNS, DNSQR, DNSRR, sr1, conf, ls
import math
import secrets
import time

gateway = conf.route.route("0.0.0.0")[2]

def dnsFn(domain, dns_server="8.8.8.8", record_type="A", timeout=5):

    # Validate requested record type
    record_type = record_type.upper()

    record_types = {
        "A": 1,
        "AAAA": 28
    }

    if record_type not in record_types:
        return {
            "success": False,
            "reason": "Unsupported record type. Use A or AAAA."
        }

    qtype = record_types[record_type]
    print(qtype)

    # Find the local source IP
    route = conf.route.route(dns_server)
    source_ip = route[1]

    if not source_ip or source_ip == "0.0.0.0":
        return {
            "success": False,
            "reason": "No valid route to DNS server"
        }

    # transaction ID and source port
    transaction_id = secrets.randbelow(65536)
    source_port = secrets.randbelow(16384) + 49152
    print("Transaction Id:", transaction_id)
    print("Source Port:", source_port)


    # Construct DNS query
    pkt = (
        IP(src=source_ip, dst=dns_server) /
        UDP(sport=source_port, dport=53) /
        DNS(
            id=transaction_id,
            rd=1,
            qd=DNSQR(
                qname=domain,
                qtype=qtype,
                qclass=1
            )
        )
    )

    # Send DNS query and measure latency
    start = time.perf_counter()
    res = sr1(pkt, timeout=timeout, verbose=0)
    end = time.perf_counter()

    latency = round((end - start) * 1000, 2)

    # Handle timeout
    if res is None:
        return {
            "success": False,
            "response_valid": False,
            "reason": "DNS server timeout",
            "server": dns_server,
            "domain": domain,
            "latency_ms": None,
            "answers": []
        }

    # Validate packet structure
    if (
        not res.haslayer(IP)
        or not res.haslayer(UDP)
        or not res.haslayer(DNS)
    ):
        return {
            "success": False,
            "response_valid": False,
            "reason": "Unexpected response packet",
            "server": dns_server,
            "domain": domain,
            "latency_ms": latency,
            "answers": []
        }

    response = res[DNS]
    print(ls(response))
    # normalize domain names for comparison
    def normalize_name(name):
        if isinstance(name, bytes):
            name = name.decode("ascii", errors="replace")

        return str(name).rstrip(".").lower()

    # validate DNS question
    question = response.qd

    question_valid = (
        question is not None
        and normalize_name(question.qname) == normalize_name(domain)
        and question.qtype == qtype
        and question.qclass == 1
    )

    # Validate response
    checks = {
        "source_ip": res[IP].src == dns_server,
        "destination_ip": res[IP].dst == source_ip,
        "source_port": res[UDP].sport == 53,
        "destination_port": res[UDP].dport == source_port,
        "dns_response": response.qr == 1,
        "transaction_id": response.id == transaction_id,
        "opcode": response.opcode == pkt[DNS].opcode,
        "question": question_valid
    }

    # Reject invalid responses
    if not all(checks.values()):
        return {
            "success": False,
            "response_valid": False,
            "reason": "Invalid or mismatched DNS response",
            "server": dns_server,
            "domain": domain,
            "latency_ms": latency,
            "checks": checks,
            "answers": []
        }

    # Handle truncated responses
    if response.tc == 1:
        return {
            "success": False,
            "response_valid": True,
            "reason": "DNS response truncated. TCP fallback required.",
            "server": dns_server,
            "domain": domain,
            "latency_ms": latency,
            "checks": checks,
            "answers": []
        }

    # Interpret DNS response codes
    rcode_names = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED"
    }

    rcode = response.rcode
    rcode_name = rcode_names.get(rcode, f"UNKNOWN ({rcode})")

   
    # Extract DNS answers
    answers = []

    record_names = {
        1: "A",
        2: "NS",
        5: "CNAME",
        15: "MX",
        16: "TXT",
        28: "AAAA"
    }

    for record in response.an:

        data = record.rdata

        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")

        answers.append({
            "name": normalize_name(record.rrname),
            "type": record_names.get(record.type, str(record.type)),
            "ttl": record.ttl,
            "data": str(data)
        })


    # Find answers matching the requested record type
    matching_answers = [
        answer for answer in answers
        if answer["type"] == record_type
    ]

    # Interpret DNS result
    if rcode == 3:
        reason = "Domain does not exist (NXDOMAIN)"
        success = False

    elif rcode != 0:
        reason = f"DNS server returned {rcode_name}"
        success = False

    elif not matching_answers:
        reason = f"No {record_type} records found (possible NODATA)"
        success = False

    else:
        reason = "DNS resolution successful"
        success = True

    return {
        "success": success,
        "response_valid": True,
        "reason": reason,
        "server": dns_server,
        "domain": domain,
        "record_type": record_type,
        "rcode": rcode,
        "rcode_name": rcode_name,
        "latency_ms": latency,
        "checks": checks,
        "answers": answers
    }


# DNS tests
print("Starting DNS Diagnostics...")

print("\n--- GOOGLE A RECORD ---")
print(dnsFn("google.com"))

print("\n--- GOOGLE AAAA RECORD ---")
print(dnsFn("google.com", record_type="AAAA"))

print("\n--- NONEXISTENT DOMAIN ---")
print(dnsFn("network-doctor-test.invalid"))

def pingFn(des):

    route = conf.route.route(des)
    source_ip = route[1]
    if not source_ip or source_ip == "0.0.0.0":
        return {
            "success": False,
            "reason": "no valid route",
            "latency": None
        }
    
    pkt = IP(src=source_ip,dst=des) / ICMP()

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
print(pingFn("8.8.8.8"))