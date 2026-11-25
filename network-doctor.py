"""
Network Doctor v1.0
A small, practical network diagnostic tool.

Checks:
1. Default gateway reachability (ICMP)
2. External IP reachability (ICMP)
3. DNS A-record resolution
4. TCP connection to port 443
5. TLS handshake and certificate verification

Requirements:
    pip install scapy

Run from an elevated/admin terminal if Scapy requires packet-capture privileges.
"""

from scapy.all import IP, ICMP, UDP, DNS, DNSQR, sr1, conf

import secrets
import socket
import ssl
import time


# ============================================================
# CONFIGURATION
# ============================================================

DNS_SERVER = "8.8.8.8"
INTERNET_TEST_IP = "1.1.1.1"
HTTPS_PORT = 443
DEFAULT_TIMEOUT = 5
TEST_DOMAIN = "google.com"


# ============================================================
# SHARED HELPERS
# ============================================================

def make_result(success, reason, **extra):
    """Create a consistent result dictionary for every diagnostic."""
    return {
        "success": success,
        "reason": reason,
        **extra
    }


def make_failure(reason, **extra):
    return make_result(False, reason, **extra)


def get_source_ip(destination):
    """Ask Scapy's routing table which local IPv4 address reaches destination."""
    try:
        route = conf.route.route(destination)
        source_ip = route[1]

        if not source_ip or source_ip == "0.0.0.0":
            return None

        return source_ip

    except (OSError, ValueError, IndexError):
        return None


def has_layers(packet, *layers):
    return packet is not None and all(
        packet.haslayer(layer) for layer in layers
    )


def normalize_name(name):
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="replace")

    return str(name).rstrip(".").lower()


def first_record(records):
    """Scapy versions may expose a DNS question as one record or a list."""
    if records is None:
        return None

    if isinstance(records, (list, tuple)):
        return records[0] if records else None

    return records


def send_packet(packet, timeout=DEFAULT_TIMEOUT):
    """Send one Scapy packet and return its response and elapsed time."""
    start = time.perf_counter()

    try:
        response = sr1(packet, timeout=timeout, verbose=0)
    except OSError as error:
        return None, round((time.perf_counter() - start) * 1000, 2), str(error)

    latency = round((time.perf_counter() - start) * 1000, 2)
    return response, latency, None


def print_check(title, result):
    status = "PASS" if result.get("success") else "FAIL"
    latency = result.get("latency_ms")

    suffix = f" ({latency} ms)" if latency is not None else ""
    print(f"[{status}] {title}{suffix}")
    print(f"       {result.get('reason', 'No details')}")


# ============================================================
# 1. ICMP PING
# ============================================================

def pingFn(destination, timeout=DEFAULT_TIMEOUT):
    source_ip = get_source_ip(destination)

    if not source_ip:
        return make_failure("No valid route to destination")

    packet = IP(src=source_ip, dst=destination) / ICMP()
    response, latency, send_error = send_packet(packet, timeout)

    if send_error:
        return make_failure(
            f"Could not send ICMP packet: {send_error}",
            latency_ms=latency
        )

    if response is None:
        return make_failure("No ICMP reply before timeout", latency_ms=latency)

    if not has_layers(response, IP, ICMP):
        return make_failure("Received an unexpected packet", latency_ms=latency)

    checks = {
        "ip_addresses": (
            packet[IP].src == response[IP].dst
            and packet[IP].dst == response[IP].src
        ),
        "echo_reply_type": response[ICMP].type == 0,
        "icmp_code": response[ICMP].code == 0,
        "identifier": packet[ICMP].id == response[ICMP].id,
        "sequence": packet[ICMP].seq == response[ICMP].seq
    }

    success = all(checks.values())

    return make_result(
        success,
        "Ping reply validated" if success else "ICMP response validation failed",
        destination=destination,
        latency_ms=latency,
        checks=checks
    )


# ============================================================
# 2. DNS RESOLUTION
# ============================================================

def dnsFn(
    domain,
    dns_server=DNS_SERVER,
    record_type="A",
    timeout=DEFAULT_TIMEOUT
):
    record_type = record_type.upper()

    record_types = {
        "A": 1,
        "AAAA": 28
    }

    record_names = {
        1: "A",
        2: "NS",
        5: "CNAME",
        15: "MX",
        16: "TXT",
        28: "AAAA"
    }

    rcode_names = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED"
    }

    if record_type not in record_types:
        return make_failure(
            "Unsupported record type; use A or AAAA",
            response_valid=False,
            answers=[]
        )

    source_ip = get_source_ip(dns_server)

    if not source_ip:
        return make_failure(
            "No valid route to DNS server",
            response_valid=False,
            answers=[]
        )

    qtype = record_types[record_type]
    transaction_id = secrets.randbelow(65536)
    source_port = secrets.randbelow(16384) + 49152

    packet = (
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

    response_packet, latency, send_error = send_packet(packet, timeout)

    if send_error:
        return make_failure(
            f"Could not send DNS query: {send_error}",
            response_valid=False,
            latency_ms=latency,
            answers=[]
        )

    if response_packet is None:
        return make_failure(
            "DNS server did not respond before timeout",
            response_valid=False,
            server=dns_server,
            domain=domain,
            latency_ms=latency,
            answers=[]
        )

    if not has_layers(response_packet, IP, UDP, DNS):
        return make_failure(
            "Received an unexpected response packet",
            response_valid=False,
            latency_ms=latency,
            answers=[]
        )

    response = response_packet[DNS]
    question = first_record(response.qd)

    question_valid = (
        question is not None
        and normalize_name(question.qname) == normalize_name(domain)
        and question.qtype == qtype
        and question.qclass == 1
    )

    checks = {
        "source_ip": response_packet[IP].src == dns_server,
        "destination_ip": response_packet[IP].dst == source_ip,
        "source_port": response_packet[UDP].sport == 53,
        "destination_port": response_packet[UDP].dport == source_port,
        "is_response": response.qr == 1,
        "transaction_id": response.id == transaction_id,
        "opcode": response.opcode == packet[DNS].opcode,
        "question": question_valid
    }

    if not all(checks.values()):
        return make_failure(
            "DNS response did not pass validation",
            response_valid=False,
            server=dns_server,
            domain=domain,
            latency_ms=latency,
            checks=checks,
            answers=[]
        )

    if response.tc:
        return make_failure(
            "DNS response was truncated; TCP fallback is not included in v1.0",
            response_valid=True,
            server=dns_server,
            domain=domain,
            latency_ms=latency,
            checks=checks,
            answers=[]
        )

    rcode = response.rcode
    rcode_name = rcode_names.get(rcode, f"UNKNOWN ({rcode})")

    answers = []

    # Scapy exposes the answer section as a linked packet list.
    # Iterating over it collects each answer record.
    answer_record = response.an
    while answer_record is not None and hasattr(answer_record, "type"):
        record_type_name = record_names.get(
            answer_record.type,
            str(answer_record.type)
        )

        data = answer_record.rdata
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")

        answers.append({
            "name": normalize_name(answer_record.rrname),
            "type": record_type_name,
            "ttl": answer_record.ttl,
            "data": str(data)
        })

        answer_record = answer_record.payload

        # Stop when the payload is no longer another DNS answer record.
        if not hasattr(answer_record, "type") or not hasattr(answer_record, "rrname"):
            break

    matching_answers = [
        answer for answer in answers
        if answer["type"] == record_type
    ]

    if rcode == 3:
        success = False
        reason = "Domain does not exist (NXDOMAIN)"
    elif rcode != 0:
        success = False
        reason = f"DNS server returned {rcode_name}"
    elif not matching_answers:
        success = False
        reason = f"DNS replied successfully, but no {record_type} answer was found"
    else:
        success = True
        reason = "DNS resolution successful"

    return make_result(
        success,
        reason,
        response_valid=True,
        server=dns_server,
        domain=domain,
        record_type=record_type,
        rcode=rcode,
        rcode_name=rcode_name,
        latency_ms=latency,
        checks=checks,
        answers=answers
    )


# ============================================================
# 3. TCP CONNECTION
# ============================================================

def tcpFn(destination, port=HTTPS_PORT, timeout=DEFAULT_TIMEOUT):
    start = time.perf_counter()

    try:
        with socket.create_connection(
            (destination, port),
            timeout=timeout
        ):
            latency = round((time.perf_counter() - start) * 1000, 2)

            return make_result(
                True,
                "TCP connection established",
                server=destination,
                port=port,
                latency_ms=latency
            )

    except socket.timeout:
        reason = "TCP connection timed out"
    except ConnectionRefusedError:
        reason = "Connection refused by destination"
    except OSError as error:
        reason = f"TCP connection error: {error}"

    latency = round((time.perf_counter() - start) * 1000, 2)

    return make_failure(
        reason,
        server=destination,
        port=port,
        latency_ms=latency
    )


# ============================================================
# 4. TLS CONNECTION
# ============================================================

def tlsFn(destination, domain, port=HTTPS_PORT, timeout=DEFAULT_TIMEOUT):
    context = ssl.create_default_context()

    # Measure TCP connection and TLS setup together in v1.0.
    # The field name makes clear that this is not TLS-only latency.
    start = time.perf_counter()

    try:
        with socket.create_connection(
            (destination, port),
            timeout=timeout
        ) as raw_socket:

            raw_socket.settimeout(timeout)

            with context.wrap_socket(
                raw_socket,
                server_hostname=domain
            ) as tls_socket:

                total_latency = round(
                    (time.perf_counter() - start) * 1000,
                    2
                )

                certificate = tls_socket.getpeercert()
                cipher_info = tls_socket.cipher()

                return make_result(
                    True,
                    "TLS handshake successful; certificate verification passed",
                    server=destination,
                    domain=domain,
                    tls_version=tls_socket.version(),
                    cipher=cipher_info[0] if cipher_info else None,
                    certificate_verified=bool(certificate),
                    connection_plus_tls_ms=total_latency
                )

    except ssl.SSLCertVerificationError as error:
        reason = f"Certificate verification failed: {error}"
    except ssl.SSLError as error:
        reason = f"TLS handshake failed: {error}"
    except socket.timeout:
        reason = "TCP/TLS setup timed out"
    except OSError as error:
        reason = f"TCP/TLS connection error: {error}"

    total_latency = round((time.perf_counter() - start) * 1000, 2)

    return make_failure(
        reason,
        server=destination,
        domain=domain,
        connection_plus_tls_ms=total_latency
    )


# ============================================================
# 5. DIAGNOSIS ENGINE
# ============================================================

def generate_diagnosis(results):
    diagnosis = []

    gateway = results["gateway"]
    internet = results["internet"]
    dns = results["dns"]
    tcp = results["tcp"]
    tls = results["tls"]

    if not gateway["success"]:
        diagnosis.append(
            "The gateway did not answer the ICMP ping. "
            "Check the local connection and gateway, but note that "
            "some gateways block ping."
        )

    if not internet["success"]:
        diagnosis.append(
            "The external test IP did not answer ICMP. "
            "External connectivity is not confirmed; ICMP filtering "
            "could also explain this result."
        )

    if not dns["success"]:
        diagnosis.append(
            f"DNS lookup failed: {dns.get('reason', 'Unknown DNS error')}. "
            "Check DNS server reachability, DNS settings, or filtering."
        )

    if dns["success"] and not tcp["success"]:
        diagnosis.append(
            f"DNS succeeded, but TCP to {tcp.get('server')}:{tcp.get('port')} "
            f"failed: {tcp.get('reason')}. Check the destination service, "
            "firewall, or route."
        )

    if tcp["success"] and not tls["success"]:
        diagnosis.append(
            "TCP succeeded, but TLS setup failed: "
            f"{tls.get('reason')}. Investigate certificate trust, "
            "hostname, system time, TLS compatibility, or interception."
        )

    if tls["success"]:
        diagnosis.append(
            "DNS, TCP, and TLS checks succeeded. The tested HTTPS "
            "connection path is working. This does not yet test an HTTP response."
        )

    if not diagnosis:
        diagnosis.append("No specific problem was identified by these checks.")

    return diagnosis


# ============================================================
# 6. MAIN DIAGNOSTIC ENGINE
# ============================================================

def run_diagnostics(domain=TEST_DOMAIN):
    print("\n" + "=" * 58)
    print(f"NETWORK DOCTOR v1.0 — {domain}")
    print("=" * 58)

    results = {}

    # Step 1: Find and test the default gateway.
    print("\n[1/6] DEFAULT GATEWAY")

    try:
        gateway = conf.route.route("0.0.0.0")[2]
    except (OSError, ValueError, IndexError):
        gateway = None

    if gateway and gateway != "0.0.0.0":
        results["gateway"] = pingFn(gateway)
        results["gateway"]["destination"] = gateway
    else:
        results["gateway"] = make_failure("No default gateway found")

    print_check("Gateway ping", results["gateway"])

    # Step 2: Test reachability of a known external IP.
    print("\n[2/6] EXTERNAL IP REACHABILITY")
    results["internet"] = pingFn(INTERNET_TEST_IP)
    print_check(f"Ping {INTERNET_TEST_IP}", results["internet"])

    # Step 3: Resolve the requested domain.
    print("\n[3/6] DNS")
    results["dns"] = dnsFn(domain, record_type="A")
    print_check("DNS A-record lookup", results["dns"])

    # Select the first A record returned by DNS.
    ip_address = None

    if results["dns"]["success"]:
        for answer in results["dns"].get("answers", []):
            if answer["type"] == "A":
                ip_address = answer["data"]
                break

    # Step 4 and 5: TCP, then TLS only if TCP succeeds.
    if ip_address:
        print("\n[4/6] TCP")
        results["tcp"] = tcpFn(ip_address, HTTPS_PORT)
        print_check(f"TCP {ip_address}:{HTTPS_PORT}", results["tcp"])

        if results["tcp"]["success"]:
            print("\n[5/6] TLS")
            results["tls"] = tlsFn(ip_address, domain, HTTPS_PORT)
            status = "PASS" if results["tls"]["success"] else "FAIL"
            print(f"[{status}] TLS handshake")
            print(f"       {results['tls']['reason']}")
            if results["tls"]["success"]:
                print(f"       Version: {results['tls']['tls_version']}")
                print(f"       Cipher:  {results['tls']['cipher']}")
                print(
                    "       TCP + TLS setup: "
                    f"{results['tls']['connection_plus_tls_ms']} ms"
                )
        else:
            results["tls"] = make_failure(
                "Skipped because the TCP connection failed"
            )
            print("\n[5/6] TLS")
            print("[SKIP] TLS was not attempted because TCP failed.")
    else:
        results["tcp"] = make_failure(
            "Skipped because DNS did not provide an IPv4 A record"
        )
        results["tls"] = make_failure(
            "Skipped because DNS did not provide an IPv4 A record"
        )

        print("\n[4/6] TCP")
        print("[SKIP] No IPv4 address available from DNS.")
        print("\n[5/6] TLS")
        print("[SKIP] No IPv4 address available from DNS.")

    # Step 6: Interpret the collected evidence.
    print("\n[6/6] DIAGNOSIS")
    results["diagnosis"] = generate_diagnosis(results)

    for item in results["diagnosis"]:
        print(f"- {item}")

    print("\n" + "=" * 58)
    print("DIAGNOSTICS COMPLETED")
    print("=" * 58)

    return results


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    report = run_diagnostics()
