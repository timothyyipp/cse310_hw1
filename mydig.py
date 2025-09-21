
"""
A simple iterative DNS resolver using dnspython.

Features:
- Queries root servers directly, then follows delegations down the DNS hierarchy.
- Supports both A (IPv4) and AAAA (IPv6) lookups.
- Handles CNAME redirection chains (up to MAX_CNAME_CHAIN).
- Uses glue records (additional section) when available.
- Multi-threaded: queries A and AAAA records in parallel.
- Prints the resolved record, TTL, and query time if successful.
- If an error occurs, prints a descriptive error message.

Possible error messages:
- "Query to <IP> failed: <details>"
    The resolver could not reach the DNS server at the given IP (timeout, network unreachable, etc.).
- "No response from any server"
    None of the queried servers responded.
- "CNAME chain too long"
    The domain redirected too many times (potential loop or misconfiguration).
- "No usable answer or delegation found"
    The DNS server replied, but did not provide an answer, glue record, or delegation.
    This usually means the domain does not exist (NXDOMAIN) or is misconfigured.

Usage:
    python3/python mydig.py
    Enter a domain name when prompted, e.g. "example.com".
"""



import sys
import time
import threading
from datetime import datetime
import dns.message, dns.query, dns.rdatatype, dns.exception

ROOT_SERVERS = [
    # IPv4 addresses
    "198.41.0.4",       # A
    "199.9.14.201",     # B
    "192.33.4.12",      # C
    "199.7.91.13",      # D
    "192.203.230.10",   # E
    "192.5.5.241",      # F
    "192.112.36.4",     # G
    "198.97.190.53",    # H
    "192.36.148.17",    # I
    "192.58.128.30",    # J
    "193.0.14.129",     # K
    "199.7.83.42",      # L
    "202.12.27.33",     # M

    # IPv6 addresses
    "2001:503:ba3e::2:30",   # A
    "2001:500:200::b",       # B
    "2001:500:2::c",         # C
    "2001:500:2d::d",        # D
    "2001:500:a8::e",        # E
    "2001:500:2f::f",        # F
    "2001:500:12::d0d",      # G
    "2001:500:1::53",        # H
    "2001:7fe::53",          # I
    "2001:503:c27::2:30",    # J
    "2001:7fd::1",           # K
    "2001:500:9f::42",       # L
    "2001:dc3::35",          # M
]

TIMEOUT = 3.0
MAX_CNAME_CHAIN = 10

def send_query(name, rdtype, server_ip):
    query = dns.message.make_query(name, rdtype)
    query.flags &= ~dns.flags.RD
    try:
        return dns.query.udp(query, server_ip, timeout=TIMEOUT)
    except Exception as e:
        ### return None but also preserve error message
        raise RuntimeError(f"Query to {server_ip} failed: {e}")

def resolve_once(domain, rdtype, servers):
    last_err = None
    for server in servers:
        try:
            resp = send_query(domain, rdtype, server)
            if resp:
                return resp
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    return None

def extract_glue_ips(response):
    ips = []
    for rrset in response.additional:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for r in rrset:
                ips.append(r.address)
    return ips

def extract_ns_ips(response, rdtype):
    ips = []
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for r in rrset:
                ns_name = str(r.target)
                try:
                    ns_ans = iterative_resolve(ns_name, rdtype)
                    if ns_ans:
                        for rr in ns_ans[0]:
                            if hasattr(rr, "address"):
                                ips.append(rr.address)
                except Exception:
                    continue
    return ips

def iterative_resolve(domain, rdtype):
    current_servers = list(ROOT_SERVERS)
    cname_chain = 0
    qname = domain

    while True:
        resp = resolve_once(qname, rdtype, current_servers)
        if not resp:
            raise RuntimeError("No response from any server")

        if resp.answer:
            cname_target = None
            for rrset in resp.answer:
                if rrset.rdtype == rdtype:
                    return [rrset]  
                elif rrset.rdtype == dns.rdatatype.CNAME:
                    cname_target = str(rrset[0].target)

            if cname_target:
                cname_chain += 1
                if cname_chain > MAX_CNAME_CHAIN:
                    raise RuntimeError("CNAME chain too long")
                qname = cname_target
                current_servers = list(ROOT_SERVERS)
                continue

        glue_ips = extract_glue_ips(resp)
        if glue_ips:
            current_servers = glue_ips
            continue

        ns_ips = extract_ns_ips(resp, dns.rdatatype.A) + extract_ns_ips(resp, dns.rdatatype.AAAA)
        if ns_ips:
            current_servers = ns_ips
            continue

        raise RuntimeError("No usable answer or delegation found")

def pretty_print(domain, answers, elapsed_ms):
    print("QUESTION SECTION:")
    print(f"{domain}.")
    print()

    print("ANSWER SECTION:")
    if not answers:
        print("(no answer)")
    else:
        rrset = answers[0]
        r = rrset[0]
        print(f"{rrset.name}")
        print(f"{rrset.ttl} IN {dns.rdatatype.to_text(rrset.rdtype)} {r}")
    print()

    print(f"Query time: {int(elapsed_ms)} msec")
    print(f"WHEN: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}")
    print()

def resolve_with_timing(domain, rdtype, result_holder):
    start = time.time()
    try:
        answers = iterative_resolve(domain, rdtype)
        if not answers:
            return
        elapsed = (time.time() - start) * 1000.0
        if "result" not in result_holder:
            result_holder["result"] = (rdtype, answers, elapsed)
    except Exception as e:
        ### Store error for main thread
        result_holder["error"] = str(e)

def main():
    domain = input("Enter a domain name to resolve: ").strip().rstrip('.')
    if not domain:
        print("No domain entered. Exiting.")
        sys.exit(2)

    result = {}
    threads = []
    for rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
        t = threading.Thread(target=resolve_with_timing, args=(domain, rdtype, result))
        t.start()
        threads.append(t)

    while True:
        if "result" in result:
            rdtype, answers, elapsed = result["result"]
            pretty_print(domain, answers, elapsed)
            return
        if "error" in result:
            print(f"Error: {result['error']}")
            return
        if all(not t.is_alive() for t in threads):
            print("Lookup failed")
            return
        time.sleep(0.05)

if __name__ == "__main__":
    main()
