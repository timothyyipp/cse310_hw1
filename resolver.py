import sys
import time
import threading
from datetime import datetime
import dns.message, dns.query, dns.rdatatype

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
    query.flags &= ~dns.flags.RD  # iterative mode
    try:
        return dns.query.udp(query, server_ip, timeout=TIMEOUT)
    except Exception:
        return None

def resolve_once(domain, rdtype, servers):
    for server in servers:
        resp = send_query(domain, rdtype, server)
        if resp:
            return resp
    return None

def extract_glue_ips(response):
    ips = []
    for rrset in response.additional:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for r in rrset:
                ips.append(r.address)
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
            answers = []
            cname_target = None
            for rrset in resp.answer:
                if rrset.rdtype == rdtype:
                    answers.append(rrset)
                elif rrset.rdtype == dns.rdatatype.CNAME:
                    cname_target = str(rrset[0].target)

            if answers:
                return answers
            elif cname_target:
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

        raise RuntimeError("No usable answer or delegation found")

def pretty_print(domain, rdtype, answers, elapsed_ms):
    print("QUESTION SECTION:")
    print(f"{domain}. IN {dns.rdatatype.to_text(rdtype)}")
    print()
    print("ANSWER SECTION:")
    if not answers:
        print("(no answer)")
    else:
        for rrset in answers:
            for r in rrset:
                print(f"{rrset.name} {rrset.ttl} IN {dns.rdatatype.to_text(rrset.rdtype)} {r}")
    print()
    print(f"Query time: {int(elapsed_ms)} msec")
    print(f"WHEN: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}")
    print()

def resolve_with_timing(domain, rdtype, result_holder):
    start = time.time()
    try:
        answers = iterative_resolve(domain, rdtype)
        elapsed = (time.time() - start) * 1000.0
        result_holder["result"] = (rdtype, answers, elapsed)
    except Exception as e:
        result_holder["error"] = f"{dns.rdatatype.to_text(rdtype)} lookup failed: {e}"

def main():
    if len(sys.argv) != 2:
        print("Usage: python resolver.py <domain>")
        sys.exit(2)

    domain = sys.argv[1].rstrip('.')

    result = {}

    # Run both A and AAAA in parallel
    threads = []
    for rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
        t = threading.Thread(target=resolve_with_timing, args=(domain, rdtype, result))
        t.start()
        threads.append(t)

    # Wait until one of them succeeds
    while True:
        if "result" in result:
            rdtype, answers, elapsed = result["result"]
            pretty_print(domain, rdtype, answers, elapsed)
            return
        # If both threads are done but only errors exist, print one error
        if all(not t.is_alive() for t in threads):
            print(result.get("error", "Lookup failed"))
            return
        time.sleep(0.05)

if __name__ == "__main__":
    main()
