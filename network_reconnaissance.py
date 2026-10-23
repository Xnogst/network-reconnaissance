
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


SERVICES = {
    1: "TCPMUX",
    7: "Echo",
    9: "Discard",
    13: "Daytime",
    17: "QOTD",
    19: "Chargen",
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time",
    42: "WINS",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    81: "HTTP Alternate",
    88: "Kerberos",
    102: "ISO-TSAP",
    110: "POP3",
    111: "RPCbind",
    113: "Ident",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    201: "AppleTalk",
    264: "BGMP",
    389: "LDAP",
    427: "SLP",
    443: "HTTPS",
    445: "SMB",
    464: "Kerberos Password",
    465: "SMTPS",
    500: "IKE/IPsec",
    512: "rexec",
    513: "rlogin",
    514: "Syslog",
    515: "LPD Printing",
    520: "RIP",
    521: "RIPng",
    540: "UUCP",
    548: "AFP",
    554: "RTSP",
    587: "SMTP Submission",
    593: "RPC over HTTP",
    631: "IPP Printing",
    636: "LDAPS",
    646: "LDP",
    691: "Microsoft Exchange",
    860: "iSCSI",
    873: "rsync",
    902: "VMware Server",
    989: "FTPS Data",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1000: "Custom Service",
    1024: "Dynamic/Private",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    2049: "NFS",
    2181: "ZooKeeper",
    2375: "Docker API",
    3000: "Development Server",
    3306: "MySQL",
    3389: "RDP",
    5000: "Development Server",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "HTTP Alternate",
    8080: "HTTP Alternate",
    8081: "HTTP Alternate",
    8443: "HTTPS Alternate",
    8888: "HTTP Alternate",
    9000: "Service Port",
    9090: "Service Port",
    9200: "Elasticsearch",
    9300: "Elasticsearch Nodes",
    11211: "Memcached",
    27017: "MongoDB",
}

PORTS = sorted(set(range(1, 1025)) | {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
    110, 111, 123, 135, 137, 138, 139, 143, 161,
    389, 443, 445, 465, 587, 636, 993, 995,
    1433, 1521, 2049, 2181, 2375, 3000, 3306,
    3389, 5000, 5432, 5672, 5900, 5985, 5986,
    6379, 6443, 8000, 8080, 8081, 8443, 8888,
    9000, 9090, 9200, 9300, 11211, 27017
})


def scan_port(target, port, timeout=0.5):
    start = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

        elapsed = (time.perf_counter() - start) * 1000
        service = SERVICES.get(port, "Unknown")

        if result == 0:
            return port, "OPEN", service, elapsed

        return port, "CLOSED", service, elapsed

    except (socket.timeout, OSError):
        elapsed = (time.perf_counter() - start) * 1000
        return port, "FILTERED/UNREACHABLE", SERVICES.get(port, "Unknown"), elapsed


def main():
    print("=" * 60)
    print("                  MINI PORT SCANNER")
    print("=" * 60)

    target = input(
        "\nTarget IP or hostname [127.0.0.1]: "
    ).strip() or "127.0.0.1"

    permission = input(
        "Do you own this target or have permission to scan it? (yes/no): "
    ).strip().lower()

    if permission != "yes":
        print("Scan cancelled. Only scan authorized targets.")
        return

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Could not resolve the target.")
        return

    print(f"\nTarget: {target} ({target_ip})")
    print(f"Checking {len(PORTS)} TCP ports...\n")

    start = time.perf_counter()
    open_count = 0
    closed_count = 0
    other_count = 0

    print(f"{'PORT':<12}{'STATE':<24}{'SERVICE':<25}{'TIME':>10}")
    print("-" * 71)

    with ThreadPoolExecutor(max_workers=10) as executor:
        tasks = [
            executor.submit(scan_port, target_ip, port)
            for port in PORTS
        ]

        for task in as_completed(tasks):
            port, state, service, elapsed = task.result()

            if state == "OPEN":
                open_count += 1
                print(
                    f"{port}/tcp{'':<5}{state:<24}"
                    f"{service:<25}{elapsed:>7.1f} ms"
                )
            elif state == "CLOSED":
                closed_count += 1
            else:
                other_count += 1

    duration = time.perf_counter() - start

    print("\n" + "=" * 60)
    print(f"Scan complete in: {duration:.2f} seconds")
    print(f"Ports checked:    {len(PORTS)}")
    print(f"Open:             {open_count}")
    print(f"Closed:           {closed_count}")
    print(f"Unreachable/other:{other_count:>4}")
    print("=" * 60)


if __name__ == "__main__":
    main()
