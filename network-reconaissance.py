import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5000: "Development server",
    5432: "PostgreSQL",
    8000: "HTTP alternate",
    8080: "HTTP proxy",
    8443: "HTTPS alternate",
}


def scan_port(target, port, timeout=0.5):
    """Test whether a TCP port accepts connections."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    start = time.perf_counter()

    try:
        result = sock.connect_ex((target, port))
        elapsed = (time.perf_counter() - start) * 1000

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            return port, "OPEN", service, elapsed

        return port, "CLOSED", "", elapsed

    except (socket.timeout, OSError):
        return port, "FILTERED/UNREACHABLE", "", 0

    finally:
        sock.close()


def main():
    print("=" * 55)
    print("             MINI PORT SCANNER")
    print("=" * 55)

    target = input(
        "\nTarget IP or hostname [127.0.0.1]: "
    ).strip() or "127.0.0.1"

    if input(
        "Do you own this target or have permission to scan it? (yes/no): "
    ).strip().lower() != "yes":
        print("Scan cancelled. Only scan authorized targets.")
        return

    try:

        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Could not resolve the target.")
        return

    print(f"\nTarget: {target} ({target_ip})")
    print(f"Checking {len(COMMON_PORTS)} common TCP ports...\n")

    start = time.perf_counter()
    open_count = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        tasks = [
            executor.submit(scan_port, target_ip, port)
            for port in COMMON_PORTS
        ]

        for task in as_completed(tasks):
            port, state, service, elapsed = task.result()

            if state == "OPEN":
                open_count += 1
                print(
                    f"{port:5}/tcp  OPEN      "
                    f"{service:<20} {elapsed:.1f} ms"
                )

    duration = time.perf_counter() - start

    print("\n" + "=" * 55)
    print(f"Scan complete in {duration:.2f} seconds.")
    print(f"Open ports found: {open_count}")
    print("=" * 55)


if __name__ == "__main__":
    main()
