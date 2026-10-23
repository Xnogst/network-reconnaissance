# Network Reconnaissance

A lightweight TCP port scanner written in Python. It uses sockets and multithreading to identify open TCP ports on a target host.

## Features

- Scans TCP ports 1–1024.
- Includes additional commonly used ports above 1024.
- Uses multithreading for faster scanning.
- Identifies common services associated with port numbers.
- Displays open ports and connection response times.
- Supports IP addresses and hostnames.
- Uses only Python's standard library.

## Requirements

- Python 3.8 or newer
- Git (optional, for cloning the repository)

No third-party Python packages are required.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Xnogst/network_reconnaissance.git
```

### 2. Enter the project directory

```bash
cd network_reconnaissance
```

### 3. Run the scanner

On Windows:

```bash
python network_reconnaissance.py
```

If `python` is not recognized, try:

```bash
py network_reconnaissance.py
```

On Linux or macOS:

```bash
python3 network_reconnaissance.py
```

## Usage

When the program starts, enter the target IP address or hostname.

For example:

```text
Target IP or hostname [127.0.0.1]: 127.0.0.1
Do you own this target or have permission to scan it? (yes/no): yes
```

The scanner will display open ports, their associated service labels, and connection response times.

Press Enter at the target prompt to scan your own computer using `127.0.0.1`.

## How It Works

1. Resolves the target hostname to an IPv4 address.
2. Builds a list containing ports 1–1024 and additional predefined ports above 1024.
3. Attempts TCP connections using Python's `socket` module.
4. Uses a thread pool to scan multiple ports concurrently.
5. Reports ports that accept TCP connections.

Service names are based on conventional port assignments. They do not guarantee which application is actually running on an open port.

## Limitations

- Scans TCP only, not UDP.
- Only scans the ports included in the configured port list.
- A failed connection does not always mean a port is closed; firewalls and network conditions can affect results.
- Service identification is based on port numbers, not full application fingerprinting.

## Security and Responsible Use

Only scan systems you own or have explicit permission to assess.

The permission prompt is a reminder, not a technical authorization check. Always obtain the necessary authorization before scanning another system.
