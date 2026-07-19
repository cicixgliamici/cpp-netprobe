# cpp-netprobe

[![CI](https://github.com/cicixgliamici/cpp-netprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/cicixgliamici/cpp-netprobe/actions/workflows/ci.yml)

A lightweight, layered **network packet analyzer** written in modern C++20.
It reads PCAP capture files and dissects packets layer by layer following the OSI model,
printing a structured human-readable report for each frame.

Built as a portfolio project to demonstrate practical knowledge of network protocols
and systems-level C++ programming.

---

## Features

- **Layer 2 — Ethernet II**: source/destination MAC address, EtherType detection
  (IPv4, IPv6, ARP)
- **Layer 3 — IPv4**: version, IHL, TTL, protocol, source/destination IP; handles
  variable-length headers; RFC 1071 checksum verification; RFC 791 fragmentation
  flags (DF/MF) and offset
- **Layer 3 — IPv6**: hop limit, next header, 128-bit source/destination addresses;
  traffic class and flow label
- **Layer 3 — ARP**: operation (request/reply), sender/target MAC and IP (RFC 826)
- **Layer 4 — TCP**: ports, sequence/acknowledgment numbers, all 8 flags
  (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR), window size
- **Layer 4 — UDP**: ports, datagram length, checksum
- **Layer 4 — ICMP**: message type (Echo Request/Reply, Destination Unreachable,
  Time Exceeded), code
- **Layer 4 — ICMPv6**: full RFC 4443 type coverage including NDP messages
  (Neighbor Solicitation/Advertisement, Router Solicitation/Advertisement)
- **Live capture**: real-time packet capture from any Ethernet interface via
  `pcap_open_live` with promiscuous mode
- **BPF filter**: compile and install arbitrary Berkeley Packet Filter expressions
  (`-f "tcp port 443"`) directly into the kernel capture path
- **Zero-copy design**: parsers operate directly on the libpcap buffer without copying
  packet data
- **`std::optional`-based error handling**: no exceptions; a missing value signals a
  malformed or truncated frame

---

## Architecture

The project follows the OSI layered model: each protocol is an independent parser that
takes a raw byte span and returns a typed struct (or `std::nullopt` on failure).
The `netprobe` static library exposes these parsers; `main.cpp` wires them together.

```
┌───────────────────────────────────────────────┐
│                  cpp-netprobe                 │  ← CLI executable
│         reads .pcap via libpcap               │
└───────────────────┬───────────────────────────┘
                    │ raw bytes
        ┌───────────▼────────────┐
        │   parse_ethernet()     │  L2 — Ethernet II
        └───────────┬────────────┘
                    │ payload + EtherType
        ┌───────────▼────────────┐
        │   parse_ipv4()         │  L3 — IPv4
        └───────────┬────────────┘
                    │ payload + protocol number
     ┌──────────────┼──────────────┐
     │              │              │
┌────▼────┐   ┌─────▼────┐  ┌─────▼────┐
│parse_tcp│   │parse_udp │  │parse_icmp│  L4
└─────────┘   └──────────┘  └──────────┘
```

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| C++ compiler | C++20 or later | GCC 10+, Clang 12+, MSVC 19.29+ |
| CMake | 3.16 or later | |
| libpcap | 1.9 or later | `libpcap-dev` on Debian/Ubuntu |

### Install dependencies on Debian / Ubuntu

```bash
sudo apt update
sudo apt install build-essential cmake libpcap-dev
```

### Install dependencies on macOS (Homebrew)

```bash
brew install cmake libpcap
```

---

## Building

```bash
# Clone the repository
git clone https://github.com/cicixgliamici/cpp-netprobe.git
cd cpp-netprobe

# Configure and build (out-of-source)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run the smoke test
./build/smoke_test
```

---

## Usage

```bash
# Offline analysis from a PCAP file
cpp-netprobe -r <file.pcap>

# Live capture from a network interface
cpp-netprobe -i <interface>

# With a BPF filter expression (offline or live)
cpp-netprobe -r capture.pcap -f "tcp port 443"
cpp-netprobe -i eth0 -f "host 8.8.8.8 and udp"
```

### Example output

```
Reading from file: capture.pcap

========== Packet #1 ==========
Ethernet
  Src MAC:   08:00:27:aa:bb:cc
  Dst MAC:   52:54:00:12:34:56
  EtherType: 0x800 (IPv4)
IPv4
  Src IP:        192.168.1.10
  Dst IP:        8.8.8.8
  TTL:           64
  Protocol:      6 (TCP)
  Total Length:  60 bytes
  Checksum:      OK
  Flags:         DF
  Frag Offset:   0 (0 bytes)
TCP
  Src Port: 54321
  Dst Port: 443
  Seq:      1000
  Ack:      0
  Flags:    SYN
  Window:   65535
  Payload:  0 bytes

========== Packet #2 ==========
Ethernet
  Src MAC:   52:54:00:12:34:56
  Dst MAC:   ff:ff:ff:ff:ff:ff
  EtherType: 0x806 (ARP)
ARP
  Operation:   1 (Request)
  Sender MAC:  52:54:00:12:34:56
  Sender IP:   192.168.1.1
  Target MAC:  00:00:00:00:00:00
  Target IP:   192.168.1.10
```

---

## Project Structure

```
cpp-netprobe/
├── include/netprobe/       # Public headers — one per protocol
│   ├── utils.hpp           # Byte-order helpers, MAC/IP formatters
│   ├── ethernet.hpp
│   ├── ipv4.hpp
│   ├── tcp.hpp
│   ├── udp.hpp
│   └── icmp.hpp
├── src/                    # Implementation files
│   ├── main.cpp            # Entry point: PCAP loop + dispatch
│   ├── ethernet.cpp
│   ├── ipv4.cpp
│   ├── tcp.cpp
│   ├── udp.cpp
│   └── icmp.cpp
├── tests/
│   └── smoke_test.cpp      # Synthetic-frame integration test
├── CMakeLists.txt
├── CHANGELOG.md
└── .gitignore
```

---

## Roadmap

- [x] Live capture from network interface (`-i eth0`)
- [x] BPF filter expression via CLI (`-f "tcp port 80"`)
- [x] IPv6 and ARP parsers
- [x] IPv4 checksum verification (RFC 1071)
- [x] IPv4 fragmentation handling
- [ ] JSON output format (`--format json`)
- [ ] Per-session statistics and flow tracking (5-tuple)
- [ ] Unit tests with Catch2

---

## References

- [RFC 791](https://www.rfc-editor.org/rfc/rfc791) — Internet Protocol (IPv4)
- [RFC 792](https://www.rfc-editor.org/rfc/rfc792) — Internet Control Message Protocol (ICMP)
- [RFC 793](https://www.rfc-editor.org/rfc/rfc793) — Transmission Control Protocol (TCP)
- [RFC 768](https://www.rfc-editor.org/rfc/rfc768) — User Datagram Protocol (UDP)
- [RFC 826](https://www.rfc-editor.org/rfc/rfc826) — Address Resolution Protocol (ARP)
- [libpcap documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)

---

## License

This project is released under the [MIT License](LICENSE).