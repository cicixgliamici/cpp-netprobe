# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- IPv6 parser (`parse_ipv6`): fixed 40-byte header (RFC 8200), traffic class, flow label,
  hop limit, next-header dispatch, 128-bit address formatting
- ARP parser (`parse_arp`): Ethernet+IPv4 hardware/protocol type, operation
  (request/reply), sender/target MAC and IP (RFC 826)
- IPv4 checksum verification via Internet Checksum algorithm (RFC 1071): new
  `checksum_valid` field on `IPv4Packet`; invalid checksums are flagged in the output
- IPv4 fragmentation fields on `IPv4Packet`: `flags` (DF/MF bits) and `fragment_offset`
  (13-bit, units of 8 bytes, per RFC 791); fragmented non-initial frames skip L4 parsing
- ICMPv6 type string mapping (`icmpv6_type_to_string`): full RFC 4443 error types plus
  NDP messages (RFC 4861) and multicast listener messages (RFC 3810)
- Live capture mode: `cpp-netprobe -i <interface>` opens the interface in promiscuous
  mode via `pcap_open_live`; validates Ethernet link-layer type
- BPF filter support: `-f "<expression>"` compiles and installs a Berkeley Packet Filter
  via `pcap_compile` / `pcap_setfilter`; invalid expressions are reported with an error
- CLI argument parser replacing the single positional argument:
  `-r <file>` (offline), `-i <interface>` (live), `-f <filter>` (optional)
- SIGINT handler (`signal_handler`): live capture stops cleanly on Ctrl-C and prints
  the number of packets processed
- Protocol `ip_protocol_to_string` extended with ICMPv6 (58) and IPv6-in-IPv4 (41)

## [0.1.0] — 2026-07-19

### Added
- CMake build system (C++20, CMake 3.16+) with separate `netprobe` static library and
  `cpp-netprobe` executable targets
- `include/netprobe/utils.hpp`: low-level helpers (`read_u16_be`, `read_u32_be`,
  `mac_to_string`, `ipv4_to_string`)
- Ethernet II parser (`parse_ethernet`): destination/source MAC, EtherType; recognises
  IPv4 (0x0800), IPv6 (0x86DD), ARP (0x0806)
- IPv4 parser (`parse_ipv4`): version, IHL, TTL, protocol, total length, source/destination
  IP; validates version field and IHL range
- TCP parser (`parse_tcp`): source/destination ports, sequence and acknowledgment numbers,
  data offset, all 8 flags (FIN/SYN/RST/PSH/ACK/URG/ECE/CWR), window size
- UDP parser (`parse_udp`): source/destination ports, length, checksum
- ICMP parser (`parse_icmp`): type, code, checksum; human-readable type strings for
  Echo Request/Reply, Destination Unreachable, Time Exceeded
- `src/main.cpp`: offline PCAP reader via `pcap_open_offline` / `pcap_next_ex` with
  per-packet protocol dissection printed to stdout
- `tests/smoke_test.cpp`: synthetic Ethernet+IPv4 frame with assertions on parsed fields
- `.gitignore`: excludes build artefacts, PCAP captures, IDE files, and `local/`

### Fixed
- ICMP header length corrected from 4 to 8 bytes as specified in RFC 792
  (type + code + checksum + 4-byte rest-of-header); previously the payload pointer
  started 4 bytes too early

[Unreleased]: https://github.com/cicixgliamici/cpp-netprobe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cicixgliamici/cpp-netprobe/releases/tag/v0.1.0
