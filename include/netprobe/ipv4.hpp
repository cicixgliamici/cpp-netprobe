#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

// =============================================================================
// ipv4.hpp — Internet Protocol version 4 packet parser
//
// IPv4 is defined in RFC 791.  The header has a variable length controlled by
// the IHL (Internet Header Length) field, which counts the number of 32-bit
// words.  The minimum value is 5, giving a 20-byte header; a value of 15 gives
// the maximum 60-byte header (40 bytes of options).
//
// IPv4 header layout (minimum 20 bytes):
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |Version|  IHL  |Type of Service|         Total Length          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |         Identification        |Flags|     Fragment Offset      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Time to Live |    Protocol   |        Header Checksum        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                       Source Address                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Destination Address                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Options (if IHL > 5)                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Fragmentation (RFC 791 §2.3):
//   Bytes 6-7 carry the Flags (3 bits) and Fragment Offset (13 bits).
//   - Bit 15 (Reserved): must be 0.
//   - Bit 14 (DF — Don't Fragment): if set, routers must not fragment this datagram.
//   - Bit 13 (MF — More Fragments): if set, more fragments follow.  The last
//     fragment of a datagram has MF=0.
//   - Bits 12-0 (Fragment Offset): position of this fragment's payload within
//     the original unfragmented datagram, measured in units of 8 bytes.
//
//   A packet is part of a fragmented datagram if MF=1 OR Fragment Offset > 0.
//   Only the first fragment (offset = 0) carries the L4 header; all subsequent
//   fragments start at a non-zero offset and contain only raw payload data,
//   so L4 parsing must be skipped for them.
// =============================================================================

namespace netprobe {

/// Represents a parsed IPv4 packet.
///
/// `payload` and `payload_len` are a zero-copy view into the capture buffer.
struct IPv4Packet {
    uint8_t  version;         ///< IP version (always 4 for IPv4)
    uint8_t  ihl;             ///< Internet Header Length in 32-bit words (min 5 → 20 bytes)
    uint8_t  ttl;             ///< Time to Live: decremented by each router; packet is
                              ///< discarded when it reaches 0 (prevents routing loops)
    uint8_t  protocol;        ///< Identifies the L4 protocol: 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6
    uint16_t total_length;    ///< Total size of IP datagram in bytes (header + payload)
    uint8_t  flags;           ///< 3-bit Flags field: bit1=DF (Don't Fragment), bit0=MF (More Fragments)
    uint16_t fragment_offset; ///< 13-bit offset of this fragment in units of 8 bytes (RFC 791)
    bool     checksum_valid;  ///< true if the RFC 1071 Internet Checksum over the header passes
    std::string src_ip;       ///< Source IP address in dot-decimal notation (e.g. "192.168.1.10")
    std::string dst_ip;       ///< Destination IP address in dot-decimal notation
    const uint8_t* payload;   ///< Pointer to the first byte of the L4 payload (zero-copy)
    std::size_t    payload_len; ///< Number of bytes in the L4 payload
};

/// Parse a raw IPv4 packet from @p data of length @p len.
///
/// Validates the version field (must be 4), the IHL range (must be ≥ 5), and
/// that the buffer is large enough to hold the full header.  Sets
/// `checksum_valid` based on a RFC 1071 checksum computation.
///
/// Returns std::nullopt on any validation failure.
std::optional<IPv4Packet> parse_ipv4(const uint8_t* data, std::size_t len);

/// Return a human-readable name for common IP protocol numbers.
/// Protocol numbers are defined by IANA:
/// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
std::string ip_protocol_to_string(uint8_t protocol);

} // namespace netprobe
