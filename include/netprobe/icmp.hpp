#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

// =============================================================================
// icmp.hpp — ICMP and ICMPv6 message parsers
//
// ICMPv4 is defined in RFC 792.  It carries control and error messages for
// IPv4 networks (ping, destination unreachable, time exceeded, etc.).
// ICMPv6 is defined in RFC 4443.  It serves the same purpose for IPv6 and
// additionally carries Neighbor Discovery Protocol (NDP) messages (RFC 4861)
// which replace ARP in IPv6 networks.
//
// Both ICMP and ICMPv6 share the same 8-byte base header structure:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |      Type     |      Code     |           Checksum            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                   Rest of Header (4 bytes)                    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Data (variable length)                     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Type: identifies the general category of the message.
// Code: sub-type within the category (provides more detail about the Type).
// Checksum: one's complement checksum over the ICMP header and data.
//   For ICMPv6, this also covers a pseudo-header (src/dst IP, length, 58).
// Rest of Header: 4 bytes whose meaning depends on Type/Code.  For Echo
//   messages they carry the Identifier and Sequence Number of the ping.
//
// ICMPv4 vs ICMPv6 type spaces:
//   ICMPv4 types 0-255 and ICMPv6 types 0-255 are entirely separate
//   namespaces.  The same numeric type can mean different things in each.
//   We use separate `*_type_to_string` functions to handle this correctly.
//
// Important ICMPv4 types: 0=Echo Reply, 3=Destination Unreachable,
//   8=Echo Request, 11=Time Exceeded.
// Important ICMPv6 types: 1-4=Error messages, 128-129=Echo Req/Reply,
//   133-137=Neighbor Discovery Protocol (NDP).
// =============================================================================

namespace netprobe {

/// Represents a parsed ICMP (or ICMPv6) message base header.
///
/// We use the same struct for both ICMPv4 and ICMPv6 because their 8-byte
/// base headers are structurally identical.  The caller must use the
/// appropriate `*_type_to_string` function to interpret `type` correctly.
///
/// `payload` points to the "Data" section that follows the 8-byte header
/// (e.g. for Echo, this holds the ping payload; for Unreachable, it holds
/// the beginning of the original IP header that triggered the error).
struct IcmpPacket {
    uint8_t  type;          ///< Message type — interpretation depends on ICMPv4 vs ICMPv6
    uint8_t  code;          ///< Sub-type code; provides detail within the message type
    uint16_t checksum;      ///< One's complement checksum (raw value, not verified here)
    const uint8_t* payload;   ///< Zero-copy pointer to the data section after the 8-byte header
    std::size_t    payload_len; ///< Number of bytes available in `payload`
};

/// Parse a raw ICMP (or ICMPv6) message from @p data of length @p len.
///
/// Returns std::nullopt if the buffer is shorter than the 8-byte base header.
/// This function is reused for both ICMPv4 (IP protocol 1) and ICMPv6
/// (IP protocol 58) since their base header layouts are identical.
std::optional<IcmpPacket> parse_icmp(const uint8_t* data, std::size_t len);

/// Return a human-readable name for ICMPv4 message types (RFC 792).
/// Returns "Unknown" for unrecognised types.
std::string icmp_type_to_string(uint8_t type);

/// Return a human-readable name for ICMPv6 message types (RFC 4443).
///
/// ICMPv6 type space (RFC 4443 §2.1):
///   Types 0-127  are error messages (should not be generated for ICMP errors).
///   Types 128-255 are informational messages.
///
/// Also covers NDP messages (RFC 4861) and MLDv2 (RFC 3810).
/// Returns "Unknown" for unrecognised types.
std::string icmpv6_type_to_string(uint8_t type);

} // namespace netprobe
