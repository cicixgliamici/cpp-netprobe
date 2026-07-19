#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

// =============================================================================
// ipv6.hpp — Internet Protocol version 6 packet parser
//
// IPv6 is defined in RFC 8200 (which obsoletes RFC 2460).  Unlike IPv4, the
// fixed header length is always exactly 40 bytes — there are no options or a
// variable IHL field.  Options are expressed as "extension headers" chained
// via the Next Header field.
//
// Notable differences from IPv4:
//   - No checksum field in the IPv6 header (checksum offloaded to L4 protocols).
//   - No fragmentation at routers (only the source may fragment, via extension
//     headers), so there is no DF/MF flag or Fragment Offset in the base header.
//   - 128-bit (16-byte) addresses instead of 32-bit.
//   - TTL is renamed "Hop Limit" but serves the same purpose.
//   - Protocol field is renamed "Next Header" but carries the same IANA numbers.
//
// IPv6 fixed header layout (always 40 bytes):
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |Version| Traffic Class |            Flow Label                 |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |         Payload Length        |  Next Header  |   Hop Limit   |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                      Source Address (16 bytes)                +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  +                   Destination Address (16 bytes)              +
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Field breakdown in byte 0 and the first few bytes:
//   byte 0:      [Version(4)][Traffic Class high nibble(4)]
//   byte 1:      [Traffic Class low nibble(4)][Flow Label high nibble(4)]
//   bytes 2-3:   Flow Label (remaining 16 bits)
//   bytes 4-5:   Payload Length (length of everything after the 40-byte header)
//   byte  6:     Next Header (same IANA protocol numbers as IPv4 Protocol field)
//   byte  7:     Hop Limit
//   bytes 8-23:  Source Address (128 bits)
//   bytes 24-39: Destination Address (128 bits)
// =============================================================================

namespace netprobe {

/// Represents a parsed IPv6 fixed header.
///
/// Extension headers (Hop-by-Hop, Routing, Fragment, etc.) are not parsed;
/// `payload` points to the first byte after the 40-byte base header, which
/// may be an extension header or the L4 data depending on `next_header`.
struct IPv6Packet {
    uint8_t  traffic_class;  ///< 8-bit field (formerly DSCP+ECN, analogous to IPv4 ToS)
    uint32_t flow_label;     ///< 20-bit flow identifier for QoS; 0 means no specific flow
    uint16_t payload_length; ///< Length in bytes of everything after this 40-byte header
    uint8_t  next_header;    ///< Identifies the next protocol (same IANA numbers as IPv4 Protocol)
    uint8_t  hop_limit;      ///< Maximum number of router hops; analogous to IPv4 TTL
    std::string src_ip;      ///< Source address in colon-hex notation (full, uncompressed)
    std::string dst_ip;      ///< Destination address in colon-hex notation
    const uint8_t* payload;  ///< Zero-copy pointer to the data following the base header
    std::size_t    payload_len; ///< Bytes available in `payload` (capped at captured length)
};

/// Parse the IPv6 fixed header from @p data of length @p len.
///
/// Returns std::nullopt if:
///   - @p len is less than 40 bytes (minimum fixed header size), or
///   - the Version nibble is not 6.
///
/// Extension headers are not parsed; `payload` points immediately after
/// the 40-byte base header and `next_header` indicates what follows.
std::optional<IPv6Packet> parse_ipv6(const uint8_t* data, std::size_t len);

/// Format a 16-byte IPv6 address as a full (uncompressed) colon-separated
/// hex string, e.g. "2001:db8:0:0:0:0:0:1".
///
/// @p addr must point to exactly 16 bytes in network byte order.
/// Note: this produces the verbose form; RFC 5952 compression (e.g. "::1")
/// is not applied — keeping it simple makes the output unambiguous.
std::string ipv6_to_string(const uint8_t* addr);

} // namespace netprobe
