#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

// =============================================================================
// ethernet.hpp — Ethernet II frame parser
//
// Ethernet II is the most common framing standard on wired LANs (IEEE 802.3).
// Every packet captured from a standard NIC starts with a 14-byte Ethernet
// header, making this the first parser invoked on any raw capture buffer.
//
// Ethernet II frame layout (bytes on the wire):
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                 Destination MAC (6 bytes)                      |
//  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                               |      Source MAC (6 bytes)      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//  |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                               |      EtherType (2 bytes)       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                   Payload (variable length)                    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Well-known EtherType values:
//   0x0800  IPv4
//   0x86DD  IPv6
//   0x0806  ARP
// =============================================================================

namespace netprobe {

/// Represents a parsed Ethernet II frame.
///
/// The `payload` pointer and `payload_len` give a zero-copy view into the
/// original libpcap buffer — no data is copied.  The caller must ensure the
/// underlying buffer remains valid while this struct is in use.
struct EthernetFrame {
    std::string dst_mac;      ///< Destination MAC address (e.g. "52:54:00:12:34:56")
    std::string src_mac;      ///< Source MAC address      (e.g. "08:00:27:aa:bb:cc")
    uint16_t    ether_type;   ///< EtherType field: identifies the encapsulated protocol
    const uint8_t* payload;   ///< Pointer to the first byte after the 14-byte header
    std::size_t    payload_len; ///< Number of bytes available in `payload`
};

/// Parse a raw Ethernet II frame from @p data of length @p len.
///
/// Returns std::nullopt if the buffer is shorter than the minimum 14-byte
/// Ethernet header.  On success the returned struct contains a zero-copy
/// reference into the caller's buffer.
std::optional<EthernetFrame> parse_ethernet(const uint8_t* data, std::size_t len);

/// Return a human-readable name for common EtherType values.
/// Returns "Unknown" for unrecognised types.
std::string ether_type_to_string(uint16_t ether_type);

} // namespace netprobe
