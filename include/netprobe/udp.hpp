#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

// =============================================================================
// udp.hpp — User Datagram Protocol datagram parser
//
// UDP is defined in RFC 768.  Unlike TCP it is connectionless and provides no
// delivery guarantees, ordering, or retransmission.  It is used where low
// latency or simplicity matters more than reliability (DNS, DHCP, VoIP, video
// streaming, gaming, QUIC transport, etc.).
//
// UDP header layout (fixed 8 bytes):
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Source Port          |       Destination Port        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |            Length             |           Checksum            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Data (variable length)                     |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Length field: total size of the UDP datagram in bytes (header + data).
//   The minimum valid value is 8 (header only, zero bytes of data).
//
// Checksum field: optional in IPv4 (a value of 0x0000 means "not computed"),
//   mandatory in IPv6.  The checksum covers a pseudo-header (src/dst IP,
//   protocol, UDP length), the UDP header, and the UDP data.  We store the
//   raw value here but do not verify it — checksum offload to the NIC means
//   software-computed checksums are often 0 in live captures.
// =============================================================================

namespace netprobe {

/// Represents a parsed UDP datagram.
///
/// `payload` and `payload_len` are zero-copy references into the capture buffer.
struct UdpDatagram {
    uint16_t src_port;     ///< Source port (e.g. ephemeral port chosen by the OS)
    uint16_t dst_port;     ///< Destination port (e.g. 53=DNS, 67/68=DHCP, 5353=mDNS)
    uint16_t length;       ///< Total UDP datagram length in bytes (header 8 + data n)
    uint16_t checksum;     ///< Raw checksum field; 0x0000 means "not computed" in IPv4
    const uint8_t* payload;   ///< Zero-copy pointer to the application-layer data
    std::size_t    payload_len; ///< Number of bytes of application-layer data
};

/// Parse a raw UDP datagram from @p data of length @p len.
///
/// Validates that the buffer is at least 8 bytes and that the Length field is
/// consistent (≥ 8).  Payload length is capped at the captured data available
/// to handle truncated captures.
///
/// Returns std::nullopt on any validation failure.
std::optional<UdpDatagram> parse_udp(const uint8_t* data, std::size_t len);

} // namespace netprobe
