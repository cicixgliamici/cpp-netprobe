#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

// =============================================================================
// tcp.hpp — Transmission Control Protocol segment parser
//
// TCP is defined in RFC 9293 (which obsoletes RFC 793).  It provides a
// reliable, ordered, full-duplex byte stream between two endpoints.  It
// achieves this through sequence numbers, acknowledgments, and a sliding
// window flow-control mechanism.
//
// TCP header layout (minimum 20 bytes; up to 60 bytes with options):
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Source Port          |       Destination Port        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                        Sequence Number                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Acknowledgment Number                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Data |       |C|E|U|A|P|R|S|F|                              |
//  | Offset|  Rsv  |W|C|R|C|S|S|Y|I|            Window           |
//  |       |       |R|E|G|K|H|T|N|N|                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Checksum            |        Urgent Pointer         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Options (if Data Offset > 5)               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Data Offset (4 bits, byte 12 high nibble):
//   Number of 32-bit words in the TCP header (including options).
//   Minimum value: 5 → 20-byte header with no options.
//   Maximum value: 15 → 60-byte header.
//   Actual header size in bytes = Data Offset × 4.
//
// Flags byte (byte 13):
//   Bit 7 (0x80): CWR — Congestion Window Reduced (RFC 3168, ECN)
//   Bit 6 (0x40): ECE — ECN-Echo (RFC 3168, ECN)
//   Bit 5 (0x20): URG — Urgent Pointer field is significant
//   Bit 4 (0x10): ACK — Acknowledgment field is significant
//   Bit 3 (0x08): PSH — Push: receiver should pass data to the application immediately
//   Bit 2 (0x04): RST — Reset the connection
//   Bit 1 (0x02): SYN — Synchronize sequence numbers (connection establishment)
//   Bit 0 (0x01): FIN — No more data from sender (connection teardown)
// =============================================================================

namespace netprobe {

/// Represents a parsed TCP segment.
///
/// `payload` and `payload_len` are zero-copy references into the capture buffer.
struct TcpSegment {
    uint16_t src_port;             ///< Source port number (identifies the sending application)
    uint16_t dst_port;             ///< Destination port number (identifies the target application)
    uint32_t sequence_number;      ///< Position of the first payload byte in the sender's byte stream
    uint32_t acknowledgment_number;///< Next sequence number the sender expects to receive (valid when ACK=1)
    uint8_t  data_offset;          ///< Header length in 32-bit words (×4 = bytes); minimum 5
    uint8_t  flags;                ///< Control bits: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN (bit7..bit0)
    uint16_t window_size;          ///< Flow control: number of bytes the sender is willing to receive
    const uint8_t* payload;        ///< Zero-copy pointer to the application-layer data
    std::size_t    payload_len;    ///< Number of bytes of application-layer data in this segment
};

/// Parse a raw TCP segment from @p data of length @p len.
///
/// Validates the Data Offset field (must be ≥ 5) and ensures the buffer is
/// large enough to hold the full header.
///
/// Returns std::nullopt on any validation failure.
std::optional<TcpSegment> parse_tcp(const uint8_t* data, std::size_t len);

/// Return a vector of human-readable flag names for the set bits in @p flags.
///
/// Example: flags = 0x12 (SYN + ACK) → {"SYN", "ACK"}
/// An empty vector means no flags are set.
std::vector<std::string> tcp_flags_to_strings(uint8_t flags);

} // namespace netprobe
