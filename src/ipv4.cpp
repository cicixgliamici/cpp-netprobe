#include "netprobe/ipv4.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

// -----------------------------------------------------------------------------
// Internet Checksum (RFC 1071)
//
// The IPv4 header checksum is computed as follows:
//   1. Treat the entire header as a sequence of 16-bit words (network byte order).
//   2. Sum all words using one's complement arithmetic.
//   3. Take the one's complement of the final sum.
//   4. A sender stores this result in the Checksum field so that re-computing
//      the checksum over the whole header (including the Checksum field itself)
//      yields 0xFFFF.  We use this property for validation: if the received
//      header is uncorrupted, the 16-bit one's complement sum of all words
//      (including the stored checksum) must equal 0xFFFF.
//
// The "fold carry" step converts any 32-bit overflow back into the 16-bit range:
//   if sum = 0x1FFFE → fold → 0xFFFE + 0x0001 = 0xFFFF  ✓
// -----------------------------------------------------------------------------
static bool verify_ipv4_checksum(const uint8_t* data, std::size_t header_len) {
    uint32_t sum = 0;

    // header_len is always a multiple of 4 (IHL * 4), so it is always even.
    // We can safely step by 2 without an odd-byte tail case.
    for (std::size_t i = 0; i < header_len; i += 2) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
    }

    // Fold any carry bits from the upper 16 bits back into the lower 16 bits.
    // A single fold is sufficient because the maximum header length is 60 bytes
    // (30 words × 0xFFFF ≈ 0x001DFFD1), well within a single fold.
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return sum == 0xFFFF;
}

std::optional<IPv4Packet> parse_ipv4(const uint8_t* data, std::size_t len) {
    // The smallest valid IPv4 header is 20 bytes (IHL = 5, no options).
    constexpr std::size_t min_ipv4_header_len = 20;

    if (len < min_ipv4_header_len) {
        return std::nullopt;
    }

    // Byte 0 packs two 4-bit fields:
    //   [7:4] Version — must be 4 for IPv4
    //   [3:0] IHL    — number of 32-bit words in the header
    uint8_t version = data[0] >> 4;
    uint8_t ihl     = data[0] & 0x0F;

    if (version != 4) {
        return std::nullopt;
    }

    // IHL must be at least 5 (20 bytes); values below 5 are illegal per RFC 791.
    // header_len is always a multiple of 4 bytes.
    std::size_t header_len = static_cast<std::size_t>(ihl) * 4;

    if (ihl < 5 || len < header_len) {
        return std::nullopt;
    }

    // Bytes 2-3: total length of the IP datagram (header + payload).
    uint16_t total_length = read_u16_be(data + 2);

    // The total length must be at least as large as the header itself.
    if (total_length < header_len) {
        return std::nullopt;
    }

    // The capture may have been truncated (e.g. libpcap snaplen < total_length).
    // We cap the effective length at the number of bytes actually available.
    std::size_t effective_len = total_length;
    if (effective_len > len) {
        effective_len = len;
    }

    // ---------------------------------------------------------------------------
    // Flags and Fragment Offset (bytes 6-7)
    //
    // Bit layout of the 16-bit field at bytes 6-7:
    //
    //   bit 15 (byte6 bit7): Reserved — always 0
    //   bit 14 (byte6 bit6): DF (Don't Fragment)
    //   bit 13 (byte6 bit5): MF (More Fragments)
    //   bits 12-0:           Fragment Offset (unit = 8 bytes)
    //
    //   byte6: [R][DF][MF][fo12][fo11][fo10][fo9][fo8]
    //   byte7: [fo7][fo6][fo5][fo4][fo3][fo2][fo1][fo0]
    //
    // We store the 3-bit flags value (bits 15-13 of the 16-bit field, i.e.
    // the top 3 bits of byte 6) and the 13-bit offset separately.
    // ---------------------------------------------------------------------------
    uint8_t  flags           = (data[6] >> 5) & 0x07;
    uint16_t fragment_offset = static_cast<uint16_t>((data[6] & 0x1F) << 8) | data[7];

    IPv4Packet packet;
    packet.version         = version;
    packet.ihl             = ihl;
    packet.ttl             = data[8];   // byte 8: Time to Live
    packet.protocol        = data[9];   // byte 9: encapsulated L4 protocol number
    packet.total_length    = total_length;
    packet.flags           = flags;
    packet.fragment_offset = fragment_offset;
    packet.checksum_valid  = verify_ipv4_checksum(data, header_len);
    packet.src_ip          = ipv4_to_string(data + 12); // bytes 12-15: source IP
    packet.dst_ip          = ipv4_to_string(data + 16); // bytes 16-19: destination IP
    packet.payload         = data + header_len;
    packet.payload_len     = effective_len - header_len;

    return packet;
}

std::string ip_protocol_to_string(uint8_t protocol) {
    // Protocol numbers are assigned by IANA.  Only the most common ones
    // relevant to this analyzer are listed here.
    switch (protocol) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6-in-IPv4";  // IPv6 encapsulated in IPv4 (6in4 tunnel)
        case 58: return "ICMPv6";
        default: return "Unknown";
    }
}

} // namespace netprobe
