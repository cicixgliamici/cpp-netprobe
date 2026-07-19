#include "netprobe/ipv6.hpp"
#include "netprobe/utils.hpp"

#include <sstream>
#include <iomanip>

namespace netprobe {

std::string ipv6_to_string(const uint8_t* addr) {
    // An IPv6 address is 128 bits = 16 bytes, displayed as 8 groups of 4 hex
    // digits separated by colons.  We step through the 16 bytes two at a time,
    // combining each pair into a 16-bit value and printing it as hex.
    //
    // Example: bytes {0x20,0x01, 0x0d,0xb8, 0x00,0x00, ...}
    //          → "2001:db8:0:0:0:0:0:0"
    //
    // We intentionally produce the full form without RFC 5952 compression
    // (e.g. "::1") to keep the output unambiguous and easier to parse.
    std::ostringstream oss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) oss << ':';
        // Combine two consecutive bytes into one 16-bit group.
        oss << std::hex
            << static_cast<unsigned>((static_cast<uint16_t>(addr[i]) << 8) | addr[i + 1]);
    }
    return oss.str();
}

std::optional<IPv6Packet> parse_ipv6(const uint8_t* data, std::size_t len) {
    // RFC 8200: the IPv6 base header is exactly 40 bytes, no more, no less.
    constexpr std::size_t ipv6_header_len = 40;

    if (len < ipv6_header_len) {
        return std::nullopt;
    }

    // Byte 0: [Version(4 bits)][Traffic Class high nibble(4 bits)]
    uint8_t version = data[0] >> 4;
    if (version != 6) {
        return std::nullopt;
    }

    IPv6Packet packet;

    // ---------------------------------------------------------------------------
    // Traffic Class (8 bits): split across the lower nibble of byte 0 and the
    // upper nibble of byte 1.
    //
    //   byte0: [V][V][V][V][TC7][TC6][TC5][TC4]
    //   byte1: [TC3][TC2][TC1][TC0][FL19][FL18][FL17][FL16]
    //
    // To reconstruct TC: take the low 4 bits of byte 0 and shift them to the
    // high nibble of the result, then OR in the high 4 bits of byte 1.
    // ---------------------------------------------------------------------------
    packet.traffic_class = static_cast<uint8_t>(((data[0] & 0x0F) << 4) | (data[1] >> 4));

    // ---------------------------------------------------------------------------
    // Flow Label (20 bits): occupies the low nibble of byte 1 plus all of
    // bytes 2 and 3.
    //
    //   byte1 bits[3:0] → bits [19:16] of flow label
    //   byte2           → bits [15:8]
    //   byte3           → bits [7:0]
    // ---------------------------------------------------------------------------
    packet.flow_label = (static_cast<uint32_t>(data[1] & 0x0F) << 16) |
                        (static_cast<uint32_t>(data[2])         <<  8) |
                         static_cast<uint32_t>(data[3]);

    // bytes 4-5: Payload Length — number of bytes after this 40-byte header
    packet.payload_length = read_u16_be(data + 4);
    // byte 6: Next Header — same IANA protocol number as IPv4's Protocol field
    packet.next_header    = data[6];
    // byte 7: Hop Limit — analogous to IPv4 TTL; decremented at each router hop
    packet.hop_limit      = data[7];
    // bytes 8-23:  Source Address (128 bits = 16 bytes)
    packet.src_ip         = ipv6_to_string(data + 8);
    // bytes 24-39: Destination Address (128 bits = 16 bytes)
    packet.dst_ip         = ipv6_to_string(data + 24);

    // Zero-copy payload pointer: immediately after the 40-byte base header.
    packet.payload = data + ipv6_header_len;

    // The capture may be truncated — cap payload_len at actually available bytes.
    // `payload_length` from the header is the "expected" size; `len` is what
    // libpcap actually delivered.
    std::size_t total     = ipv6_header_len + static_cast<std::size_t>(packet.payload_length);
    std::size_t effective = (total > len) ? len : total;
    packet.payload_len    = effective - ipv6_header_len;

    return packet;
}

} // namespace netprobe
