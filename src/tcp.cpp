#include "netprobe/tcp.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<TcpSegment> parse_tcp(const uint8_t* data, std::size_t len) {
    // The smallest valid TCP header (no options) is 20 bytes.
    constexpr std::size_t min_tcp_header_len = 20;

    if (len < min_tcp_header_len) {
        return std::nullopt;
    }

    // Byte 12 high nibble: Data Offset — number of 32-bit words in the header.
    // Multiply by 4 to get the header size in bytes.
    // A value below 5 is illegal (it would be less than the 20-byte minimum).
    uint8_t     data_offset = data[12] >> 4;
    std::size_t header_len  = static_cast<std::size_t>(data_offset) * 4;

    if (data_offset < 5 || len < header_len) {
        return std::nullopt;
    }

    TcpSegment segment;
    segment.src_port             = read_u16_be(data);      // bytes 0-1
    segment.dst_port             = read_u16_be(data + 2);  // bytes 2-3
    segment.sequence_number      = read_u32_be(data + 4);  // bytes 4-7
    segment.acknowledgment_number = read_u32_be(data + 8); // bytes 8-11
    segment.data_offset          = data_offset;
    // Byte 13: the 8 control flags, from MSB to LSB:
    //   CWR(7) ECE(6) URG(5) ACK(4) PSH(3) RST(2) SYN(1) FIN(0)
    segment.flags                = data[13];
    segment.window_size          = read_u16_be(data + 14); // bytes 14-15
    // Payload begins after the variable-length header (header_len accounts
    // for any options).  Checksum and Urgent Pointer (bytes 16-19) are not
    // stored in the struct because they are rarely needed for passive analysis.
    segment.payload     = data + header_len;
    segment.payload_len = len - header_len;

    return segment;
}

std::vector<std::string> tcp_flags_to_strings(uint8_t flags) {
    // Check each bit from lowest to highest (FIN first, CWR last).
    // This ordering matches the conventional display used by Wireshark and tcpdump.
    std::vector<std::string> result;

    if (flags & 0x01) result.push_back("FIN"); // connection teardown
    if (flags & 0x02) result.push_back("SYN"); // connection establishment
    if (flags & 0x04) result.push_back("RST"); // abrupt connection reset
    if (flags & 0x08) result.push_back("PSH"); // push buffered data to application
    if (flags & 0x10) result.push_back("ACK"); // acknowledgment number is valid
    if (flags & 0x20) result.push_back("URG"); // urgent pointer is significant
    if (flags & 0x40) result.push_back("ECE"); // ECN-Echo (congestion notification)
    if (flags & 0x80) result.push_back("CWR"); // Congestion Window Reduced

    return result;
}

} // namespace netprobe
