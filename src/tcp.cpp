#include "netprobe/tcp.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<TcpSegment> parse_tcp(const uint8_t* data, std::size_t len) {
    constexpr std::size_t min_tcp_header_len = 20;

    if (len < min_tcp_header_len) {
        return std::nullopt;
    }

    uint8_t data_offset = data[12] >> 4;
    std::size_t header_len = data_offset * 4;

    if (data_offset < 5 || len < header_len) {
        return std::nullopt;
    }

    TcpSegment segment;
    segment.src_port = read_u16_be(data);
    segment.dst_port = read_u16_be(data + 2);
    segment.sequence_number = read_u32_be(data + 4);
    segment.acknowledgment_number = read_u32_be(data + 8);
    segment.data_offset = data_offset;
    segment.flags = data[13];
    segment.window_size = read_u16_be(data + 14);
    segment.payload = data + header_len;
    segment.payload_len = len - header_len;

    return segment;
}

std::vector<std::string> tcp_flags_to_strings(uint8_t flags) {
    std::vector<std::string> result;

    if (flags & 0x01) result.push_back("FIN");
    if (flags & 0x02) result.push_back("SYN");
    if (flags & 0x04) result.push_back("RST");
    if (flags & 0x08) result.push_back("PSH");
    if (flags & 0x10) result.push_back("ACK");
    if (flags & 0x20) result.push_back("URG");
    if (flags & 0x40) result.push_back("ECE");
    if (flags & 0x80) result.push_back("CWR");

    return result;
}

} // namespace netprobe
