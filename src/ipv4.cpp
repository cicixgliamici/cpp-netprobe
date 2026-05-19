#include "netprobe/ipv4.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<IPv4Packet> parse_ipv4(const uint8_t* data, std::size_t len) {
    constexpr std::size_t min_ipv4_header_len = 20;

    if (len < min_ipv4_header_len) {
        return std::nullopt;
    }

    uint8_t version = data[0] >> 4;
    uint8_t ihl = data[0] & 0x0F;

    if (version != 4) {
        return std::nullopt;
    }

    std::size_t header_len = ihl * 4;

    if (ihl < 5 || len < header_len) {
        return std::nullopt;
    }

    uint16_t total_length = read_u16_be(data + 2);

    if (total_length < header_len) {
        return std::nullopt;
    }

    std::size_t effective_len = total_length;

    if (effective_len > len) {
        effective_len = len;
    }

    IPv4Packet packet;
    packet.version = version;
    packet.ihl = ihl;
    packet.ttl = data[8];
    packet.protocol = data[9];
    packet.total_length = total_length;
    packet.src_ip = ipv4_to_string(data + 12);
    packet.dst_ip = ipv4_to_string(data + 16);
    packet.payload = data + header_len;
    packet.payload_len = effective_len - header_len;

    return packet;
}

std::string ip_protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        default:
            return "Unknown";
    }
}

} // namespace netprobe
