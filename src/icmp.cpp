#include "netprobe/icmp.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<IcmpPacket> parse_icmp(const uint8_t* data, std::size_t len) {
    constexpr std::size_t icmp_header_len = 4;

    if (len < icmp_header_len) {
        return std::nullopt;
    }

    IcmpPacket packet;
    packet.type = data[0];
    packet.code = data[1];
    packet.checksum = read_u16_be(data + 2);
    packet.payload = data + icmp_header_len;
    packet.payload_len = len - icmp_header_len;

    return packet;
}

std::string icmp_type_to_string(uint8_t type) {
    switch (type) {
        case 0:
            return "Echo Reply";
        case 3:
            return "Destination Unreachable";
        case 8:
            return "Echo Request";
        case 11:
            return "Time Exceeded";
        default:
            return "Unknown";
    }
}

} // namespace netprobe
