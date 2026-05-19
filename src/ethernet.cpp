#include "netprobe/ethernet.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<EthernetFrame> parse_ethernet(const uint8_t* data, std::size_t len) {
    constexpr std::size_t ethernet_header_len = 14;

    if (len < ethernet_header_len) {
        return std::nullopt;
    }

    EthernetFrame frame;
    frame.dst_mac = mac_to_string(data);
    frame.src_mac = mac_to_string(data + 6);
    frame.ether_type = read_u16_be(data + 12);
    frame.payload = data + ethernet_header_len;
    frame.payload_len = len - ethernet_header_len;

    return frame;
}

std::string ether_type_to_string(uint16_t ether_type) {
    switch (ether_type) {
        case 0x0800:
            return "IPv4";
        case 0x86DD:
            return "IPv6";
        case 0x0806:
            return "ARP";
        default:
            return "Unknown";
    }
}

} // namespace netprobe
