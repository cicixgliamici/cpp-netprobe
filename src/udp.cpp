#include "netprobe/udp.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<UdpDatagram> parse_udp(const uint8_t* data, std::size_t len) {
    constexpr std::size_t udp_header_len = 8;

    if (len < udp_header_len) {
        return std::nullopt;
    }

    uint16_t udp_length = read_u16_be(data + 4);

    if (udp_length < udp_header_len) {
        return std::nullopt;
    }

    std::size_t effective_len = udp_length;

    if (effective_len > len) {
        effective_len = len;
    }

    UdpDatagram datagram;
    datagram.src_port = read_u16_be(data);
    datagram.dst_port = read_u16_be(data + 2);
    datagram.length = udp_length;
    datagram.checksum = read_u16_be(data + 6);
    datagram.payload = data + udp_header_len;
    datagram.payload_len = effective_len - udp_header_len;

    return datagram;
}

} // namespace netprobe
