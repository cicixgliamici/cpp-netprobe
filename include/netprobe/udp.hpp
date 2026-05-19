#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

namespace netprobe {

struct UdpDatagram {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    const uint8_t* payload;
    std::size_t payload_len;
};

std::optional<UdpDatagram> parse_udp(const uint8_t* data, std::size_t len);

} // namespace netprobe
