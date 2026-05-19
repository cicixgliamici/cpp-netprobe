#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

namespace netprobe {

struct EthernetFrame {
    std::string dst_mac;
    std::string src_mac;
    uint16_t ether_type;
    const uint8_t* payload;
    std::size_t payload_len;
};

std::optional<EthernetFrame> parse_ethernet(const uint8_t* data, std::size_t len);

std::string ether_type_to_string(uint16_t ether_type);

} // namespace netprobe
