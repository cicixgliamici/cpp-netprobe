#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

namespace netprobe {

struct IcmpPacket {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    const uint8_t* payload;
    std::size_t payload_len;
};

std::optional<IcmpPacket> parse_icmp(const uint8_t* data, std::size_t len);

std::string icmp_type_to_string(uint8_t type);

} // namespace netprobe
