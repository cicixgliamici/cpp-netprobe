#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

namespace netprobe {

struct IPv4Packet {
    uint8_t version;
    uint8_t ihl;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t total_length;
    std::string src_ip;
    std::string dst_ip;
    const uint8_t* payload;
    std::size_t payload_len;
};

std::optional<IPv4Packet> parse_ipv4(const uint8_t* data, std::size_t len);

std::string ip_protocol_to_string(uint8_t protocol);

} // namespace netprobe
