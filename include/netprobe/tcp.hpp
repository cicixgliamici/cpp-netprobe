#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace netprobe {

struct TcpSegment {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    const uint8_t* payload;
    std::size_t payload_len;
};

std::optional<TcpSegment> parse_tcp(const uint8_t* data, std::size_t len);

std::vector<std::string> tcp_flags_to_strings(uint8_t flags);

} // namespace netprobe
