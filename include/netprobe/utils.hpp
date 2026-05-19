#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>

namespace netprobe {

inline uint16_t read_u16_be(const uint8_t* data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

inline uint32_t read_u32_be(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8)  |
           (static_cast<uint32_t>(data[3]));
}

inline std::string mac_to_string(const uint8_t* mac) {
    std::ostringstream oss;

    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            oss << ":";
        }

        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }

    return oss.str();
}

inline std::string ipv4_to_string(const uint8_t* ip) {
    std::ostringstream oss;

    oss << static_cast<int>(ip[0]) << "."
        << static_cast<int>(ip[1]) << "."
        << static_cast<int>(ip[2]) << "."
        << static_cast<int>(ip[3]);

    return oss.str();
}

} // namespace netprobe
