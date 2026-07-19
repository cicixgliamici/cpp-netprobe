#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>

// =============================================================================
// utils.hpp — Low-level byte-manipulation helpers
//
// Network protocols transmit multi-byte integers in big-endian order (also
// called "network byte order"), meaning the most significant byte comes first
// on the wire.  On little-endian CPUs (x86, ARM in LE mode) we must read two
// or four consecutive bytes and assemble them manually instead of casting a
// raw pointer directly — direct casting would silently produce wrong values.
//
// These helpers are declared `inline` so they expand at the call site with no
// function-call overhead.  They are all zero-copy: they take a raw pointer into
// the existing libpcap capture buffer and read from it without allocating memory.
// =============================================================================

namespace netprobe {

/// Read a 16-bit unsigned integer stored in big-endian order (network byte
/// order) from the address @p data.
///
/// Wire layout (2 bytes):
///   [data+0]  most-significant byte
///   [data+1]  least-significant byte
///
/// Example: bytes 0x08, 0x00 → returns 0x0800 (EtherType IPv4).
inline uint16_t read_u16_be(const uint8_t* data) {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

/// Read a 32-bit unsigned integer stored in big-endian order (network byte
/// order) from the address @p data.
///
/// Wire layout (4 bytes):
///   [data+0]  most-significant byte
///   [data+3]  least-significant byte
///
/// Example: bytes 0xC0, 0xA8, 0x01, 0x0A → returns 0xC0A8010A (192.168.1.10).
inline uint32_t read_u32_be(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) <<  8) |
            static_cast<uint32_t>(data[3]);
}

/// Format a 6-byte MAC address as a colon-separated lowercase hex string.
///
/// @p mac must point to exactly 6 bytes.
/// Example: {0x08, 0x00, 0x27, 0xAA, 0xBB, 0xCC} → "08:00:27:aa:bb:cc"
///
/// std::setw(2) + std::setfill('0') ensures each octet is zero-padded to two
/// hex digits (e.g. byte 0x0A → "0a", not "a").
inline std::string mac_to_string(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ':';
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

/// Format a 4-byte IPv4 address as a dot-decimal string.
///
/// @p ip must point to exactly 4 bytes in network byte order.
/// Example: {192, 168, 1, 10} → "192.168.1.10"
inline std::string ipv4_to_string(const uint8_t* ip) {
    std::ostringstream oss;
    oss << static_cast<int>(ip[0]) << '.'
        << static_cast<int>(ip[1]) << '.'
        << static_cast<int>(ip[2]) << '.'
        << static_cast<int>(ip[3]);
    return oss.str();
}

} // namespace netprobe
