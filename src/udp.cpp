#include "netprobe/udp.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<UdpDatagram> parse_udp(const uint8_t* data, std::size_t len) {
    // The UDP header is a fixed 8 bytes with no options.
    constexpr std::size_t udp_header_len = 8;

    if (len < udp_header_len) {
        return std::nullopt;
    }

    // Bytes 4-5: Length field = total UDP datagram size (header + data) in bytes.
    // The minimum valid value is 8 (header only, empty payload).
    // A value below 8 is malformed per RFC 768.
    uint16_t udp_length = read_u16_be(data + 4);

    if (udp_length < udp_header_len) {
        return std::nullopt;
    }

    // The captured buffer may be shorter than udp_length if the PCAP snaplen
    // truncated the packet.  effective_len is what we can safely read.
    std::size_t effective_len = udp_length;
    if (effective_len > len) {
        effective_len = len;
    }

    UdpDatagram datagram;
    datagram.src_port   = read_u16_be(data);      // bytes 0-1
    datagram.dst_port   = read_u16_be(data + 2);  // bytes 2-3
    datagram.length     = udp_length;
    // bytes 6-7: Checksum.  Stored as-is; we do not verify it here because
    // NIC hardware checksum offload can result in 0x0000 in software captures.
    datagram.checksum   = read_u16_be(data + 6);
    datagram.payload    = data + udp_header_len;
    datagram.payload_len = effective_len - udp_header_len;

    return datagram;
}

} // namespace netprobe
