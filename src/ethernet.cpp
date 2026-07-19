#include "netprobe/ethernet.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<EthernetFrame> parse_ethernet(const uint8_t* data, std::size_t len) {
    // An Ethernet II header is always exactly 14 bytes:
    //   6 bytes  destination MAC
    //   6 bytes  source MAC
    //   2 bytes  EtherType
    // If the buffer is shorter, the frame is definitely malformed.
    constexpr std::size_t ethernet_header_len = 14;

    if (len < ethernet_header_len) {
        return std::nullopt;
    }

    EthernetFrame frame;
    // Destination MAC: first 6 bytes.  mac_to_string formats them as "xx:xx:xx:xx:xx:xx".
    frame.dst_mac = mac_to_string(data);
    // Source MAC: next 6 bytes (offset 6).
    frame.src_mac = mac_to_string(data + 6);
    // EtherType: bytes 12-13 in big-endian order.
    frame.ether_type = read_u16_be(data + 12);
    // Zero-copy payload: we do not allocate or copy — we simply point into
    // the capture buffer at byte 14 and record how many bytes follow.
    frame.payload     = data + ethernet_header_len;
    frame.payload_len = len - ethernet_header_len;

    return frame;
}

std::string ether_type_to_string(uint16_t ether_type) {
    // Only the most common types are listed here; everything else returns "Unknown".
    // A complete registry is maintained by IANA:
    // https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
    switch (ether_type) {
        case 0x0800: return "IPv4";
        case 0x86DD: return "IPv6";
        case 0x0806: return "ARP";
        default:     return "Unknown";
    }
}

} // namespace netprobe
