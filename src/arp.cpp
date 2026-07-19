#include "netprobe/arp.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<ArpPacket> parse_arp(const uint8_t* data, std::size_t len) {
    // The ARP fixed header (everything before the variable-length addresses)
    // is 8 bytes: hardware type (2) + protocol type (2) + hw_len (1) +
    // proto_len (1) + operation (2).
    constexpr std::size_t arp_fixed_header = 8;

    if (len < arp_fixed_header) {
        return std::nullopt;
    }

    // Read the hardware and protocol type fields to decide whether we can parse
    // this packet.  Both are 16-bit big-endian values.
    uint16_t hw_type    = read_u16_be(data);
    uint16_t proto_type = read_u16_be(data + 2);
    // hw_len and proto_len tell us the byte size of each address in the
    // variable-length fields that follow.  They are intentionally not fixed by
    // ARP — ARP is a general address-resolution protocol, not Ethernet-specific.
    uint8_t  hw_len     = data[4];
    uint8_t  proto_len  = data[5];

    // We only support Ethernet+IPv4: hw_len must be 6 (MAC address) and
    // proto_len must be 4 (IPv4 address).  Any other combination (e.g. ATM,
    // IPv6) is returned as null rather than silently mis-parsed.
    if (hw_len != 6 || proto_len != 4) {
        return std::nullopt;
    }

    // Total packet size = 8-byte fixed header
    //                   + Sender Hardware Address (hw_len bytes)
    //                   + Sender Protocol Address (proto_len bytes)
    //                   + Target Hardware Address (hw_len bytes)
    //                   + Target Protocol Address (proto_len bytes)
    // For Ethernet+IPv4: 8 + 6 + 4 + 6 + 4 = 28 bytes.
    // We compute it dynamically from hw_len / proto_len so the check remains
    // correct if we ever extend support to other hardware types.
    std::size_t required = arp_fixed_header +
                           2 * (static_cast<std::size_t>(hw_len) +
                                static_cast<std::size_t>(proto_len));
    if (len < required) {
        return std::nullopt;
    }

    ArpPacket packet;
    packet.hardware_type  = hw_type;
    packet.protocol_type  = proto_type;
    packet.hw_addr_len    = hw_len;
    packet.proto_addr_len = proto_len;
    packet.operation      = read_u16_be(data + 6);

    // Walk through the variable-length address fields in order.
    // Using a moving pointer `p` makes the layout explicit and avoids
    // hardcoding the individual byte offsets (which would break if hw_len
    // or proto_len ever changed).
    const uint8_t* p = data + arp_fixed_header;
    packet.sender_mac = mac_to_string(p);      p += hw_len;    // sender MAC
    packet.sender_ip  = ipv4_to_string(p);     p += proto_len; // sender IP
    packet.target_mac = mac_to_string(p);      p += hw_len;    // target MAC (zeros in request)
    packet.target_ip  = ipv4_to_string(p);                     // target IP (the one being resolved)

    return packet;
}

std::string arp_operation_to_string(uint16_t operation) {
    // Operation codes are defined in RFC 826 and the IANA ARP Parameters registry.
    // 1 = ARP Request, 2 = ARP Reply.
    switch (operation) {
        case 1:  return "Request";
        case 2:  return "Reply";
        default: return "Unknown";
    }
}

} // namespace netprobe
