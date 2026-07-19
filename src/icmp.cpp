#include "netprobe/icmp.hpp"
#include "netprobe/utils.hpp"

namespace netprobe {

std::optional<IcmpPacket> parse_icmp(const uint8_t* data, std::size_t len) {
    // The ICMP (and ICMPv6) base header is 8 bytes:
    //   byte 0: Type
    //   byte 1: Code
    //   bytes 2-3: Checksum
    //   bytes 4-7: "Rest of Header" — meaning depends on Type/Code
    //              (e.g. for Echo: bytes 4-5 = Identifier, 6-7 = Sequence Number)
    //
    // Everything after byte 7 is the Data section (e.g. the ping payload).
    //
    // Note: the original implementation incorrectly used 4 bytes for the header
    // length, which caused the payload pointer to land in the middle of the
    // "Rest of Header" field.  Corrected to 8 bytes per RFC 792.
    constexpr std::size_t icmp_header_len = 8;

    if (len < icmp_header_len) {
        return std::nullopt;
    }

    IcmpPacket packet;
    packet.type     = data[0];               // message type (ICMPv4 or ICMPv6)
    packet.code     = data[1];               // sub-type code
    packet.checksum = read_u16_be(data + 2); // raw checksum (not verified here)
    // payload starts after the full 8-byte header (skipping the "Rest of Header")
    packet.payload     = data + icmp_header_len;
    packet.payload_len = len - icmp_header_len;

    return packet;
}

// ICMPv4 type codes (RFC 792).
// A complete list is maintained by IANA:
// https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
std::string icmp_type_to_string(uint8_t type) {
    switch (type) {
        case 0:  return "Echo Reply";
        case 3:  return "Destination Unreachable";
        case 8:  return "Echo Request";
        case 11: return "Time Exceeded";
        default: return "Unknown";
    }
}

// ICMPv6 type codes (RFC 4443 + RFC 4861 NDP + RFC 3810 MLD).
//
// The type space is divided by convention into two ranges:
//   0-127:   Error messages — generated when a packet cannot be delivered or
//            processed.  They always contain (part of) the offending packet.
//   128-255: Informational messages — generated as part of normal operation
//            (e.g. ping, neighbor discovery, router discovery).
//
// A complete list is maintained by IANA:
// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
std::string icmpv6_type_to_string(uint8_t type) {
    switch (type) {
        // --- Error messages (RFC 4443 §3) ---
        case 1:   return "Destination Unreachable";
        case 2:   return "Packet Too Big";       // analogous to ICMPv4 type 3 code 4
        case 3:   return "Time Exceeded";
        case 4:   return "Parameter Problem";    // malformed header in the packet

        // --- Informational: Echo (RFC 4443 §4) ---
        case 128: return "Echo Request";
        case 129: return "Echo Reply";

        // --- Informational: Multicast Listener Discovery (RFC 3810) ---
        case 130: return "Multicast Listener Query";
        case 131: return "Multicast Listener Report";
        case 132: return "Multicast Listener Done";

        // --- Informational: Neighbor Discovery Protocol (RFC 4861) ---
        // NDP replaces ARP in IPv6.  Nodes use these messages to discover
        // neighbors' link-layer addresses (Solicitation/Advertisement) and
        // to find routers (Solicitation/Advertisement).
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";  // equivalent to ARP Request
        case 136: return "Neighbor Advertisement"; // equivalent to ARP Reply
        case 137: return "Redirect";

        default:  return "Unknown";
    }
}

} // namespace netprobe
