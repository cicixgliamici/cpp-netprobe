#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

// =============================================================================
// arp.hpp — Address Resolution Protocol packet parser
//
// ARP is defined in RFC 826.  Its purpose is to resolve an IP address (L3)
// to a hardware (MAC) address (L2) on a local network segment.  ARP operates
// directly on top of Ethernet and is identified by EtherType 0x0806.
//
// ARP packet layout (for the common Ethernet+IPv4 case, 28 bytes total):
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |         Hardware Type         |         Protocol Type         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  HW Addr Len  | Proto Addr Len|          Operation            |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                 Sender Hardware Address (6 bytes)             |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |       Sender Protocol Address (4 bytes)       | Target HW...  |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  | ...Hardware Address (cont.) (6 bytes total)                   |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                Target Protocol Address (4 bytes)              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// How ARP works (simplified):
//   Request: Host A broadcasts "Who has IP x.x.x.x? Tell A".
//            Target MAC is all-zeros (unknown), Dst Ethernet is FF:FF:FF:FF:FF:FF.
//   Reply:   Host B replies unicast "IP x.x.x.x is at MAC yy:yy:yy:yy:yy:yy".
//
// ARP is general-purpose: hardware type and address lengths are variable, so
// in principle it can map any L2 address to any L3 address.  In practice,
// Ethernet+IPv4 (hw_len=6, proto_len=4) is the overwhelming majority of traffic.
// =============================================================================

namespace netprobe {

/// Represents a parsed ARP packet for the Ethernet+IPv4 combination.
///
/// This parser only handles hardware_type=1 (Ethernet) and protocol_type=0x0800
/// (IPv4).  Other combinations return std::nullopt.
struct ArpPacket {
    uint16_t hardware_type;   ///< 1 = Ethernet
    uint16_t protocol_type;   ///< 0x0800 = IPv4
    uint8_t  hw_addr_len;     ///< Hardware address length in bytes (6 for Ethernet)
    uint8_t  proto_addr_len;  ///< Protocol address length in bytes (4 for IPv4)
    uint16_t operation;       ///< 1 = Request, 2 = Reply
    std::string sender_mac;   ///< MAC address of the host sending this ARP message
    std::string sender_ip;    ///< IP address of the host sending this ARP message
    std::string target_mac;   ///< MAC address being sought (all-zeros in a Request)
    std::string target_ip;    ///< IP address being looked up (in a Request)
};

/// Parse a raw ARP packet from @p data of length @p len.
///
/// Returns std::nullopt if:
///   - the buffer is too short for the fixed 8-byte ARP header, or
///   - hw_addr_len != 6 or proto_addr_len != 4 (non-Ethernet/IPv4 combination),
///   - the buffer is too short to hold the variable-length address fields.
std::optional<ArpPacket> parse_arp(const uint8_t* data, std::size_t len);

/// Return "Request", "Reply", or "Unknown" for the ARP operation field.
std::string arp_operation_to_string(uint16_t operation);

} // namespace netprobe
