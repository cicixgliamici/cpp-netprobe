#include <cassert>
#include <cstdint>
#include <iostream>

#include "netprobe/ethernet.hpp"
#include "netprobe/ipv4.hpp"

using namespace netprobe;

int main() {
    uint8_t ethernet_ipv4_frame[] = {
        // Ethernet header
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // dst mac
        0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc, // src mac
        0x08, 0x00,                         // ethertype IPv4

        // IPv4 header, minimal 20 bytes
        0x45, 0x00,                         // version/IHL, DSCP/ECN
        0x00, 0x14,                         // total length = 20
        0x00, 0x00,                         // identification
        0x00, 0x00,                         // flags/fragment offset
        0x40,                               // TTL = 64
        0x06,                               // protocol = TCP
        0x00, 0x00,                         // checksum placeholder
        192, 168, 1, 10,                    // src ip
        8, 8, 8, 8                          // dst ip
    };

    auto eth = parse_ethernet(ethernet_ipv4_frame, sizeof(ethernet_ipv4_frame));

    assert(eth.has_value());
    assert(eth->src_mac == "08:00:27:aa:bb:cc");
    assert(eth->dst_mac == "52:54:00:12:34:56");
    assert(eth->ether_type == 0x0800);

    auto ip = parse_ipv4(eth->payload, eth->payload_len);

    assert(ip.has_value());
    assert(ip->version == 4);
    assert(ip->ihl == 5);
    assert(ip->ttl == 64);
    assert(ip->protocol == 6);
    assert(ip->src_ip == "192.168.1.10");
    assert(ip->dst_ip == "8.8.8.8");

    std::cout << "Smoke test passed.\n";
    return 0;
}
