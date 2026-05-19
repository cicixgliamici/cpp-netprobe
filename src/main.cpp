#include <pcap.h>

#include <iostream>
#include <string>
#include <vector>

#include "netprobe/ethernet.hpp"
#include "netprobe/ipv4.hpp"
#include "netprobe/tcp.hpp"
#include "netprobe/udp.hpp"
#include "netprobe/icmp.hpp"

using namespace netprobe;

static void print_tcp_flags(uint8_t flags) {
    auto names = tcp_flags_to_strings(flags);

    if (names.empty()) {
        std::cout << "None";
        return;
    }

    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i > 0) {
            std::cout << ", ";
        }

        std::cout << names[i];
    }
}

static void analyze_packet(const uint8_t* data, std::size_t len, int packet_number) {
    std::cout << "\n========== Packet #" << packet_number << " ==========\n";

    auto eth = parse_ethernet(data, len);

    if (!eth) {
        std::cout << "Invalid Ethernet frame\n";
        return;
    }

    std::cout << "Ethernet\n";
    std::cout << "  Src MAC: " << eth->src_mac << "\n";
    std::cout << "  Dst MAC: " << eth->dst_mac << "\n";
    std::cout << "  EtherType: 0x" << std::hex << eth->ether_type << std::dec
              << " (" << ether_type_to_string(eth->ether_type) << ")\n";

    if (eth->ether_type != 0x0800) {
        std::cout << "  Non-IPv4 packet. Skipping higher-level parsing.\n";
        return;
    }

    auto ip = parse_ipv4(eth->payload, eth->payload_len);

    if (!ip) {
        std::cout << "Invalid IPv4 packet\n";
        return;
    }

    std::cout << "IPv4\n";
    std::cout << "  Src IP: " << ip->src_ip << "\n";
    std::cout << "  Dst IP: " << ip->dst_ip << "\n";
    std::cout << "  TTL: " << static_cast<int>(ip->ttl) << "\n";
    std::cout << "  Protocol: " << static_cast<int>(ip->protocol)
              << " (" << ip_protocol_to_string(ip->protocol) << ")\n";
    std::cout << "  Total Length: " << ip->total_length << " bytes\n";

    switch (ip->protocol) {
        case 6: {
            auto tcp = parse_tcp(ip->payload, ip->payload_len);

            if (!tcp) {
                std::cout << "Invalid TCP segment\n";
                return;
            }

            std::cout << "TCP\n";
            std::cout << "  Src Port: " << tcp->src_port << "\n";
            std::cout << "  Dst Port: " << tcp->dst_port << "\n";
            std::cout << "  Seq: " << tcp->sequence_number << "\n";
            std::cout << "  Ack: " << tcp->acknowledgment_number << "\n";
            std::cout << "  Flags: ";
            print_tcp_flags(tcp->flags);
            std::cout << "\n";
            std::cout << "  Window: " << tcp->window_size << "\n";
            std::cout << "  Payload: " << tcp->payload_len << " bytes\n";
            break;
        }

        case 17: {
            auto udp = parse_udp(ip->payload, ip->payload_len);

            if (!udp) {
                std::cout << "Invalid UDP datagram\n";
                return;
            }

            std::cout << "UDP\n";
            std::cout << "  Src Port: " << udp->src_port << "\n";
            std::cout << "  Dst Port: " << udp->dst_port << "\n";
            std::cout << "  Length: " << udp->length << " bytes\n";
            std::cout << "  Payload: " << udp->payload_len << " bytes\n";
            break;
        }

        case 1: {
            auto icmp = parse_icmp(ip->payload, ip->payload_len);

            if (!icmp) {
                std::cout << "Invalid ICMP packet\n";
                return;
            }

            std::cout << "ICMP\n";
            std::cout << "  Type: " << static_cast<int>(icmp->type)
                      << " (" << icmp_type_to_string(icmp->type) << ")\n";
            std::cout << "  Code: " << static_cast<int>(icmp->code) << "\n";
            std::cout << "  Payload: " << icmp->payload_len << " bytes\n";
            break;
        }

        default:
            std::cout << "Unsupported IPv4 protocol in MVP 0\n";
            break;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage:\n";
        std::cerr << "  cpp-netprobe <file.pcap>\n";
        return 1;
    }

    const char* filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_offline(filename, errbuf);

    if (handle == nullptr) {
        std::cerr << "Could not open PCAP file: " << errbuf << "\n";
        return 1;
    }

    const uint8_t* packet_data = nullptr;
    struct pcap_pkthdr* packet_header = nullptr;

    int packet_number = 1;
    int status = 0;

    while ((status = pcap_next_ex(handle, &packet_header, &packet_data)) >= 0) {
        if (status == 0) {
            continue;
        }

        analyze_packet(packet_data, packet_header->caplen, packet_number);
        packet_number++;
    }

    if (status == -1) {
        std::cerr << "Error while reading PCAP: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    return 0;
}
