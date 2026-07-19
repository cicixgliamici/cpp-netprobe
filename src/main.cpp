#include <pcap.h>

#include <atomic>
#include <csignal>
#include <iostream>
#include <string>

#include "netprobe/arp.hpp"
#include "netprobe/ethernet.hpp"
#include "netprobe/icmp.hpp"
#include "netprobe/ipv4.hpp"
#include "netprobe/ipv6.hpp"
#include "netprobe/tcp.hpp"
#include "netprobe/udp.hpp"

using namespace netprobe;

// =============================================================================
// Signal handling
//
// In live capture mode the packet loop runs indefinitely.  To stop cleanly on
// Ctrl-C we install a SIGINT handler that sets a flag checked in the loop.
//
// Why std::atomic<bool>?
//   The signal handler is called asynchronously from a different context
//   (the OS interrupts the main thread mid-instruction).  Writing to a plain
//   `bool` from a signal handler and reading it from the main loop is a data
//   race (undefined behaviour in C++).  `std::atomic<bool>` with its default
//   sequential-consistency guarantees makes this access safe.
// =============================================================================
static std::atomic<bool> g_running{true};

static void signal_handler(int /*sig*/) {
    // Minimal work inside a signal handler — only safe to call async-signal-safe
    // functions here.  Storing to an atomic is safe.
    g_running = false;
}

// =============================================================================
// CLI configuration
//
// The tool supports two input modes:
//   -r <file.pcap>   Offline analysis: read packets from a pre-recorded file.
//   -i <interface>   Live capture: capture packets from a network interface in
//                    real time.  Requires root/CAP_NET_RAW on Linux.
//
// An optional BPF filter expression can be supplied with -f / --filter.
// The expression is compiled into kernel bytecode (via libpcap) and applied
// *before* packets are delivered to user space, so unmatched packets never
// cross the kernel–user boundary.  This is far more efficient than filtering
// in user space, especially at high packet rates.
// =============================================================================
struct Config {
    std::string source;       // filename (-r) or interface name (-i)
    bool        live{false};  // true = live capture, false = offline PCAP file
    std::string bpf_filter;   // optional BPF expression ("-f tcp port 443")
};

static void print_usage(const char* prog) {
    std::cerr
        << "Usage:\n"
        << "  " << prog << " -r <file.pcap> [-f <filter>]\n"
        << "  " << prog << " -i <interface>  [-f <filter>]\n"
        << "\nExamples:\n"
        << "  " << prog << " -r capture.pcap\n"
        << "  " << prog << " -r capture.pcap -f \"tcp port 443\"\n"
        << "  " << prog << " -i eth0 -f \"udp port 53\"\n";
}

/// Parse command-line arguments into @p cfg.
/// Returns true on success, false if any argument is unknown or mandatory
/// options are missing.
static bool parse_args(int argc, char* argv[], Config& cfg) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-r" && i + 1 < argc) {
            cfg.source = argv[++i];
            cfg.live   = false;
        } else if (arg == "-i" && i + 1 < argc) {
            cfg.source = argv[++i];
            cfg.live   = true;
        } else if ((arg == "-f" || arg == "--filter") && i + 1 < argc) {
            cfg.bpf_filter = argv[++i];
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            return false;
        }
    }
    // At minimum -r or -i must have been supplied.
    return !cfg.source.empty();
}

// =============================================================================
// L4 printer helpers
//
// Each printer receives a fully parsed struct and writes a human-readable
// summary to stdout.  Keeping them separate from analyze_packet() makes the
// code easier to extend (e.g. add JSON output later without touching the
// dispatch logic).
// =============================================================================

/// Print the set TCP flag names to stdout (e.g. "SYN, ACK").
static void print_tcp_flags(uint8_t flags) {
    auto names = tcp_flags_to_strings(flags);
    if (names.empty()) { std::cout << "None"; return; }
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << names[i];
    }
}

static void print_tcp(const TcpSegment& seg) {
    std::cout << "TCP\n"
              << "  Src Port: " << seg.src_port << "\n"
              << "  Dst Port: " << seg.dst_port << "\n"
              << "  Seq:      " << seg.sequence_number << "\n"
              << "  Ack:      " << seg.acknowledgment_number << "\n"
              << "  Flags:    "; print_tcp_flags(seg.flags); std::cout << "\n"
              << "  Window:   " << seg.window_size << "\n"
              << "  Payload:  " << seg.payload_len << " bytes\n";
}

static void print_udp(const UdpDatagram& dg) {
    std::cout << "UDP\n"
              << "  Src Port: " << dg.src_port << "\n"
              << "  Dst Port: " << dg.dst_port << "\n"
              << "  Length:   " << dg.length << " bytes\n"
              << "  Payload:  " << dg.payload_len << " bytes\n";
}

static void print_icmp(const IcmpPacket& pkt) {
    std::cout << "ICMP\n"
              << "  Type:    " << static_cast<int>(pkt.type)
              << " (" << icmp_type_to_string(pkt.type) << ")\n"
              << "  Code:    " << static_cast<int>(pkt.code) << "\n"
              << "  Payload: " << pkt.payload_len << " bytes\n";
}

static void print_icmpv6(const IcmpPacket& pkt) {
    // We reuse IcmpPacket for ICMPv6 because the 8-byte header layout is
    // identical.  The only difference is the type string interpretation.
    std::cout << "ICMPv6\n"
              << "  Type:    " << static_cast<int>(pkt.type)
              << " (" << icmpv6_type_to_string(pkt.type) << ")\n"
              << "  Code:    " << static_cast<int>(pkt.code) << "\n"
              << "  Payload: " << pkt.payload_len << " bytes\n";
}

// =============================================================================
// L4 dispatch
//
// Both IPv4 and IPv6 use the same IANA protocol numbers for their L4 fields
// (IPv4: "Protocol", IPv6: "Next Header"), so this single function handles
// both.  ICMPv4 (protocol 1) and ICMPv6 (protocol 58) are structurally the
// same but have different type strings; the protocol number disambiguates them.
// =============================================================================
static void dispatch_l4(uint8_t protocol,
                         const uint8_t* payload, std::size_t payload_len) {
    switch (protocol) {
        case 6: {   // TCP
            auto seg = parse_tcp(payload, payload_len);
            if (!seg) { std::cout << "  [Invalid TCP segment]\n"; return; }
            print_tcp(*seg);
            break;
        }
        case 17: {  // UDP
            auto dg = parse_udp(payload, payload_len);
            if (!dg) { std::cout << "  [Invalid UDP datagram]\n"; return; }
            print_udp(*dg);
            break;
        }
        case 1: {   // ICMPv4
            auto pkt = parse_icmp(payload, payload_len);
            if (!pkt) { std::cout << "  [Invalid ICMP packet]\n"; return; }
            print_icmp(*pkt);
            break;
        }
        case 58: {  // ICMPv6
            auto pkt = parse_icmp(payload, payload_len);
            if (!pkt) { std::cout << "  [Invalid ICMPv6 packet]\n"; return; }
            print_icmpv6(*pkt);
            break;
        }
        default:
            std::cout << "  [Unsupported L4 protocol: "
                      << static_cast<int>(protocol) << "]\n";
            break;
    }
}

// =============================================================================
// Per-packet dissector
//
// Called once for every captured packet.  It follows the OSI model top-down:
//   L2 → Ethernet → determine EtherType
//   L3 → IPv4 / IPv6 / ARP  (based on EtherType)
//   L4 → TCP / UDP / ICMP   (based on IPv4 Protocol or IPv6 Next Header)
//
// Each layer calls the next only if parsing succeeds.  std::optional makes the
// failure path explicit: a returned nullopt means the frame is malformed or
// truncated, and we simply skip the higher layers.
// =============================================================================
static void analyze_packet(const uint8_t* data, std::size_t len, int packet_number) {
    std::cout << "\n========== Packet #" << packet_number << " ==========\n";

    // --- L2: Ethernet ---
    auto eth = parse_ethernet(data, len);
    if (!eth) { std::cout << "[Invalid Ethernet frame]\n"; return; }

    // std::hex / std::dec are sticky I/O manipulators — we must reset to decimal
    // after printing the hex EtherType to avoid corrupting later numeric output.
    std::cout << "Ethernet\n"
              << "  Src MAC:   " << eth->src_mac << "\n"
              << "  Dst MAC:   " << eth->dst_mac << "\n"
              << "  EtherType: 0x" << std::hex << eth->ether_type << std::dec
              << " (" << ether_type_to_string(eth->ether_type) << ")\n";

    switch (eth->ether_type) {

        // --- L3: IPv4 (EtherType 0x0800) ---
        case 0x0800: {
            auto ip = parse_ipv4(eth->payload, eth->payload_len);
            if (!ip) { std::cout << "[Invalid IPv4 packet]\n"; return; }

            // Build the flags display string.  We avoid printing empty strings
            // by checking each bit individually and defaulting to "none".
            std::string flags_str;
            if (ip->flags & 0x02) flags_str += "DF ";   // Don't Fragment
            if (ip->flags & 0x01) flags_str += "MF ";   // More Fragments
            if (!flags_str.empty() && flags_str.back() == ' ') flags_str.pop_back();
            if (flags_str.empty()) flags_str = "none";

            std::cout << "IPv4\n"
                      << "  Src IP:        " << ip->src_ip << "\n"
                      << "  Dst IP:        " << ip->dst_ip << "\n"
                      << "  TTL:           " << static_cast<int>(ip->ttl) << "\n"
                      << "  Protocol:      " << static_cast<int>(ip->protocol)
                      << " (" << ip_protocol_to_string(ip->protocol) << ")\n"
                      << "  Total Length:  " << ip->total_length << " bytes\n"
                      << "  Checksum:      " << (ip->checksum_valid ? "OK" : "INVALID") << "\n"
                      << "  Flags:         " << flags_str << "\n"
                      // Fragment offset × 8 converts from 8-byte units to bytes.
                      << "  Frag Offset:   " << ip->fragment_offset
                      << " (" << (ip->fragment_offset * 8) << " bytes)\n";

            // If MF=1 or fragment_offset > 0, this is a non-initial fragment.
            // Its L4 header has already been sent in the first fragment (offset=0),
            // so there is nothing to parse here.
            if (ip->flags & 0x01 || ip->fragment_offset > 0) {
                std::cout << "  [Fragmented packet — L4 parsing skipped]\n";
                return;
            }

            dispatch_l4(ip->protocol, ip->payload, ip->payload_len);
            break;
        }

        // --- L3: IPv6 (EtherType 0x86DD) ---
        case 0x86DD: {
            auto ip6 = parse_ipv6(eth->payload, eth->payload_len);
            if (!ip6) { std::cout << "[Invalid IPv6 packet]\n"; return; }

            // Note: IPv6 has no Checksum field in its base header and no
            // fragmentation flags (fragmentation uses an optional extension header).
            std::cout << "IPv6\n"
                      << "  Src IP:         " << ip6->src_ip << "\n"
                      << "  Dst IP:         " << ip6->dst_ip << "\n"
                      << "  Hop Limit:      " << static_cast<int>(ip6->hop_limit) << "\n"
                      << "  Next Header:    " << static_cast<int>(ip6->next_header)
                      << " (" << ip_protocol_to_string(ip6->next_header) << ")\n"
                      << "  Payload Length: " << ip6->payload_length << " bytes\n";

            dispatch_l4(ip6->next_header, ip6->payload, ip6->payload_len);
            break;
        }

        // --- L3: ARP (EtherType 0x0806) ---
        case 0x0806: {
            auto arp = parse_arp(eth->payload, eth->payload_len);
            if (!arp) { std::cout << "[Invalid ARP packet]\n"; return; }

            std::cout << "ARP\n"
                      << "  Operation:   " << arp->operation
                      << " (" << arp_operation_to_string(arp->operation) << ")\n"
                      << "  Sender MAC:  " << arp->sender_mac << "\n"
                      << "  Sender IP:   " << arp->sender_ip << "\n"
                      << "  Target MAC:  " << arp->target_mac << "\n"
                      << "  Target IP:   " << arp->target_ip << "\n";
            break;
        }

        default:
            std::cout << "[EtherType 0x" << std::hex << eth->ether_type
                      << std::dec << " not supported]\n";
            break;
    }
}

// =============================================================================
// Entry point
// =============================================================================
int main(int argc, char* argv[]) {
    Config cfg;
    if (!parse_args(argc, argv, cfg)) {
        print_usage(argv[0]);
        return 1;
    }

    // Install SIGINT handler so Ctrl-C stops live capture gracefully.
    std::signal(SIGINT, signal_handler);

    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;

    if (cfg.live) {
        // pcap_open_live parameters:
        //   device   — interface name (e.g. "eth0")
        //   snaplen  — maximum bytes to capture per packet; 65535 captures the
        //              full MTU (1500) and any jumbo frames up to 64 KB
        //   promisc  — 1 = promiscuous mode: the NIC delivers all frames it
        //              sees on the wire, not just those addressed to this host
        //   to_ms    — read timeout in milliseconds; 1000 ms means pcap_next_ex
        //              returns 0 (timeout) roughly once per second if no packets
        //              arrive, allowing our g_running check to run periodically
        //   errbuf   — buffer for error messages from libpcap
        handle = pcap_open_live(cfg.source.c_str(), 65535, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "Could not open interface '" << cfg.source << "': " << errbuf << "\n";
            return 1;
        }

        // We only handle Ethernet frames (DLT_EN10MB).  Other link-layer types
        // (e.g. DLT_LINUX_SLL for cooked captures, DLT_RAW for raw IP) would
        // require a different L2 parser.
        if (pcap_datalink(handle) != DLT_EN10MB) {
            std::cerr << "Interface '" << cfg.source << "' is not an Ethernet interface\n";
            pcap_close(handle);
            return 1;
        }
        std::cout << "Capturing on interface: " << cfg.source << "  (Ctrl-C to stop)\n";

    } else {
        // pcap_open_offline reads from a saved .pcap file instead of a live
        // interface.  Everything else (BPF, pcap_next_ex loop) works identically.
        handle = pcap_open_offline(cfg.source.c_str(), errbuf);
        if (!handle) {
            std::cerr << "Could not open file '" << cfg.source << "': " << errbuf << "\n";
            return 1;
        }
        std::cout << "Reading from file: " << cfg.source << "\n";
    }

    // -------------------------------------------------------------------------
    // BPF filter installation
    //
    // A BPF (Berkeley Packet Filter) expression is compiled into a small
    // bytecode program that runs inside the kernel (or inside libpcap for
    // offline files).  Only packets matching the expression reach user space.
    //
    // pcap_compile:
    //   Compiles the human-readable expression (e.g. "tcp port 443") into a
    //   `bpf_program` struct containing the bytecode.
    //   - The third argument (1) enables optimisation of the bytecode.
    //   - PCAP_NETMASK_UNKNOWN tells libpcap we do not know the netmask (it
    //     is only needed for some "broadcast" filters).
    //
    // pcap_setfilter:
    //   Installs the compiled program into the pcap handle.  After this call,
    //   pcap_next_ex only returns packets that pass the filter.
    //
    // pcap_freecode:
    //   Releases the memory allocated by pcap_compile.  Must be called even
    //   if pcap_setfilter fails, to avoid a memory leak.
    // -------------------------------------------------------------------------
    if (!cfg.bpf_filter.empty()) {
        struct bpf_program fp{};
        if (pcap_compile(handle, &fp, cfg.bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Invalid BPF filter \"" << cfg.bpf_filter << "\": "
                      << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Could not set BPF filter: " << pcap_geterr(handle) << "\n";
            pcap_freecode(&fp);
            pcap_close(handle);
            return 1;
        }
        pcap_freecode(&fp);
        std::cout << "BPF filter: \"" << cfg.bpf_filter << "\"\n";
    }

    // -------------------------------------------------------------------------
    // Main packet loop
    //
    // pcap_next_ex return values:
    //   1   — a packet was successfully read; packet_data and packet_header
    //         are valid pointers into libpcap's internal buffer
    //   0   — timeout expired (live capture only); no packet available yet;
    //         loop immediately to check g_running and retry
    //  -1   — an error occurred; pcap_geterr() gives the reason
    //  -2   — no more packets in the file (offline mode only; normal EOF)
    //
    // We use `caplen` (captured length) rather than `len` (original length)
    // to avoid reading past the end of the captured data when a packet was
    // truncated by the snaplen setting.
    // -------------------------------------------------------------------------
    const uint8_t*      packet_data   = nullptr;
    struct pcap_pkthdr* packet_header = nullptr;
    int                 packet_number = 1;
    int                 status        = 0;

    while (g_running &&
           (status = pcap_next_ex(handle, &packet_header, &packet_data)) >= 0) {
        if (status == 0) continue;  // timeout: g_running will be checked on next iteration
        analyze_packet(packet_data, packet_header->caplen, packet_number++);
    }

    if (!g_running) {
        std::cout << "\nCapture stopped by user. "
                  << (packet_number - 1) << " packets processed.\n";
    } else if (status == -1) {
        // A read error occurred; print the libpcap error message and exit non-zero.
        std::cerr << "Error reading packets: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }
    // status == -2: normal end-of-file for offline mode; fall through to cleanup.

    pcap_close(handle);
    return 0;
}
