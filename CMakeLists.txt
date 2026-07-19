cmake_minimum_required(VERSION 3.16)

project(cpp_netprobe VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(include)
include_directories(${PCAP_INCLUDE_DIRS})

add_library(netprobe
    src/ethernet.cpp
    src/ipv4.cpp
    src/ipv6.cpp
    src/arp.cpp
    src/tcp.cpp
    src/udp.cpp
    src/icmp.cpp
)

target_include_directories(netprobe PUBLIC include)
target_link_libraries(netprobe PUBLIC ${PCAP_LIBRARIES})

add_executable(cpp-netprobe src/main.cpp)
target_link_libraries(cpp-netprobe PRIVATE netprobe ${PCAP_LIBRARIES})

add_executable(smoke_test tests/smoke_test.cpp)
target_link_libraries(smoke_test PRIVATE netprobe)
