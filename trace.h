#ifndef TRACE_H
#define TRACE_H

#include <stdint.h>
#include <inttypes.h>

// TODO: make packed
typedef struct ethernetHeader_t {
    uint16_t src_addr1;
    uint16_t src_addr2;
    uint16_t src_addr3;
    uint16_t dst_addr1;
    uint16_t dst_addr2;
    uint16_t dst_addr3;
    uint16_t type;
    uint8_t* data;
    uint32_t crc;
} ethernetHeader_t;

// ? where should this go?
#define MAC_STR_LEN 19   // "xx:xx:xx:xx:xx:xx" + null 
#define IP_STR_LEN 16   // "xxx.xxx.xxx.xxx" + null

#define ETH_IP_TYPE (0x0800)
#define ETH_ARP_TYPE (0x0806)
#define ETH_MAIN_HEADER_SIZE (sizeof(uint16_t) * 6 + sizeof(uint16_t))
#define ETH_DATA_OFFSET (sizeof(uint16_t) * 6 + sizeof(uint16_t))
#define ETH_CRC_SIZE (sizeof(uint32_t))
#define ETH_METADATA_SIZE (ETH_MAIN_HEADER_SIZE + ETH_CRC_SIZE)

typedef struct ipHeader_t {
    uint8_t version: 4;
    uint8_t header_len: 4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t ipflags: 3; // ? should I break out the bits
    uint16_t frag_offset: 13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} ipHeader_t;

#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17

typedef struct __attribute__((packed)) arpHeader_t {
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t hw_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint16_t src_mac_addr1;
    uint16_t src_mac_addr2;
    uint16_t src_mac_addr3;
    uint32_t src_ip_addr;
    uint16_t dst_mac_addr1;
    uint16_t dst_mac_addr2;
    uint16_t dst_mac_addr3;
    uint32_t dst_ip_addr;
} arpHeader_t;  


#endif // # TRACE_H
