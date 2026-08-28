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

#define ETH_IP_TYPE (0x0800)
#define ETH_ARP_TYPE (0x0806)
#define ETH_MAIN_HEADER_SIZE (sizeof(uint16_t) * 6 + sizeof(uint16_t))
#define ETH_DATA_OFFSET (sizeof(uint16_t) * 6 + sizeof(uint16_t))
#define ETH_CRC_SIZE (sizeof(uint32_t))
#define ETH_METADATA_SIZE (ETH_MAIN_HEADER_SIZE + ETH_CRC_SIZE)

#endif // # TRACE_H
