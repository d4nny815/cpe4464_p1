#ifndef TRACE_H
#define TRACE_H

#include <stdint.h>

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


#endif // # TRACE_H
