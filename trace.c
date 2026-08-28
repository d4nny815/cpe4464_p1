#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <inttypes.h>
#include "smartalloc.h"

#include "trace.h"


void print_eth_header(ethernetHeader_t* eth_header);


void construct_eth_frame(ethernetHeader_t* eth_header, const u_char* data_ptr, struct pcap_pkthdr pkt_header);
void clean_eth_frame(ethernetHeader_t* eth_header);
void construct_mac_addr(char* mac_addr_str_buf, uint16_t p1, uint16_t p2, uint16_t p3);


int main(int argc, char* argv[]) {
    // take in 1 arg
    if (argc != 2) {
        printf("Usage: ./trace-Linux-x86_64 aTraceFile\n");
        
        return 1; // invalid arg count 
    }
    // fprintf(stderr, "opening %s\n", argv[1]);
    
    char errbuf[PCAP_ERRBUF_SIZE];

    // init pcap
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Error initializing pcap\n");
        return 1;
    }

    // open pcap file
    pcap_t* pcap_ptr = pcap_open_offline(argv[1], errbuf);

    size_t pkt_cntr = 0;
    struct pcap_pkthdr pkt_header;
    const u_char* data_ptr;

    // read packet by packet
    data_ptr = pcap_next(pcap_ptr, &pkt_header);
    while (data_ptr) {
        // print metadata
        printf("\nPacket number: %lu Packet Len: %d\n", ++pkt_cntr, pkt_header.caplen);

        // ethernet frame portion
        ethernetHeader_t eth_header;
        construct_eth_frame(&eth_header, data_ptr, pkt_header);
        print_eth_header(&eth_header);

        // packet type portion
        switch (eth_header.type) {
            case ETH_IP_TYPE:
                printf("\n\tIPv4 Packet\n");
                // print IP header
                break;
            case ETH_ARP_TYPE:
                printf("\tARP Packet\n");
                break;
            default:
                printf("\tUnknown Packet Type\n");
        }
        
        clean_eth_frame(&eth_header);

        data_ptr = pcap_next(pcap_ptr, &pkt_header);
    }
    
    // close file
    pcap_close(pcap_ptr);

    return 0;
}

void construct_mac_addr(char* mac_addr_str_buf, uint16_t p1, uint16_t p2, uint16_t p3) {
    uint8_t p1_upper = p1 >> 8 & 0xFF;
    uint8_t p1_lower = p1 & 0xFF;
    uint8_t p2_upper = p2 >> 8 & 0xFF;
    uint8_t p2_lower = p2 & 0xFF;
    uint8_t p3_upper = p3 >> 8 & 0xFF;
    uint8_t p3_lower = p3 & 0xFF;

    snprintf(mac_addr_str_buf, MAC_STR_LEN, "%x:%x:%x:%x:%x:%x", p1_upper, p1_lower, p2_upper, p2_lower, p3_upper, p3_lower);
    
    return;
}

void construct_eth_frame(ethernetHeader_t* eth_header, const u_char* data_ptr, struct pcap_pkthdr pkt_header) {
    // make an eth frame from the data_ptr
    eth_header->data = (uint8_t*)malloc(pkt_header.caplen - ETH_MAIN_HEADER_SIZE - ETH_CRC_SIZE);
    memcpy(eth_header, data_ptr, ETH_MAIN_HEADER_SIZE); // copy metadata into struct
    memcpy(eth_header->data, (void*)(data_ptr + ETH_DATA_OFFSET), pkt_header.caplen - ETH_METADATA_SIZE); // copy data into struct
    memcpy(&eth_header->crc, (void*)(data_ptr + pkt_header.caplen - ETH_CRC_SIZE), ETH_CRC_SIZE); // copy crc into struct

    // convert from network byte order to host byte order
    eth_header->src_addr1 = ntohs(eth_header->src_addr1);
    eth_header->src_addr2 = ntohs(eth_header->src_addr2);
    eth_header->src_addr3 = ntohs(eth_header->src_addr3);
    eth_header->dst_addr1 = ntohs(eth_header->dst_addr1);
    eth_header->dst_addr2 = ntohs(eth_header->dst_addr2);
    eth_header->dst_addr3 = ntohs(eth_header->dst_addr3);
    eth_header->type = ntohs(eth_header->type);

    // ? do I have to convert data byte order?

    eth_header->crc = ntohl(eth_header->crc); // TODO: copy crc into struct
 
    return;
}

void clean_eth_frame(ethernetHeader_t* eth_header) {
    free((void*)eth_header->data);
    return;
}

void print_eth_header(ethernetHeader_t* eth_header) {
    char mac_addr[MAC_STR_LEN];

    printf("\n\tEthernet Header\n");
    construct_mac_addr(mac_addr, eth_header->src_addr1, eth_header->src_addr2, eth_header->src_addr3);
    printf("\t\tDest MAC: %s\n", mac_addr);
    construct_mac_addr(mac_addr, eth_header->dst_addr1, eth_header->dst_addr2, eth_header->dst_addr3);
    printf("\t\tSource MAC: %s\n", mac_addr);
    
    switch (eth_header->type) {
        case ETH_IP_TYPE:
            printf("\t\tType: IP\n");
            break;
        case ETH_ARP_TYPE:
            printf("\t\tType: ARP\n");
            break;
        default:
            printf("\t\tType: Unknown\n");
    }
}

