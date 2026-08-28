#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>

#include "trace.h"

#define MAC_STR_LEN 19   // "xx:xx:xx:xx:xx:xx" + null


void print_eth_header(uint8_t* data_ptr);


void construct_mac_addr(char* mac_addr_str_buf, uint16_t p1, uint16_t p2, uint16_t p3);


int main(int argc, char* argv[]) {

    // take in 1 arg
    if (argc != 2) {
        printf("Usage: ./trace-Linux-x86_64 aTraceFile\n");
        
        return 1; // invalid arg count 
    }
    fprintf(stderr, "opening %s\n", argv[1]);
    
    char errbuf[PCAP_ERRBUF_SIZE];

    // init pcap
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "hello\n");
    }

    // open pcap file
    pcap_t* pcap_ptr = pcap_open_offline(argv[1], errbuf);

    size_t pkt_cntr = 0;
    struct pcap_pkthdr pkt_header;
    const u_char* data_ptr;

    data_ptr = pcap_next(pcap_ptr, &pkt_header);
    
    // read packet by packet
    while (data_ptr) {
        // print metadata
        printf("\nPacket number: %lu Packet Len: %d\n", ++pkt_cntr, pkt_header.caplen);

        print_eth_header((uint8_t*)data_ptr);

        data_ptr = pcap_next(pcap_ptr, &pkt_header);
    }
    
    // close file
    pcap_close(pcap_ptr);

    return 0;
}

void print_eth_header(uint8_t* data_ptr) {
    ethernetHeader_t eth_header;
    memcpy(&eth_header, data_ptr, sizeof(eth_header));

    char mac_addr[MAC_STR_LEN];

    printf("\n\tEthernet Header\n");
    construct_mac_addr(mac_addr, eth_header.src_addr1, eth_header.src_addr2, eth_header.src_addr3);
    printf("\t\tDest MAC: %s\n", mac_addr);
    printf("\t\tSource MAC: %s\n", mac_addr);
    
    switch (eth_header.type) {
        case 0x0800:
            printf("\t\tType: IPv4\n");
            break;
        case 0x0806:
            printf("\t\tType: ARP\n");
            break;
        case 0x86DD:
            printf("\t\tType: IPv6\n");
            break;
        default:
            printf("\t\tType: Unknown\n");
    }
}

void construct_mac_addr(char* mac_addr_str_buf, uint16_t p1, uint16_t p2, uint16_t p3) {
    uint8_t p1_upper = p1 & 0xFF;
    uint8_t p1_lower = p1 >> 8 & 0xFF;
    uint8_t p2_upper = p2 & 0xFF;
    uint8_t p2_lower = p2 >> 8 & 0xFF;
    uint8_t p3_upper = p3 & 0xFF;
    uint8_t p3_lower = p3 >> 8 & 0xFF;

    snprintf(mac_addr_str_buf, MAC_STR_LEN, "%x:%x:%x:%x:%x:%x", p1_upper, p1_lower, p2_upper, p2_lower, p3_upper, p3_lower);
    
    return;
}



