#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <inttypes.h>
#include "smartalloc.h"

#include "trace.h"


void print_eth_header(ethernetHeader_t* eth_header);
void print_ip_header(ipHeader_t* ip_header);
void print_icmp_type(uint8_t ttl);


void construct_eth_frame(ethernetHeader_t* eth_header, const u_char* data_ptr, struct pcap_pkthdr pkt_header);
void clean_eth_frame(ethernetHeader_t* eth_header);
void construct_mac_addr(char* mac_addr_str_buf, uint16_t p1, uint16_t p2, uint16_t p3);
void construct_ip_addr(char* ip_addr_buf, uint32_t ip_addr);

void construct_ip_header(ipHeader_t* ip_header, const uint8_t* data);

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
                printf("\n\tIP Header\n");

                // IP header
                ipHeader_t ip_header;
                construct_ip_header(&ip_header, eth_header.data);
                print_ip_header(&ip_header);

                switch (ip_header.protocol) {
                    case ICMP_PROTOCOL:
                        printf("\n\tICMP Header\n");
                        print_icmp_type(ip_header.ttl);
                        break;
                    default:
                        printf("Unknown IP Protocol\n");
                }

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

void construct_ip_addr(char* ip_addr_buf, uint32_t ip_addr) {
    uint8_t first = (ip_addr >> 24) & 0xff;
    uint8_t sec = (ip_addr >> 16) & 0xff;
    uint8_t third = (ip_addr >> 8) & 0xff;
    uint8_t fourth = (ip_addr >> 0) & 0xff;
    snprintf(ip_addr_buf, IP_STR_LEN, "%u.%u.%u.%u", first, sec, third, fourth);

    return;
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
    // const size_t ETH_DATA_SIZE = pkt_header.caplen - ETH_MAIN_HEADER_SIZE - ETH_CRC_SIZE;
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

void construct_ip_header(ipHeader_t* ip_header, const uint8_t* data) {
    *ip_header = *((ipHeader_t*)data);
    
    ip_header->checksum = ntohs(ip_header->checksum);
    ip_header->src_addr = ntohl(ip_header->src_addr);
    ip_header->dst_addr = ntohl(ip_header->dst_addr);

    return;
}

void print_ip_header(ipHeader_t* ip_header) {
    const char* CORRECT_CHECKSUM_STR = "Correct";
    // const char* INVALID_CHECKSUM_STR = "BAD!!!";
    char ip_addr_buf[IP_STR_LEN];

    printf("\t\tTOS: 0x%x\n", ip_header->tos);
    printf("\t\tTTL: %u\n", ip_header->ttl);
    printf("\t\tProtocol: %d\n", ip_header->protocol); // TODO: make enum
    printf("\t\tChecksum: %s (0x%x)\n", CORRECT_CHECKSUM_STR, ip_header->checksum); // TODO: check validity
    construct_ip_addr(ip_addr_buf, ip_header->src_addr);
    printf("\t\tSender IP: %s\n", ip_addr_buf);
    construct_ip_addr(ip_addr_buf, ip_header->dst_addr);
    printf("\t\tDest IP: %s\n", ip_addr_buf);
}

void print_icmp_type(uint8_t ttl) {
    // TODO: finish this
    printf("\t\tType: %x,", ttl);

    switch (ttl) {
        case 0: // reply
            printf("Reply\n");
            break;
        case 8: // request
            printf("Request\n");
            break;
        default:
            printf("Unknown\n"); 
    }
}