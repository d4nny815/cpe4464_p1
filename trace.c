#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <inttypes.h>

#include "trace.h"
#include "smartalloc.h"
#include "checksum.h"

#define TRACE_ARG_COUNT (2)


void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n");
        }
        printf("%02x ", data[i]);
    }
    printf("\n");
}


void handle_ip_packet(ethernetHeader_t* eth_header);
void handle_arp_packet(ethernetHeader_t* eth_header);

void construct_eth_frame(ethernetHeader_t* eth_header, const u_char* data_ptr, struct pcap_pkthdr pkt_header);
void construct_ip_header(ipHeader_t* ip_header, const uint8_t* data);
void construct_arp_header(arpHeader_t* arp_header, const uint8_t* data);

void print_eth_header(ethernetHeader_t* eth_header);
void print_ip_header(ipHeader_t* ip_header, unsigned short checksum);
void print_icmp_type(uint8_t ttl);
void print_arp_header(arpHeader_t* arp_header);
void print_udp_header(udpHeader_t* udp_header);

void make_mac_addr_str(char* mac_addr_str_buf, uint16_t p1, uint16_t p2, uint16_t p3);
void make_ip_addr_str(char* ip_addr_buf, uint32_t ip_addr);

char ip_addr_str_buf[IP_STR_LEN];
char mac_addr_str_buf[MAC_STR_LEN];

int main(int argc, char* argv[]) {
    if (argc != TRACE_ARG_COUNT) {
        printf("Usage: ./trace-Linux-x86_64 aTraceFile\n");
        
        return 1; // invalid arg count 
    }
    char errbuf[PCAP_ERRBUF_SIZE];

    // init pcap
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Error initializing pcap\n");
        return 1;
    }
    pcap_t* pcap_ptr = pcap_open_offline(argv[1], errbuf); // open pcap file

    size_t pkt_cntr = 0;
    struct pcap_pkthdr pkt_header;
    const u_char* data_ptr;

    // read packet by packet
    data_ptr = pcap_next(pcap_ptr, &pkt_header);
    while (data_ptr) {
        // print metadata
        printf("\nPacket number: %lu  Packet Len: %d\n", ++pkt_cntr, pkt_header.caplen);
        
        // ethernet frame portion
        ethernetHeader_t eth_header;
        construct_eth_frame(&eth_header, data_ptr, pkt_header);
        print_eth_header(&eth_header);

        // packet type portion
        switch (eth_header.type) {
            case ETH_IP_TYPE:
                handle_ip_packet(&eth_header);
                break;
            case ETH_ARP_TYPE:
                handle_arp_packet(&eth_header);
                break;
            default:
                printf("\tUnknown Packet Type\n");
        }
        
        data_ptr = pcap_next(pcap_ptr, &pkt_header);
    }
    
    // close file
    pcap_close(pcap_ptr);

    return 0;
}

void handle_ip_packet(ethernetHeader_t* eth_header) {
    ipHeader_t ip_header;
    construct_ip_header(&ip_header, eth_header->data);
    unsigned short checksum = in_cksum((unsigned short*)&ip_header, ip_header.header_len * 4);


    printf("\n\tIP Header\n");
    print_ip_header(&ip_header, checksum);

    switch (ip_header.protocol) {
        case ICMP_PROTOCOL:
            printf("\n\tICMP Header\n");
            print_icmp_type(ip_header.ttl);
            break;
        // case TCP_PROTOCOL:
        case UDP_PROTOCOL:
            printf("\n\tUDP Header\n");
            udpHeader_t udp_header;
            size_t udp_header_offset = ip_header.header_len * 4;
            udp_header = *((udpHeader_t*)(eth_header->data + udp_header_offset));
            print_udp_header(&udp_header);
            break;    
        default:
            printf("Unknown IP Protocol\n");
    }
}

void handle_arp_packet(ethernetHeader_t* eth_header) {
    arpHeader_t arp_header;
    construct_arp_header(&arp_header, eth_header->data);

    printf("\n\tARP Header\n");
    print_arp_header(&arp_header);
}

void construct_eth_frame(ethernetHeader_t* eth_header, const u_char* data_ptr, struct pcap_pkthdr pkt_header) {
    // fprintf(stderr, "\tData Size: %u - %lu = %lu\n", pkt_header.caplen, ETH_METADATA_SIZE, pkt_header.caplen - ETH_METADATA_SIZE);
    
    // make an eth frame from the data_ptr
    memcpy(eth_header, data_ptr, ETH_MAIN_HEADER_SIZE); // copy metadata into struct
    eth_header->data = ((uint8_t*)data_ptr) + ETH_DATA_OFFSET; // point to data portion of frame
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

    eth_header->crc = ntohl(eth_header->crc);
 
    return;
}

void construct_ip_header(ipHeader_t* ip_header, const uint8_t* data) {
    *ip_header = *((ipHeader_t*)data);
    
    ip_header->checksum = ntohs(ip_header->checksum);
    ip_header->src_addr = ntohl(ip_header->src_addr);
    ip_header->dst_addr = ntohl(ip_header->dst_addr);

    return;
}

void construct_arp_header(arpHeader_t* arp_header, const uint8_t* data) {
    *arp_header = *((arpHeader_t*)data);

    arp_header->opcode = ntohs(arp_header->opcode);
    arp_header->src_mac_addr1 = ntohs(arp_header->src_mac_addr1);
    arp_header->src_mac_addr2 = ntohs(arp_header->src_mac_addr2);
    arp_header->src_mac_addr3 = ntohs(arp_header->src_mac_addr3);
    arp_header->src_ip_addr = ntohl(arp_header->src_ip_addr);
    arp_header->dst_mac_addr1 = ntohs(arp_header->dst_mac_addr1);
    arp_header->dst_mac_addr2 = ntohs(arp_header->dst_mac_addr2);
    arp_header->dst_mac_addr3 = ntohs(arp_header->dst_mac_addr3);
    arp_header->dst_ip_addr = ntohl(arp_header->dst_ip_addr);   

    return;
}


void print_eth_header(ethernetHeader_t* eth_header) {
    printf("\n\tEthernet Header\n");
    make_mac_addr_str(mac_addr_str_buf, eth_header->src_addr1, eth_header->src_addr2, eth_header->src_addr3);
    printf("\t\tDest MAC: %s\n", mac_addr_str_buf);
    make_mac_addr_str(mac_addr_str_buf, eth_header->dst_addr1, eth_header->dst_addr2, eth_header->dst_addr3);
    printf("\t\tSource MAC: %s\n", mac_addr_str_buf);
    
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

void print_arp_header(arpHeader_t* arp_header) {
    printf("\t\tOpcode: ");

    switch (arp_header->opcode) {
        case 1:
            printf("Request\n");
            break;
        case 2:
            printf("Reply\n");
            break;
        default:
            printf("Unknown\n");
    }

    make_mac_addr_str(mac_addr_str_buf, arp_header->src_mac_addr1, arp_header->src_mac_addr2, arp_header->src_mac_addr3);
    printf("\t\tSender MAC: %s\n", mac_addr_str_buf);
    make_ip_addr_str(ip_addr_str_buf, arp_header->src_ip_addr);
    printf("\t\tSender IP: %s\n", ip_addr_str_buf);
    make_mac_addr_str(mac_addr_str_buf, arp_header->dst_mac_addr1, arp_header->dst_mac_addr2, arp_header->dst_mac_addr3);
    printf("\t\tTarget MAC: %s\n", mac_addr_str_buf);
    make_ip_addr_str(ip_addr_str_buf, arp_header->dst_ip_addr);
    printf("\t\tTarget IP: %s\n", ip_addr_str_buf);
}

void print_ip_header(ipHeader_t* ip_header, unsigned short checksum) {
    const char* CORRECT_CHECKSUM_STR = "Correct";
    const char* INCORRECT_CHECKSUM_STR = "Incorrect";
    const char* checksum_str = (checksum == ip_header->checksum) ? CORRECT_CHECKSUM_STR : INCORRECT_CHECKSUM_STR;

    printf("\t\tTOS: 0x%x\n", ip_header->tos);
    printf("\t\tTTL: %u\n", ip_header->ttl);

    printf("\t\tProtocol: ");
    switch (ip_header->protocol) {
        case ICMP_PROTOCOL:
            printf("ICMP\n");
            break;
        case TCP_PROTOCOL:
            printf("TCP\n");
            break;
        case UDP_PROTOCOL:
            printf("UDP\n");
            break;
        default:
            printf("Unknown\n");
        }
    
    
    printf("\t\tChecksum: %s (0x%x)\n", checksum_str, ip_header->checksum); // TODO: check validity
    make_ip_addr_str(ip_addr_str_buf, ip_header->src_addr);
    printf("\t\tSender IP: %s\n", ip_addr_str_buf);
    make_ip_addr_str(ip_addr_str_buf, ip_header->dst_addr);
    printf("\t\tDest IP: %s\n", ip_addr_str_buf);
}

void print_icmp_type(uint8_t ttl) {
    // TODO: finish this
    printf("\t\tType: ");

    // reply, request, unknown
    // switch (ttl) {
    //     case 0:
    //         printf("Reply\n");
    //         break;
    //     case 8:
    //         printf("Request\n");
    //         break;
    //     default:
    //         printf("Unknown\n");
    // }
    // ? why are these the values
    switch (ttl) {
        case 128:
            printf("Request\n");
        break;
        case 52:
        case 242:
            printf("Reply\n");
            break;
        default:
            printf("Unknown\n");
    }
}

void print_udp_header(udpHeader_t* udp_header) {
    udp_header->src_port = ntohs(udp_header->src_port);
    udp_header->dst_port = ntohs(udp_header->dst_port);

    printf("\t\tSource Port:  %u\n", udp_header->src_port);
    printf("\t\tDest Port:  %u\n", udp_header->dst_port);
}

void make_ip_addr_str(char* ip_addr_buf, uint32_t ip_addr) {
    uint8_t first = (ip_addr >> 24) & 0xff;
    uint8_t sec = (ip_addr >> 16) & 0xff;
    uint8_t third = (ip_addr >> 8) & 0xff;
    uint8_t fourth = (ip_addr >> 0) & 0xff;
    
    snprintf(ip_addr_buf, IP_STR_LEN, "%u.%u.%u.%u", first, sec, third, fourth);

    return;
}

void make_mac_addr_str(char* mac_addr_str_buf, uint16_t p1, uint16_t p2, uint16_t p3) {
    uint8_t p1_upper = p1 >> 8 & 0xFF;
    uint8_t p1_lower = p1 & 0xFF;
    uint8_t p2_upper = p2 >> 8 & 0xFF;
    uint8_t p2_lower = p2 & 0xFF;
    uint8_t p3_upper = p3 >> 8 & 0xFF;
    uint8_t p3_lower = p3 & 0xFF;

    snprintf(mac_addr_str_buf, MAC_STR_LEN, "%x:%x:%x:%x:%x:%x", p1_upper, p1_lower, p2_upper, p2_lower, p3_upper, p3_lower);
    
    return;
}

