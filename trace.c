#include <stdio.h>
#include <pcap/pcap.h>

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
        printf("Packet number: %lu Packet Len: %d\n", ++pkt_cntr, pkt_header.caplen);


        data_ptr = pcap_next(pcap_ptr, &pkt_header);
    }

    // close file
    pcap_close(pcap_ptr);

    return 0;
}

