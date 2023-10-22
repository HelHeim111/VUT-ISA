#include <stdio.h>
#include <pcap.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <getopt.h>

// Structure to hold information about the IP prefix
struct PrefixInfo {
    char* prefix;
    int maxHosts;
    int allocated;
};

int isIpInPrefix(char* prefix, char* ip, char* mask) {
    struct in_addr ipAddr, prefixAddr, maskAddr;
    if(inet_aton(ip, &ipAddr) == 0 || inet_aton(mask, &maskAddr) == 0 || inet_aton(prefix, &prefixAddr) == 0) {
        return -1;
    }
    if((ipAddr.s_addr & maskAddr.s_addr) == prefixAddr.s_addr) {
        return 1;
    }
    return 0;
}

void handlePacket(const unsigned char* packet, struct PrefixInfo* prefixes, const struct udphdr* udp) {
    //todo
}

int main(int argc, char* argv[]) {
    int opt;
    char* interface = NULL;
    char* filename = NULL;
    struct PrefixInfo *prefixes = NULL;
    int prefixCount = 0;
    int prefixesMax = argc - 1;
    char errbuf[PCAP_ERRBUF_SIZE];


    // Handling arguments
    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
            case 'r':
                filename = strdup(optarg);
                prefixesMax -= 2;
                break;
            case 'i':
                interface = strdup(optarg);
                prefixesMax -= 2;
                break;
            default:
                fprintf(stderr, "Usage: ./dhcp-stats [-r <filename>] [-i <interface>] <ip-prefix> [<ip-prefix> ...]\n");
                exit(EXIT_FAILURE);
        }
    }

    // Process the IP prefixes
    prefixes = (struct PrefixInfo *)malloc(prefixesMax * sizeof(struct PrefixInfo));

    for (int i = optind; i < argc; i++) {
        prefixes[prefixCount].prefix = strdup(argv[i]);
        prefixes[prefixCount].maxHosts = 0;
        prefixes[prefixCount].allocated = 0;
        prefixCount++;
    }

    printf("Interface: %s\n", interface);
    printf("Filename: %s\n", filename);
    printf("IP Prefixes:\n");
    for (int i = 0; i < prefixCount; i++) {
        printf("%s\n", prefixes[i].prefix);
    }

    //opening network interface
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    //setting filter for intercepting dhcp packets
    char* filter = "udp port 67 or udp port 68";
    struct bpf_program bfp;

    if (pcap_compile(handle, &bfp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &bfp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    while (1) {
        struct pcap_pkthdr header;
        const unsigned char* packet = pcap_next(handle, &header);

        if (packet == NULL) {
            continue;
        }
        //add handling here
    }


    //free alocated memory
    free(interface);
    free(filename);
    for (int i = 0; i < prefixCount; i++) {
        free(prefixes[i].prefix);
    }
    free(prefixes);

    return 0;
}
