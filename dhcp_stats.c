#include <stdio.h>
#include <pcap.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <getopt.h>

int prefixCount = 0;

//structure to hold information about the IP prefix
struct PrefixInfo {
    char* prefix;
    int maxHosts;
    int allocated;
};

int isIpInPrefix(char* prefix, in_addr_t ip) {
    struct in_addr prefixAddr;

    if (inet_aton(prefix, &prefixAddr) == 0) {
        return -1;
    }

    in_addr_t ipNetworkPart = ip & prefixAddr.s_addr;
    return ipNetworkPart == prefixAddr.s_addr;
}

void handlePacket(const unsigned char* packet, struct PrefixInfo* prefixes) {

    struct in_addr source_ip;
    const unsigned char* dhcp_offset = packet + 26;  

    memcpy(&source_ip.s_addr, dhcp_offset, 4);

    for (int i = 0; i < prefixCount; i++) {
        char* token, *netPrefix, *cidr_notation;
        char* prefixCopy = strdup(prefixes[i].prefix);

        token = strtok(prefixCopy, "/");
        netPrefix = (char*)malloc(strlen(token) + 1);
        strcpy(netPrefix, token);
        token = strtok(NULL, "/");
        cidr_notation = (char*)malloc(strlen(token) + 1);
        strcpy(cidr_notation, token);
        
        if(prefixes[i].maxHosts == 0) {
            prefixes[i].maxHosts = 1 << (32 - atoi(cidr_notation));
        }
        if(isIpInPrefix(netPrefix, source_ip.s_addr)) {
            prefixes[i].allocated++;
            double percentage = (double)(prefixes[i].allocated) * 100.00 / (double)(prefixes[i].maxHosts);
            printf("%s %d %d %.2f%%\n", prefixes[i].prefix, prefixes[i].maxHosts, prefixes[i].allocated, percentage);
        }

        free(netPrefix);
        free(cidr_notation);
        free(prefixCopy);
    }
}

int main(int argc, char* argv[]) {
    int opt;
    char* interface = NULL;
    char* filename = NULL;
    struct PrefixInfo *prefixes = NULL;
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
    
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if(filename != NULL) {
        //open pcap file for reading
        handle = pcap_open_offline(filename, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
            return 1;
        }
    }

    else if(interface != NULL) {
        //opening network interface
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
    }

    while (1) {
        struct pcap_pkthdr header;
        const unsigned char* packet = pcap_next(handle, &header);

        if (packet == NULL) {
            continue;
        }
        handlePacket(packet, prefixes);
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
