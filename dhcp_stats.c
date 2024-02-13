
/**
 * Author: Denys Petrovskyi (xpetro27@stud.fit.vutbr.cz)
*/

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <getopt.h>
#include <syslog.h>
#include <ncurses.h>
#include <regex.h>

int prefixCount = 0;
char* interface = NULL;
char* filename = NULL;


//structure that contains information about ip prefix
struct PrefixInfo {
    char* prefix;
    int maxHosts;
    int usedHosts;
    bool sendToSys;
    char* allocatedIp; //string that contains all IP addresses that have already been counted to this prefix
};

struct PrefixInfo *prefixes = NULL;

pcap_t* handle = NULL;

//checking if ip is in prefix
int isIpInPrefix(char* prefix, in_addr_t ip) {
    struct in_addr prefixAddr;

    if (inet_aton(prefix, &prefixAddr) == 0) {
        return -1;
    }

    in_addr_t ipNetworkPart = ip & prefixAddr.s_addr;
    return ipNetworkPart == prefixAddr.s_addr;
}
//printing out data using ncurses
void printPrefixDataInterface() {
    clear();
    printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");

    for(int i = 0; i < prefixCount; i++) {
        double percentage = (double)(prefixes[i].usedHosts) * 100.00 / (double)(prefixes[i].maxHosts);
        printw("%s %d %d %.2f%%\n", prefixes[i].prefix, prefixes[i].maxHosts, prefixes[i].usedHosts, percentage);
    }
    
    refresh();
}

void prefixDataUpdate(const unsigned char* packet) {
    struct in_addr source_ip;
    //getting source ip
    const unsigned char* dhcp_offset = packet + 26;  
    memcpy(&source_ip.s_addr, dhcp_offset, 4);

    char* source_ip_str = inet_ntoa(source_ip);

    for (int i = 0; i < prefixCount; i++) {
        //splitting the prefix
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
            prefixes[i].maxHosts -= 2;
        }
        //if IP is in prefix
        if(isIpInPrefix(netPrefix, source_ip.s_addr)) {
            char* sub_str = strstr(prefixes[i].allocatedIp, source_ip_str);
            if(sub_str == NULL) {
                prefixes[i].usedHosts++;
                double percentage = (double)(prefixes[i].usedHosts) * 100.00 / (double)(prefixes[i].maxHosts);
                if(percentage >= 100) {
                    pcap_breakloop(handle);
                }
                if (percentage > 50 && !prefixes[i].sendToSys) {
                    syslog(LOG_INFO, "prefix %s exceeded 50%% of allocations", prefixes[i].prefix);
                    prefixes[i].sendToSys = true;
                }
                //adding IP to the string of allocated IP addresses
                char* allocatedIpNew = (char*)malloc(strlen(prefixes[i].allocatedIp) + strlen(source_ip_str) + 2);
                if(allocatedIpNew == NULL) {
                    fprintf(stderr, "Error ocured while allocating memory\n");
                    exit(1);
                }
                strcpy(allocatedIpNew, prefixes[i].allocatedIp);
                strcat(allocatedIpNew, source_ip_str);
                strcat(allocatedIpNew, " ");

                free(prefixes[i].allocatedIp);
                prefixes[i].allocatedIp = allocatedIpNew;
            }
        }

        free(netPrefix);
        free(cidr_notation);
        free(prefixCopy);
    }

    if(interface != NULL)
        printPrefixDataInterface();
}

void pcapLoopPacketHandle(unsigned char* data, const struct pcap_pkthdr *pkthdr, const unsigned char* packet) {
    prefixDataUpdate(packet);
}

int main(int argc, char* argv[]) {
    int opt;
    int prefixesMax = argc - 1;
    char errbuf[PCAP_ERRBUF_SIZE];


    //handling arguments
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
                exit(1);
        }
    }

    if(filename == NULL && interface == NULL) {
        fprintf(stderr, "Desired interface or pcap file must be provided.\nUsage: ./dhcp-stats [-r <filename>] [-i <interface>] <ip-prefix> [<ip-prefix> ...]\n");
        exit(1);
    }
    if(filename != NULL && interface != NULL) {
        fprintf(stderr, "Can not provide interface and pcap file simultaneously.\nUsage: ./dhcp-stats [-r <filename>] [-i <interface>] <ip-prefix> [<ip-prefix> ...]\n");
        exit(1);
    }
    if(optind == argc) {
        fprintf(stderr, "At least one IP prefix must be provided.\nUsage: ./dhcp-stats [-r <filename>] [-i <interface>] <ip-prefix> [<ip-prefix> ...]\n");
        exit(1);
    }

    //process the IP prefixes
    prefixes = (struct PrefixInfo *)malloc(prefixesMax * sizeof(struct PrefixInfo));
    //using regex to control format of IP prefix
    regex_t reg;
    if(regcomp(&reg, "\\([0-9]\\{1,3\\}\\.\\)\\{3\\}[0-9]\\{1,3\\}\\(/[0-9]\\{1,2\\}\\)", 0) != 0) {
        fprintf(stderr, "Failed to compile regex\n");
        exit(1);
    }

    for (int i = optind; i < argc; i++) {   
        int val = regexec(&reg, argv[i], 0, NULL, 0);
        if(val != 0) {
            fprintf(stderr, "Wrong IP prefix format\n");
            exit(1);
        }

        prefixes[prefixCount].prefix = (char*)malloc(strlen(argv[i]) + 1);
        if(prefixes[prefixCount].prefix == NULL) {
            fprintf(stderr, "Error ocured while allocating memory\n");
            exit(1);
        }
        strcpy(prefixes[prefixCount].prefix, argv[i]);

        prefixes[prefixCount].maxHosts = 0;
        prefixes[prefixCount].usedHosts = 0;
        prefixes[prefixCount].sendToSys = false;

        prefixes[prefixCount].allocatedIp = (char*)malloc(5);
        if(prefixes[prefixCount].allocatedIp == NULL) {
            fprintf(stderr, "Error ocured while allocating memory\n");
            exit(1);
        }
        strcpy(prefixes[prefixCount].allocatedIp, "ip: ");
        prefixCount++;
    }
    regfree(&reg);
    //initialize syslog
    openlog("dhcp_stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    
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
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening device: %s\n", errbuf);
            return 1;
        }
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

    if(interface != NULL) {
        //initialize ncurses
        initscr();
        noecho();
        cbreak();
    }
    
    pcap_loop(handle, 0, pcapLoopPacketHandle, NULL);
    
    if(filename != NULL) {
        printf("IP-Prefix Max-hosts Allocated addresses Utilization\n");
        for(int i = 0; i < prefixCount; i++) {
            double percentage = (double)(prefixes[i].usedHosts) * 100.00 / (double)(prefixes[i].maxHosts);
            printf("%s %d %d %.2f%%\n", prefixes[i].prefix, prefixes[i].maxHosts, prefixes[i].usedHosts, percentage);

        }
    }
    //free alocated memory
    free(interface);
    free(filename);
    for (int i = 0; i < prefixCount; i++) {
        free(prefixes[i].prefix);
        free(prefixes[i].allocatedIp);
    }
    free(prefixes);
    pcap_close(handle);
    if(interface != NULL) {
        closelog();
        endwin();
    }
    return 0;
}