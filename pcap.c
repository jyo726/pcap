#include "pcap1.h"
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>

int i=0;
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }
    u_int eth_len=sizeof(struct eth_hdr);
    u_int ip_len=sizeof(struct ip_hdr);
    u_int tcp_len=sizeof(struct tcp_hdr);
    u_int udp_len=sizeof(struct udp_hdr);

   
    ethernet=(eth_hdr *)packet;
    

    if(ntohs(ethernet->eth_type)==0x0800){
        ip=(ip_hdr*)(packet+eth_len);
        printf("來源ip位址 : %d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
        printf("目的ip位址 : %d.%d.%d.%d\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
        if(ip->protocol==6){
            
            tcp=(tcp_hdr*)(packet+eth_len+ip_len);
            printf("來源port : %d\n",ntohs(tcp->sport));
            printf("目的port : %d\n",ntohs(tcp->dport));
        }
        
    }

    

    printf("封包長度 : %d\n",header->len);
    printf("封包時間 : %s",ctime((const time_t*)&header->ts.tv_sec));
    printf("\n");

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    
}

int main(int argc, char **argv) {
    char *device = "eth0";
    char filename[80];
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;
    int total_packet_count = 200;
    u_char *my_arguments = NULL;
    struct bpf_program filter;
    char filter_exp[100];
    int i=2;
    bpf_u_int32 subnet_mask, ip;

    strcpy(filename, argv[1]);

    while(argv[i]!=NULL){
        strcat(filter_exp,argv[i++]);
        filter_exp[strlen(filter_exp)]=' ';
    }

    handle = pcap_open_offline(filename, error_buffer);

    pcap_compile(handle, &filter, filter_exp, 0, ip);

    pcap_setfilter(handle, &filter);

    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

    return 0;
}
