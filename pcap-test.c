#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "p_struct.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

void print_mac(u_int8_t*m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_ip(struct in_addr m){
	printf("%s",inet_ntoa(m));
}


typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
		int size_eth = (sizeof(eth_hdr ->ether_dhost) + sizeof(eth_hdr -> ether_shost) + sizeof(eth_hdr -> ether_type));
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*) (packet+size_eth);
		u_int8_t ipln = (ip_hdr->ip_hl)*4;
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr* ) (packet+size_eth+ipln);

		u_int8_t little_th_off = (tcp_hdr -> th_off);
		little_th_off=(little_th_off & 0xff)<<4 | (little_th_off & 0xff)>>4;
		int packet_hdr = size_eth + 20 + (little_th_off *4);
		
		if(ip_hdr -> ip_p != 6){
			printf("um... this is not tcp type!\n");
			continue;
		}
		printf("%u bytes captured\nmac_s:", header->caplen);
		print_mac(eth_hdr -> ether_shost);
		printf("\nmac_d:");
		print_mac(eth_hdr -> ether_dhost);
		printf("\nip_snd: ");
		print_ip(ip_hdr -> ip_src);
		printf("\nip_dst:");
		print_ip(ip_hdr -> ip_dst);	
		printf("\n");
		printf("d_port: %u",ntohs(tcp_hdr -> th_dport));
		printf("\n");
		printf("s_port: %u",ntohs(tcp_hdr -> th_sport));
		printf("\n");

		if((header -> caplen) - packet_hdr != 0){ 
			for(int i=0; i < 10; i++){
				printf("%02x ",packet[packet_hdr+i]);
			}
		}
		else {
			printf("[tcp body emty]\n");
		}

		printf("\n");
		printf("\n");	
	}

	pcap_close(pcap);
}
