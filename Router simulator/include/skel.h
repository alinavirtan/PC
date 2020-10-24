#pragma once
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h> 
#include <netinet/if_ether.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <asm/byteorder.h>


#define MAX_LEN 1600
#define ROUTER_NUM_INTERFACES 4
#define IP_OFF (sizeof(struct ether_header))
#define ICMP_OFF (IP_OFF + sizeof(struct iphdr))

#define DIE(condition, message) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[%d]: %s\n", __LINE__, (message)); \
			perror(""); \
			exit(1); \
		} \
	} while (0)


typedef struct {
	int size;
	char payload[MAX_LEN];
	int interface;
} packet;


struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));


struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};


void parse_arp_table();
int read_rtable(struct route_table_entry *rtable);
int send_packet(int interface, packet *m);
int get_packet(packet *m);
char *get_interface_ip(int interface);
int get_interface_mac(int interface, uint8_t *mac);
void init();
uint16_t checksum(void* vdata,size_t length);
void hex_dump(const void* data, size_t size);
int hex2byte(const char *hex);
int hwaddr_aton(const char *txt, uint8_t *addr);
void init_packet(packet *pkt);
void swap_mac(u_char str1[6], u_char str2[6]);
void swap_ip(__u32& source, __u32& dest);
void swap_arp_ip(u_char str1[4], u_char str2[4]);
uint32_t to_u32(u_char str[4]);
u_char* u32_to_array(uint32_t nr);