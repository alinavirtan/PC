#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s , (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet* socket_receive_message(int sockfd, packet *m)
{        
	m->size = read(sockfd, m->payload, MAX_LEN);
	DIE(m->size == -1, "read");
	return m;
}

int send_packet(int sockfd, packet *m)
{        
	return write(interfaces[sockfd], m->payload, m->size);
}


int get_packet(packet *m) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}	

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

int get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
	return 1;
}

void init()
{
	int s0 = get_sock("r-0");
	int s1 = get_sock("r-1");
	int s2 = get_sock("r-2");
	int s3 = get_sock("r-3");
	interfaces[0] = s0;
	interfaces[1] = s1;
	interfaces[2] = s2;
	interfaces[3] = s3;
}

uint16_t checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;

	uint64_t acc=0xffff;

	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}


	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	return htons(~acc);
}


static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}


void hex_dump(const void* data, size_t size)
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

void init_packet(packet *pkt)
{
	memset(pkt->payload, 0, sizeof(pkt->payload));
	pkt->size = 0;
}

void swap_arp_ip(u_char str1[4], u_char str2[4]) {
    char temp[4];
    for(int i = 0; i < 4; i++)
    {
        temp[i] = str1[i];
        str1[i] = str2[i];
        str2[i] = temp[i];
    }
}

void swap_mac(u_char str1[6], u_char str2[6]) {
    char temp[6];
    for(int i = 0; i < 6; i++)
    {
        temp[i] = str1[i];
        str1[i] = str2[i];
        str2[i] = temp[i];
    }
}

void swap_ip(__u32& source, __u32& dest) {
        __u32 old_source = source;
        source = dest;
        dest = old_source;
}


uint32_t to_u32(u_char str[4]) {
	uint32_t conversion = *((uint32_t*) str);
	return conversion;
}

u_char* u32_to_array(uint32_t nr) {
	uint8_t* arr = (uint8_t*) malloc(5 * sizeof(uint8_t));
	for (int i = 0; i < 4; i++) {
		arr[i] = ((uint8_t*)&nr)[3 - i];
	}
	return arr;
}