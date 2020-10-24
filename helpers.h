#ifndef _HELPERS_H
#define _HELPERS_H 1

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <zconf.h>
#include <stdlib.h>
#include <queue>

#define MSG_LEN 4000
#define BUFLEN 1501	
#define MAX_CLIENTS	100	// pentru listen

/* data type in udp message */
#define INT_DATA 0
#define SHORT_REAL_DATA 1
#define FLOAT_DATA 2
#define STRING_DATA 3

/* starea clientului tcp fata de un topic */
#define SUBSCRIBED 1
#define UNSUBSCRIBED 0

/* starea clientului tcp fata de server */
#define CONNECTED 1
#define DISCONNECTED 0

using namespace std;

/* mesaj trimis de un client udp */
struct udp_message {
	char topic[50];		  // numele topicului
	uint8_t data_type;   // tipul de date din msj: INT, SHORT_REAL, FLOAT, STRING 
	char payload[1501]; // continutul mesajului
};

/* mesaj trimis de un client tcp la server */
struct tcp_message {
	uint8_t state;     // SUBSCRIBED/UNSUBSCRIBED
	uint8_t sf;       // sf = 0 -> store&forward dezactivat, sf = 1 -> activat 
	char topic[50];  // numele topicului
} __attribute__((packed));

/* mesaj transmis de server la un client tcp  */
struct server_message {
	struct in_addr udp_ip = {};
	unsigned short udp_port;
	char topic[50];
	uint8_t data_type;	 // tipul de date din msj: INT, SHORT_REAL, FLOAT, STRING 
	char payload[1501];
};

struct client_info {
	int state;  // CONNECTED/DISCONNECTED (fata de server)
	int socket; // socketul pe care s-a conectat la server
	vector<string> cli_topics;  // topicurile la care este abonat 
	queue<string> messages;	   // mesajele primeste cand e deconectat pentru
							// topicurile la care este conectat cu sf = 1
};

struct topic_info {
	string client_id;
	int sf;
};

#define DIE(assertion, call_description)					\
	do {													\
		if (assertion) {									\
			fprintf(stderr, "FAILED: " call_description); 	\
			exit(EXIT_FAILURE);								\
		}													\
	} while(0)

#endif