#include "helpers.h"

void msg_for_tcp_client(char* msg, udp_message* udp_msg, 
 							struct sockaddr_in udp_client_addr,
							unordered_map<string, client_info> &clients, 
							unordered_map<string, vector<topic_info>> &topic);

bool connection_to_server(int newsockfd, string client_id, unordered_map<string, 
					client_info> &clients, unordered_map<int, string> &sockets);

void subscription(int sock, tcp_message* tcp_msg, unordered_map<string, 
					client_info> &clients, unordered_map<string, 
					vector<topic_info>> &topics, string client_id);