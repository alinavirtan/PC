#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <iomanip>
#include "server.h"
#include <unordered_map>
#include <vector>
#include <string>

void usage(char*file)
{
	fprintf(stderr,"Usage: %s <PORT_DORIT>\n",file);
	exit(0);
}

void msg_for_tcp_client(char* msg, udp_message* udp_msg, 
						struct sockaddr_in udp_client_addr, 
						unordered_map<string, client_info> &clients, 
						unordered_map<string, vector<topic_info>> &topics) {
	server_message* new_msg = new server_message;
	int rc;

	new_msg->udp_port = udp_client_addr.sin_port;
	new_msg->udp_ip = udp_client_addr.sin_addr;
	new_msg->data_type = udp_msg->data_type - 0;

	memset(new_msg->topic, 0, sizeof(new_msg->topic));
	memcpy(new_msg->topic, udp_msg->topic, strlen(udp_msg->topic));
	memset(new_msg->payload, 0, sizeof(new_msg->payload));


	if (new_msg->data_type  == INT_DATA) {
		uint8_t sign = udp_msg->payload[0];
		int integer = int((unsigned char)(udp_msg->payload[1]) << 24 |
	 	(unsigned char)(udp_msg->payload[2]) << 16 |
	 	(unsigned char)(udp_msg->payload[3]) << 8 |
		(unsigned char)(udp_msg->payload[4]));
		if (udp_msg->payload[0] == 1) {
			integer = (-1) * integer;
		}
		sprintf(new_msg->payload, "%d", integer);
	} else if (new_msg->data_type == SHORT_REAL_DATA) {
		double shortinteger = double((unsigned char)(udp_msg->payload[0]) << 8 |
				        			(unsigned char)(udp_msg->payload[1]));
		shortinteger /= 100;
		sprintf(new_msg->payload, "%.2lf", shortinteger);
	} else if (new_msg->data_type == FLOAT_DATA) {
		uint8_t sign = udp_msg->payload[0];
		char exponent[BUFLEN];

		int floatnr = int((unsigned char)(udp_msg->payload[1]) << 24 |
								(unsigned char)(udp_msg->payload[2]) << 16 |
				            	(unsigned char)(udp_msg->payload[3]) << 8 |
				            	(unsigned char)(udp_msg->payload[4]));
		int exp = udp_msg->payload[5];
							
		int tmp = 1;
		for (int k = 1; k <= exp; k++) {
			tmp *= 10;
		}

		if (sign == 1) {
			sprintf(new_msg->payload, "-");
		}

		strcat(new_msg->payload, to_string(floatnr / tmp).c_str());

		if (exp != 0 && exp < strlen(to_string(floatnr).c_str())) {
			strcat(new_msg->payload, ".");
			strcat(new_msg->payload, to_string(floatnr).c_str() + 
						strlen(to_string(floatnr).c_str()) - exp);		
		}

		if (exp != 0 && exp > strlen(to_string(floatnr).c_str())) {
			strcat(new_msg->payload, ".");
			for (int j = 0; j < exp - strlen(to_string(floatnr).c_str()); j++) {
				strcat(new_msg->payload, "0");
			}
			strcat(new_msg->payload, to_string(floatnr).c_str());
		}
	} else if (new_msg->data_type == STRING_DATA) {
		memset(new_msg->payload, 0, sizeof(new_msg->payload));
		strncpy(new_msg->payload, udp_msg->payload, strlen(udp_msg->payload));
	}
	sprintf(msg, "%s", inet_ntoa(new_msg->udp_ip));
	strcat(msg, ":");
	strcat(msg, to_string(ntohs(new_msg->udp_port)).c_str());
	strcat(msg, " - ");
	strcat(msg, new_msg->topic);
	strcat(msg, " - ");

	if (new_msg->data_type == INT_DATA) {
		strcat(msg, "INT");
	} else if (new_msg->data_type == SHORT_REAL_DATA) {
		strcat(msg, "SHORT_REAL");
	} else if (new_msg->data_type == FLOAT_DATA) {
		strcat(msg, "FLOAT");
	} else if (new_msg->data_type == STRING_DATA) {
		strcat(msg, "STRING");
	}

	strcat(msg, " - ");
	strcat(msg, new_msg->payload);
	strcat(msg, "\n");

	int bytes_send = 0, bytes_remaining = 0, bytes_count = 0;

	/* trimite mesajul la clientii abonati */
	vector<topic_info> cli = topics[new_msg->topic];
	for (int k = 0; k < cli.size(); k++) {
		string cli_id = cli[k].client_id;
		int sock = clients[cli_id].socket;
		
		if (clients[cli_id].state == CONNECTED) {
			/*trimit dimensiunea mesajului*/
			char dim[BUFLEN] = {0};
			memset(dim, 0, sizeof(dim));
			sprintf(dim, "%s\n", to_string(strlen(msg)).c_str());
			bytes_send = send(sock, dim, BUFLEN, 0);
			DIE(bytes_send < 0, "Failed to send dimension to tcp client");

			/* trimit mesajul*/
			bytes_count = 0;
			bytes_remaining = strlen(msg);
			while (bytes_remaining > 0) {
				bytes_send = send(sock, msg + bytes_count, bytes_remaining, 0);
				DIE(bytes_send < 0, "Failed to send message to tcp client");
				bytes_remaining = bytes_remaining - bytes_send;
				bytes_count = bytes_count + bytes_send;
			}
		} 

		if (clients[cli_id].state == DISCONNECTED && cli[k].sf == 1) {
			(clients[cli_id].messages).push(msg);
		} 
	}

	delete new_msg;
}


void print_socket(unordered_map<int, string> &sockets) {
	unordered_map<int, string>::iterator it;
	for (it = sockets.begin(); it != sockets.end(); it++) {
		cout << "cheia: " << it->second << endl;
	}
	cout << endl;
}

/* conectarea/deconectarea clientului cu/de la server */
bool connection_to_server(int newsockfd, string client_id, unordered_map<string,
				  client_info> &clients, unordered_map<int, string> &sockets) {
	/* clientul incearca sa se logheze cu acelasi id de pe alt socket =>eroare*/
	if (clients.find(client_id) != clients.end() && clients[client_id].state == 
						CONNECTED && newsockfd != clients[client_id].socket) {
		int bytes_send = 0, bytes_remaining = 0, bytes_count = 0;
		char str[BUFLEN] = "Client already connected\n";

		/* trimit dimensiunea mesajului */
		char dim[BUFLEN] = {0};
		memset(dim, 0, sizeof(dim));
		sprintf(dim, "%s\n", to_string(strlen(str)).c_str());
		bytes_send = send(newsockfd, dim, BUFLEN, 0);
		DIE(bytes_send < 0, "Failed to send dimension to tcp client\n");

		/* trimit mesajul */
		bytes_count = 0;
		bytes_remaining = strlen(str);
		while (bytes_remaining > 0) {
			bytes_send = send(newsockfd, str + bytes_count, bytes_remaining, 0);
			DIE(bytes_send < 0, "Failed to send message to tcp client\n");
			bytes_remaining = bytes_remaining - bytes_send;
			bytes_count = bytes_count + bytes_send;
		}

		sockets[newsockfd] = "already_connected";
		return false;
	}				  	

	/* clientul se conecteaza pentru prima oara la server */
	if (clients.find(client_id) == clients.end()) {
		struct client_info cinfo;
		cinfo.state = CONNECTED;
		cinfo.socket = newsockfd;
		clients[client_id] = cinfo;

		sockets[newsockfd] = client_id;
	}

	/* clientul se reconecteaza dupa o deconectare anterioara */
	if (clients.find(client_id) != clients.end() && clients[client_id].state 
														== DISCONNECTED) {
		clients[client_id].state = CONNECTED;
		clients[client_id].socket = newsockfd;
		sockets[newsockfd] = client_id;

		/* trimit mesajele pastrate cand clientului s-a deconectat */
 		if (!(clients[client_id].messages).empty()) {
	 		while (!(clients[client_id].messages).empty()) {
	 			int bytes_remaining = 0, bytes_send = 0, bytes_count = 0;
	 			string queue_elem = (clients[client_id].messages).front();

	 			int queue_elem_size = queue_elem.size();
	 			char msg[MSG_LEN] = {0};
	 			memset(msg, 0, sizeof(msg));
	 			memcpy(msg, queue_elem.c_str(), queue_elem_size);

	 			/* trimit dimensiunea mesajului */
	 			char dim[BUFLEN] = {0};
				memset(dim, 0, sizeof(dim));
				sprintf(dim, "%s\n", to_string(strlen(msg)).c_str());
				bytes_send = send(newsockfd, dim, BUFLEN, 0);
				DIE(bytes_send < 0, "Failed to send dimension to tcp client");

				/* trimit mesajul*/
				bytes_count = 0;
				bytes_remaining = strlen(msg);
				while (bytes_remaining > 0) {
					bytes_send = send(newsockfd, msg + bytes_count, 
										bytes_remaining, 0);
					DIE(bytes_send < 0, "Failed to send message to tcp client");
					bytes_remaining = bytes_remaining - bytes_send;
					bytes_count = bytes_count + bytes_send;
				}

	 			/* scot mesajul din coada */
	 			(clients[client_id].messages).pop();
	 		}
		}
	}

	return true;					
}

/* s-a primit de la client subscribe/unsubscribe */							
void subscription(int sock, tcp_message* tcp_msg, unordered_map<string, 
					client_info> &clients, unordered_map<string, 
					vector<topic_info>> &topics, string client_id) {
	bool found = false;
	int k;
	for (k = 0; k < (topics[tcp_msg->topic]).size(); k++) {
		if ((topics[tcp_msg->topic])[k].client_id == client_id) {
			found = true;
			break;
		}
	}

	if (tcp_msg->state == SUBSCRIBED) {
		if (found == false) {
			struct topic_info info;
			info.client_id = client_id;
			info.sf = tcp_msg->sf;
									
			topics[tcp_msg->topic].push_back(info);
			clients[client_id].cli_topics.push_back(tcp_msg->topic);
		}

		if (found == true && tcp_msg->sf != (topics[tcp_msg->topic])[k].sf) {
			struct topic_info info;
			info.client_id = client_id;
			info.sf = tcp_msg->sf;

			(topics[tcp_msg->topic])[k] = info;
		}  
	}

	if (tcp_msg->state == UNSUBSCRIBED) {
		if (found == true) {
			(topics[tcp_msg->topic]).erase((topics[tcp_msg->topic]).begin() + k);

			for (int k = 0; k < (clients[client_id].cli_topics).size(); k++) {
				if ((clients[client_id].cli_topics)[k] == tcp_msg->topic) {
					(clients[client_id].cli_topics).erase((clients[client_id].cli_topics).begin() + k);
					break;
				}
			}		
		} else {
			char str[BUFLEN];
			int bytes_remaining = 0, bytes_count = 0, bytes_send;
			sprintf(str, "You're not connected to %s.\n", tcp_msg->topic);
				
			/* trimit dimensiunea mesajului */
			char dim[BUFLEN] = {0};
			memset(dim, 0, sizeof(dim));
			sprintf(dim, "%s\n", to_string(strlen(str)).c_str());
			int ret = send(sock, dim, BUFLEN, 0);
			DIE(ret < 0, "Failed to send dimension to tcp client\n");

			/* trimit mesajul */
			bytes_count = 0;
			bytes_remaining = strlen(str);
			while (bytes_remaining > 0) {
				bytes_send = send(sock, str + bytes_count, bytes_remaining, 0);	
				DIE(bytes_send < 0, "Failed to send message to the tcp client");
				bytes_remaining = bytes_remaining - bytes_send;
				bytes_count = bytes_count + bytes_send;
			}
		}
	}
}	


int main(int argc, char *argv[]) {
	struct sockaddr_in udp_sock_addr = {}, tcp_sock_addr, udp_client_addr = {};
	struct sockaddr_in tcp_client_addr = {}; 
	char buff[BUFLEN];
	socklen_t udp_client_len = sizeof(udp_client_addr);
	socklen_t tcp_client_len = sizeof(tcp_client_addr);
	udp_message* udp_msg = new udp_message;
	server_message* new_msg = new server_message;
	tcp_message* tcp_msg = new tcp_message;

	fd_set read_fds;	// multimea de citire folosita in select()
	fd_set tmp_fds;		// multime folosita temporar
	int fdmax;		    // valoare maxima fd din multimea read_fds

	unordered_map<string, vector<topic_info>> topics;
	unordered_map<string, client_info> clients;
	unordered_map<int, string> sockets;

	/* se goleste multimea de descriptori de citire (read_fds) 
	 *si multimea temporara (tmp_fds) */
	FD_ZERO(&read_fds);
	FD_ZERO(&tmp_fds);


	/* verificare input eronat */
	if (argc != 2) {
		usage(argv[0]);
	}	
	DIE(atoi(argv[1]) >= 0 && atoi(argv[1]) <= 1023, "Incorrect port\n");

	/* deschidere socket UDP pentru receptionarea conexiunilor */
	int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	DIE(udp_sockfd < 0, "Failed to open UDP socket\n");
	
	/* setare udp_sock_addr pentru a asculta pe portul corespunzator */
	memset((char *) &udp_sock_addr, 0, sizeof(udp_sock_addr));
	udp_sock_addr.sin_family = AF_INET; 
	udp_sock_addr.sin_port = htons(atoi(argv[1])); 
	udp_sock_addr.sin_addr.s_addr = INADDR_ANY;	
							
	/* legare proprietati de socketul UDP */
	int ret = bind(udp_sockfd, (struct sockaddr*) &udp_sock_addr, 
									sizeof(struct sockaddr_in));
	DIE(ret < 0, "Bind failed\n");

	/* deschidere socket TCP pentru receptionarea conexiunilor */
	int tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	DIE(tcp_sockfd < 0, "Failed to open TCP socket\n");
	
	/* setare tcp_sock_addr pentru a asculta pe portul corespunzator */
	memset((char *) &tcp_sock_addr, 0, sizeof(tcp_sock_addr));
	tcp_sock_addr.sin_family = AF_INET;
	tcp_sock_addr.sin_port = htons(atoi(argv[1]));
	tcp_sock_addr.sin_addr.s_addr = INADDR_ANY;

	/* legare proprietati de socketul TCP */
	int enable = 1;
    if (setsockopt(tcp_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, 
    									sizeof(int)) == -1) {
        perror("setsockopt\n");
        exit(1);
    }

    enable = 1;
	if (setsockopt(tcp_sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, 
													sizeof(int)) < 0) {
		perror("Neagle Algorithm could not be disabled\n");
		exit(1);
	}
    
    /* legarea proprietatilor de socketul TCP */
	ret = bind(tcp_sockfd, (struct sockaddr*) &tcp_sock_addr, 
								sizeof(struct sockaddr_in));
	DIE(ret < 0, "Bind failed\n");

	/* serverul asculta pe socketul tcp_sockdf */
	ret = listen(tcp_sockfd, MAX_CLIENTS);
	DIE(ret < 0, "Listen failed\n");

	FD_SET(STDIN_FILENO, &read_fds);
	FD_SET(udp_sockfd, &read_fds);
	FD_SET(tcp_sockfd, &read_fds);
	fdmax = (tcp_sockfd > udp_sockfd) ? tcp_sockfd : udp_sockfd;

	int i;
	bool out = false;
	ssize_t rc;
	memset(buff, 0, BUFLEN);

	while (1) {
		tmp_fds = read_fds;
		ret = select(fdmax + 1, &tmp_fds, NULL, NULL, NULL);
		DIE(ret < 0, "Select failed\n");

		for (i = 0; i <= fdmax; i++) {
			if (FD_ISSET(i, &tmp_fds)) {
				/* caz 1 : s-au primit comanda de la tastatura (exit) */
				if (i == 0) {
					fgets(buff, BUFLEN - 1, stdin);
					if (strncmp(buff, "exit", 4) == 0) {
						for (int k = 1; k <= fdmax; k++) {
							if (FD_ISSET(k, &read_fds)) {
								if (k != tcp_sockfd && k != udp_sockfd) {
									char str[BUFLEN];
									int bytes_count = 0, bytes_remaining = 0;
									int bytes_send = 0;
									sprintf(str, "exit");

									/* trimit dimensiunea mesajului */
									char dim[BUFLEN] = {0};
									memset(dim, 0, sizeof(dim));
									sprintf(dim, "%s\n", 
												to_string(strlen(str)).c_str());
									int ret = send(k, dim, BUFLEN, 0);
									DIE(ret < 0, "Failed to send dimension\n");
									
									/* trimit mesajul */
									bytes_count = 0;
									bytes_remaining = strlen(str);
									while (bytes_remaining > 0) {
										bytes_send = send(k, str + bytes_count, 
															bytes_remaining, 0);
										DIE(bytes_send < 0, 
										  "Failed to send exit to tcp client\n");
										bytes_remaining -= bytes_send;
										bytes_count += bytes_send;
									}
									close(k);
									FD_CLR(k, &read_fds);
								}
							}
						}
						close(udp_sockfd);
						close(tcp_sockfd);
						out = true;
						break;
					} else {
						cout << "Invalid exit message\n\n";
						continue;
					}
				} else if (i == udp_sockfd) {  	
					/* caz 2 : s-a primit mesaj de la un client UDP */
					memset(udp_msg, 0, sizeof(struct udp_message));
					rc = recvfrom(udp_sockfd, udp_msg, sizeof(struct udp_message), 
						0, (struct sockaddr*)&udp_client_addr, &udp_client_len);
					DIE(rc < 0, "Failed to receive from UDP client\n");
					DIE(udp_msg->data_type > 3, "Unknown data type");
					
					/* construiesc mesajul pe care il trimit la clientii tcp 
					 * abonati la topicul respectiv */
					char msg[MSG_LEN] = {0};
					msg_for_tcp_client(msg, udp_msg, udp_client_addr, clients, 
																	topics);
				} else if (i == tcp_sockfd) {  	
						/* caz 3 : a venit o cerere de conexiune tcp */
					/* accepta cererea de conexiune de la un client TCP */
					int newsockfd = accept(tcp_sockfd, 
						 (struct sockaddr *) &tcp_client_addr, &tcp_client_len);				  
					DIE(newsockfd < 0, "Failed to accept the client\n");

					FD_SET(newsockfd, &read_fds);

					if (newsockfd > fdmax) { 
						fdmax = newsockfd;
					}

					/* dezactivez algoritmul lui Neagle */
					enable = 1;
					if (setsockopt(newsockfd, IPPROTO_TCP, TCP_NODELAY, 
									(char *)&enable, sizeof(int)) < 0) {
				        perror("Neagle Algorithm could not be disabled\n");
				        exit(1);
				    }

				    /* receptionez mesajul de la clientul TCP */
				    rc = recv(newsockfd, buff, BUFLEN - 1, 0);
				    DIE(rc < 0, "Failed to receive the ID client\n");
				    
				    /* caut numele clientului in sockets */
				    bool isthere = false;
				    for (auto it = sockets.begin(); it != sockets.end(); ++it) {
				    	if (it->second == buff) {
				    		isthere = true;
				    		break;
				    	}
				    }
				    /* conectarea clientului la server */
				    string client_id = buff;
					bool conn = connection_to_server(newsockfd, client_id, 
														clients, sockets);
					
					// conexiunea s-a realizat cu success
					if (conn == true && isthere == false) {
						cout << "New client " << buff << " connected from ";
						cout << inet_ntoa(tcp_client_addr.sin_addr) << ":";
						cout << ntohs(tcp_client_addr.sin_port) << endl; 
						cout << endl;	
					} else {
						continue;
					}

				} else {
					/* caz 4 : s-au primit date pe unul din socketii client */
					memset(buff, 0, BUFLEN);
					rc = recv(i, buff, sizeof(tcp_message), 0);
					DIE(rc < 0, "Failed to receive data from tcp client\n");
					string client_id = sockets[i];
					
					 /* clientul inchide conexiunea fortat(CTRL+C) sau se 
					  *conecteaza un client care deja era conectat la server */
					if (rc == 0) {
						if (sockets[i] != "already_connected") {
							cout << "Client " << client_id << " disconnected.\n";
							clients[client_id].state = DISCONNECTED;
						} 

						sockets.erase(i);
						FD_CLR(i, &read_fds);  

						int new_fdmax;
						for (int k = 1; k <= fdmax; k++) {
							if (FD_ISSET(k, &read_fds)) {
								new_fdmax = k;
							}
						}

						close(i);
					} else {	
						/* clientul de pe socketul i s-a deconectat */
						if (strncmp(buff, "exit", 4) == 0) {
							cout << "Client " << client_id << " disconnected.\n\n";
							/* se scoate din multimea de citire socketul inchis */
							FD_CLR(i, &read_fds);
							
							int new_fdmax;
							for (int k = 1; k <= fdmax; k++) {
								if (FD_ISSET(k, &read_fds)) {
									new_fdmax = k;
								}
							}
							fdmax = new_fdmax;

							close(i);			
							clients[client_id].state = DISCONNECTED;
							sockets.erase(i);
						} else {
							/* s-a primit de la client subscribe/unsubscribe */
							string client_id = sockets[i];
							subscription(i, (tcp_message*)buff, clients, topics, 
																	client_id);
						}
					}
				} 
			}
		}

		/* serverul a dat comanda exit */
		if (out == true) {
			break;
		}

		/* golesc buffer-ul */
		memset(buff, 0, BUFLEN);
	}

	delete udp_msg;
	delete tcp_msg;
	delete new_msg;
	close(tcp_sockfd);
	close(udp_sockfd);
}
