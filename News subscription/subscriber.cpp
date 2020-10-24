#include "subscriber.h"


void usage(char*file)
{
	fprintf(stderr,"Usage: %s <ID_Client> <IP_Server> <Port_Server>\n",file);
	exit(0);
}

void incorrect_data_error() {
	cout << "Usage: subscribe <topic> <sf> or unsubscribe <topic> or exit\n\n";
}

void topic_too_long_error() {
	cout << "Topic too long (50 characters max)\n\n";
}

void invalid_sf_error() {
	cout << "Invalid s&f parameter. Valid values: 0 or 1. Try again.\n";
}

int main(int argc, char* argv[]) {
	int sockfd, n, ret;
	char buff[BUFLEN] = {0};
	char rec[MSG_LEN] = {0};
	struct sockaddr_in serv_addr = {};
	tcp_message* tcp_msg = new tcp_message;
	fd_set read_fds, tmp_fds;
	int fdmax;

	FD_ZERO(&read_fds);
	FD_ZERO(&tmp_fds);

	/* argumente eronate */
	if (argc != 4) {
		usage(argv[0]);
	}

	DIE(atoi(argv[3]) >= 0 && atoi(argv[3]) <= 1023, "Incorrect port\n");
	DIE(strlen(argv[1]) >= 11, "ID_Client too long\n");

	/* deschidere socket pentru conexiunea la server */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	DIE(sockfd < 0, "Failed to open socket\n");

	/* setare serv_addr pentru a asculta pe portul corespunzator */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(atoi(argv[3]));
	ret = inet_aton(argv[2], &serv_addr.sin_addr);
	DIE (ret == 0, "inet_atton failed\n");

	/* conectarea la server */
	ret = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (ret < 0) {
		perror("Connect failed\n");
	} else {
		ret = send(sockfd, argv[1], strlen(argv[1]) + 1, 0);
		DIE(ret < 0, "Failed to send ID_Client");
	}

	/* dezactivez algoritmul Neagle */
	int enable = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, 
    											sizeof(int)) < 0) {
        perror("Neagle's Algorithm could not be disabled\n");
        exit(1);
    }

	FD_SET(STDIN_FILENO, &read_fds);
	FD_SET(sockfd, &read_fds);
	fdmax = sockfd;

	while (1) {
		tmp_fds = read_fds;

		ret = select(fdmax + 1, &tmp_fds, NULL, NULL, NULL);
		DIE(ret < 0, "Select failed\n");

		/* comanda primita de la tastatura */
		if (FD_ISSET(STDIN_FILENO, &tmp_fds)) {
			/* se citeste de la tastatura */
			memset(buff, 0, BUFLEN);
			fgets(buff, BUFLEN - 1, stdin);		
			
			/* clientul se aboneaza/dezaboneaza la un anumit topic */
			buff[strlen(buff) - 1] = 0;
			char* p = strtok(buff, " ");

			if (strcmp(p, "exit") == 0) { 
				 /* clientul se deconecteaza */
				char str[5] = "exit";
				ret = send(sockfd, str, strlen(str) + 1, 0);
				DIE(ret < 0, "Send ID_Client failed\n");
				break;
			} else if (strcmp(p, "subscribe") == 0) {
				 /* clientul se aboneaza la un topic */
				tcp_msg->state = SUBSCRIBED;
			} else if (strcmp(p, "unsubscribe") == 0) {
				/* clientul se dezaboneaza de la un topic */ 
				tcp_msg->state = UNSUBSCRIBED;
			} else {
				incorrect_data_error();
				continue;
			}

			p = strtok(NULL, " ");
			if (p == NULL) {
				incorrect_data_error();
				continue;
			} else {
				if (strlen(p) <= 50) {
					memset(tcp_msg->topic, 0, 50);
					strcpy(tcp_msg->topic, p);
				} else {
					topic_too_long_error();
					continue;
				}
			}

			p = strtok(NULL, " ");
			if (tcp_msg->state == SUBSCRIBED) {
				if (p == NULL) {
					incorrect_data_error();
					continue;
				} else {
					if (strcmp(p, "0") == 0 || strcmp(p, "1") == 0) {
						tcp_msg->sf = p[0] - '0';
					} else {
						invalid_sf_error();
						continue;
					}
				}
			} else {
				if (p != NULL) {
					incorrect_data_error();
					continue;
				}
			}
			int ret = send(sockfd, tcp_msg, sizeof(tcp_message), 0);
			DIE(ret < 0, "Failed to send message to server");
			if (strncmp(buff, "subscribe", 9) == 0) {
				cout << "subscribed " << tcp_msg->topic << "\n\n";	
			}
			if (strncmp(buff, "unsubscribe", 11) == 0) {
				cout << "unsubscribed " << tcp_msg->topic << "\n\n";
			}
		} else {    /* primeste de la server */	
			int bytes_received = 0, bytes_count = 0, bytes_remaining = 0;
			memset(rec, 0, BUFLEN);
			bytes_received = recv(sockfd, rec, BUFLEN, 0);
			DIE(bytes_received < 0, "Received data failed\n");

			bytes_count = bytes_remaining = atoi(rec);

			while (bytes_remaining > 0) {
				memset(rec, 0, MSG_LEN);
				bytes_received = recv(sockfd, rec, bytes_remaining, 0);
				DIE(bytes_received < 0, "Received data failed\n");
				if (strncmp(rec, "exit", 4) == 0) {
					delete tcp_msg;
					close(sockfd);
					return 0;
				} else if (strncmp(rec, "Client already connected", 22) == 0) {
					cout << rec;
					delete tcp_msg;
					close(sockfd);
					return 0;
				} else {
					cout << rec;
				}

				bytes_remaining = bytes_remaining - bytes_received;
			}
		}
	}
	delete tcp_msg;
	close(sockfd);
	return 0;
}