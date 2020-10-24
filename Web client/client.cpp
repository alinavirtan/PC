#include <bits/stdc++.h>
#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;
using namespace std;

#define PORT 8080
#define HOST "ec2-3-8-116-10.eu-west-2.compute.amazonaws.com"
#define IP "3.8.116.10"

bool check_number(string str) {
    for (unsigned i = 0; i < str.length(); i++) {
        if (isdigit(str[i]) == false) {
            return false;
        }
    }
    return true;
}

void register_user() {
    char *message, *response;
    string user, passwd;
    char access_route[] = "/api/v1/tema/auth/register";
    char payload_type[] = "application/json";
    json js;

    cout << "username=";
    cin >> user;
    cout << "password=";
    cin >> passwd;

    js["username"] = user;
    js["password"] = passwd;

    int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
    message = compute_post_request(HOST, access_route, payload_type, 
                                    js.dump().c_str(), NULL, 0, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
            
    if (strstr(response, "HTTP/1.1 400 Bad Request") != NULL) {
        cout << "Username " << user << " is already taken.\n\n";
    } else if (strstr(response, "HTTP/1.1 201 Created") != NULL) {
        cout << "You have successfully registered!\n\n";
    } else {
        cout << "Something bad has happened. Please try again.\n\n";
    }

    free(message);
    free(response);
    close_connection(sockfd);
}

void login_user(char** cookies, int &cookies_count) {
    char *message, *response;
    char access_route[] = "/api/v1/tema/auth/login";
    char payload_type[] = "application/json";
    string user, passwd;
    json js;
    
    cout << "username=";
    cin >> user;
    cout << "password=";
    cin >> passwd;

    js["username"] = user;
    js["password"] = passwd;

    int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
    message = compute_post_request(HOST, access_route, payload_type, 
                    js.dump().c_str(), cookies, cookies_count, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
        cout << "You have successfully logged in!\n\n";
    } else if (strstr(response, "HTTP/1.1 204 No Content") != NULL) {
        cout << "You are already logged in!\n\n";
    } else if (strstr(response, "HTTP/1.1 400 Bad Request") != NULL) {
        cout << "Bad password or username.\n\n";
    } else {
        cout << "Something bad has happened. Please try again.\n\n";
    }
            
    // extrag cookie-ul
    char *p;
    p = strtok(response, " ;");
    while (p != NULL) {
        if (strncmp(p, "connect.sid", strlen("connect.sid")) == 0) {
            cookies[0] = strdup(p);
            cookies_count = 1;
        }
        p = strtok(NULL, " ;");
    }
    
    free(message);
    free(response);
    close_connection(sockfd);
}

void enter_library(char** cookies, int &cookies_count, char* &token) {
    char *message, *response;
    char access_route[] = "/api/v1/tema/library/access";

    int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(HOST, access_route, NULL, cookies, 
                                                cookies_count, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
        cout << "Welcome to the library!\n\n";
    } else if (strstr(response, "HTTP/1.1 401 Unauthorized") != NULL) {
        cout << "Unauthorized access! You are not logged in!\n\n";
    } else {
        cout << "Something bad has happened. Please try again.\n\n";
    }

    char *p;
    p = strtok(response, "\"");
    while (p != NULL) {
        if (strcmp(p, "token") == 0) {
            p = strtok(NULL, "\"");
            if (p != NULL && strcmp(p, ":") == 0) {
                p = strtok(NULL, "\"");
                if (p != NULL) {
                    token = strdup(p);
                    //break;
                }
            }
        } else {
            p = strtok(NULL, "\"");
        }
    }

    free(message);
    free(response);
    close_connection(sockfd);    
}

void get_books(char** cookies, int &cookies_count, char *token) {
    char *message, *response;
    char access_route[] = "/api/v1/tema/library/books";

    int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(HOST, access_route, NULL, cookies, 
                                            cookies_count, token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    if (strstr(response, "HTTP/1.1 200 OK") != NULL) {                
        char* p;
        p = strtok(response, "[]\n");
        cout << "[";
        while (p != NULL) {
            if (strstr(p, "id") != NULL && strstr(p, "title") != NULL) {
                string str = '[' + string(p) + ']';
                auto jsonBooks = json::parse(str);
                for (unsigned i = 0; i < jsonBooks.size(); i++) {
                    if (i == jsonBooks.size() - 1) {
                        cout << jsonBooks[i].dump(4);
                    } else {
                        cout << jsonBooks[i].dump(4) << endl;
                    }
                }
                //break;
            }
            p = strtok(NULL, "[]\n");
        }    

        cout << ']' << endl << endl;
    } else if (strstr(response, "HTTP/1.1 403 Forbidden") != NULL) {
        cout << "Forbidden! Enter the library to see the available books.\n\n";
    } else {
        cout << "Something bad happened. Please try again.\n\n";
    }

    free(message);
    free(response);
    close_connection(sockfd);
}

void get_book(char** cookies, int &cookies_count, char* token) {
    char *message, *response;
    string id;
    cout << "id=";
    cin >> id;
            
    if (check_number(id) == false) {
        cout << "Invalid book id.\n\n";
        return;
    }

    string access_route = "/api/v1/tema/library/books/" + id;

    int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(HOST, access_route.c_str(), NULL, cookies, 
                                                        cookies_count, token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
        char* p;
        p = strtok(response, "[]\n");
        while (p != NULL) {
            if (strstr(p, "title") != NULL && strstr(p, "author") != NULL) {
                string str = '[' + string(p) + ']';
                auto jsonBooks = json::parse(str);
                cout << "Title : " << jsonBooks[0]["title"].dump(4) << endl;
                cout << "Author : " << jsonBooks[0]["author"].dump(4) << endl;
                cout << "Genre : " << jsonBooks[0]["genre"].dump(4) << endl;
                cout << "Pages : " << jsonBooks[0]["page_count"].dump(4) << endl;
                cout << "Publisher : " << jsonBooks[0]["publisher"].dump(4) << endl;
                cout << endl;
            }
            p = strtok(NULL, "[]\n");
        }    
    } else if (strstr(response, "HTTP/1.1 403 Forbidden") != NULL) {
        cout << "Forbidden! Enter the library to see the available books.\n\n";
    } else if (strstr(response, "HTTP/1.1 404 Not Found") != NULL) {
        cout << "No book was found. Maybe the id is wrong.\n\n";
    } else {
        cout << "Something bad has happened. Please try again.\n\n";
    }
    
    free(message);
    free(response); 
    close_connection(sockfd);
}

void add_book(char **cookies, int &cookies_count, char *token) {
    char *message, *response;
    char access_route[] = "/api/v1/tema/library/books";
    char payload_type[] = "application/json";
    string title, author, genre, publisher, pages;
    json js;

    cin.ignore(256, '\n');

    cout << "title=";
    getline(cin, title);

    cout << "author=";
    getline(cin, author);

    cout << "genre=";
    getline(cin, genre);

    cout << "publisher=";
    getline(cin, publisher);

    cout << "page_count=";
    cin >> pages;

    if (check_number(pages) == false) {
        cout << "Invalid number of pages.\n\n";
        return;
    }

    js["title"] = title;
    js["author"] = author;
    js["genre"] = genre;
    js["publisher"] = publisher;
    js["page_count"] = pages;

    int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
    message = compute_post_request(HOST, access_route, payload_type, 
                    js.dump().c_str(), cookies, cookies_count, token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    
    if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
        cout << "The book has been added\n\n";
    } else if (strstr(response, "HTTP/1.1 403 Forbidden") != NULL) {
        cout << "Forbidden! Enter the library to add a book.\n\n";
    } else if (strstr(response, "HTTP/1.1 429 Too Many Requests") != NULL) {
        cout << "Too many requests. Please try again later.\n\n";
    } else {
        cout << "Something bad has happened. Please try again later.\n\n";
    }
    
    free(message);
    free(response);    
    close_connection(sockfd);
}

void delete_book(char** cookies, int &cookies_count, char *token) {
    char *message, *response;
    string id;
    cout << "id=";
    cin >> id;
            
    if (check_number(id) == false) {
        cout << "Invalid book id.\n\n";
        return;
    }

    string access_route = "/api/v1/tema/library/books/" + id;

    int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
    message = compute_delete_request(HOST, access_route.c_str(), NULL, cookies, 
                                                        cookies_count, token);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
        cout << "The book has been deleted\n\n";   
    } else if (strstr(response, "HTTP/1.1 403 Forbidden") != NULL) {
        cout << "Forbidden! Enter the library to delete a book.\n\n";
    } else if (strstr(response, "HTTP/1.1 404 Not Found") != NULL) {
        cout << "Wrong book id. No book was deleted.\n\n";
    } else {
        cout << "Something bad has happened. Please try again.\n\n";
    }
    
    free(message);
    free(response); 
    close_connection(sockfd);
}

void logout_user(char **cookies, int &cookies_count, char *token) {
    char *message, *response;
    char access_route[] = "/api/v1/tema/auth/logout";

    int sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
    message = compute_get_request(HOST, access_route, NULL, cookies, 
                                                cookies_count, NULL);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    if (strstr(response, "HTTP/1.1 200 OK") != NULL) {
        cout << "You have logged out.\n\n";
    } else if (strstr(response, "HTTP/1.1 400 Bad Request") != NULL) {
        cout << "You are not logged in.\n\n";
    } else {
        cout << "Something bad happened. Please try again.\n\n";
    }

    free(message);
    free(response);
    close_connection(sockfd);
}

int main(int argc, char *argv[])
{    
    char* token = NULL;
    int cookies_count = 0;
    char **cookies = (char**)malloc (1 * sizeof(char*));
    cookies[0] = NULL;
    string s;

    while (1) {
        cin >> s;
        if (s == "register") {
            register_user();
        } else if (s == "login") {
            login_user(cookies, cookies_count);
        } else if (s == "enter_library") {
            enter_library(cookies, cookies_count, token);
        } else if (s == "get_books") {
            get_books(cookies, cookies_count, token);
        } else if (s == "get_book") {
            get_book(cookies, cookies_count, token);
        } else if (s == "add_book") {
            add_book(cookies, cookies_count, token);
        } else if (s == "delete_book") {
            delete_book(cookies, cookies_count, token);
        } else if (s == "logout") {
            logout_user(cookies, cookies_count, token);
            free(cookies[0]);
            cookies[0] = NULL;
            cookies_count = 0;

            free(token);
            token = NULL;
        } else if (s == "exit") {
            break;
        } else {
            cout << "Invalid command. Try again.\n\n";
        }
    }

    if (token != NULL) {
        free(token);
    }

    if (cookies[0] != NULL) {
        free(cookies[0]);
    }

    free(cookies);
    return 0;
}
