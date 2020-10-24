# Makefile

CFLAGS = -Wall -g

# Adresa IP a clientului
ID_CLIENT = 1

# Portul pe care asculta serverul
PORT = 8080

# Adresa IP a serverului
IP_SERVER = 0.0.0.0

all: server subscriber

# Compileaza server.cpp
server: server.cpp

# Compileaza subscriber.cpp
subscriber: subscriber.cpp

.PHONY: clean run_server run_subscriber

# Ruleaza serverul
run_server:
	./server ${PORT}

# Ruleaza clientul
run_subscriber:
	./subscriber ${ID_CLIENT} ${IP_SERVER} ${PORT}

clean:
	rm -f server subscriber
