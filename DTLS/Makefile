


CFLAGS      = -std=c99 -pedantic -Wall -g -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-overlength-strings
INCLUDES    = -I/usr/local/include
LFLAGS      = -L/usr/local/lib
LIBS        = -lssl -lcrypto -pthread -lm -ldl

all: echo
echo: echo_client echo_server

echo_client: echo_client.c
	$(CC) $(CFLAGS) $(INCLUDES) -o echo_client echo_client.c utils.c $(LFLAGS) $(LIBS)

echo_server: echo_server.c
	$(CC) $(CFLAGS) $(INCLUDES) -o echo_server echo_server.c utils.c $(LFLAGS) $(LIBS)


clean:
	rm -f echo_client
	rm -f echo_server
