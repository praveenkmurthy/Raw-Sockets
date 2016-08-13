CFLAGS= -g -Werror -lrt -lpthread 
CC=gcc

all:
	$(CC) $(CFLAGS) rawsocket_http.c routing_table.c tcp_handler.c -o rawhttpget

clean:
	rm -rf rawhttpget 
