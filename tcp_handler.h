/*
 * tcp_handler.h
 *
 *  Created on: Dec 8, 2015
 *      Author: Praveen
 */

#ifndef TCP_HANDLER_H_
#define TCP_HANDLER_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

#define TOTAL_LAYERS  2
#define IP_LAYER_OFFSET  0
#define TCP_LAYER_OFFSET 1
#define PAYLOAD_OFFSET 2
#define CLIENT_PORT 35555
#define HTTP_PORT 80
#define RTAX_MAX 8
#define IP_OFFSET 0
#define TCP_OFFSET 1
#define DATA_OFFSET 2
#define MAX_BUFFER_SIZE 400
#define MAX_CLIENT_SEGMENT_SIZE 1460
#define CLIENT_WINDOW_SIZE 16384
#define WORD_LENGTH 4
#define PACKET_MAX_SIZE 16384
#define MAX_PAYLOAD_LEN (PACKET_MAX_SIZE - sizeof(struct iphdr) - sizeof(struct tcphdr))
#define MAX_CONGESTION_WINDOW_SIZE 1000

typedef enum
{
	SYN_SENT = 1,
	ESTABLISHED = 2,
	FIN_WAIT_1 = 4,
	FIN_WAIT_2 = 8,
	CLOSE_WAIT = 16,
	CLOSING = 32,
	LAST_ACK = 64,
	CLOSED = 128
} tcp_state_machine_t;

typedef struct
{
	uint8_t syn :1;
	uint8_t ack :1;
	uint8_t fin :1;
	uint8_t psh :1;
} tcp_flags_t;

typedef struct
{
	uint8_t option_type;
	uint8_t option_len;
	uint16_t option_value;
} tcp_options_t;

typedef struct
{
	char payload[PACKET_MAX_SIZE];
	char* offset[TOTAL_LAYERS + 1];
	timer_t retransmit_timer_id;
	uint16_t payload_len;
} packet_t;

typedef struct
{
	packet_t* packet;
	uint32_t packet_seq;
} buffered_packet_t;

typedef struct
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
} pseudo_header;

typedef struct
{
	struct sockaddr_in src_addr;
	struct sockaddr_in dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
	int send_fd;
	int recv_fd;
	pthread_mutex_t send_fd_lock;
} session_info__t;

typedef struct
{
	buffered_packet_t send_buffer[MAX_BUFFER_SIZE];
	uint16_t send_buffer_head;
	uint16_t send_buffer_tail;
	buffered_packet_t retx_buffer[MAX_BUFFER_SIZE];
	uint16_t retx_buffer_head;
	uint16_t retx_buffer_tail;
	pthread_mutex_t tcp_send_lock;
	pthread_mutex_t tcp_retx_lock;
	pthread_cond_t send_buffer_empty;
	pthread_cond_t send_buffer_full;
} tcp_send_data_t;

typedef struct
{
	buffered_packet_t recv_buffer[MAX_BUFFER_SIZE];
	uint16_t recv_buffer_head;
	uint16_t recv_buffer_tail;
	pthread_mutex_t tcp_recv_lock;
	pthread_cond_t recv_buffer_empty;
	pthread_cond_t recv_buffer_full;
} tcp_recv_data_t;

typedef struct
{
	session_info__t session_info;
	uint32_t client_next_seq_num;
	uint32_t last_acked_seq_num;
	uint32_t server_next_seq_num;
	uint16_t server_window_size;
	uint16_t client_window_size;
	uint16_t max_segment_size;
	uint16_t cwindow_size;
	uint16_t ssthresh;
	pthread_cond_t send_window_low_thresh;
	uint8_t syn_retries;
	tcp_send_data_t sender_info;
	tcp_recv_data_t recv_info;
	pthread_mutex_t tcp_state_lock;
	pthread_cond_t tcp_session_closed_notify;
	uint8_t tcp_write_end_closed;
	uint8_t tcp_read_end_closed;
	pthread_t tcp_worker_threads[2];
	tcp_state_machine_t tcp_current_state;
} tcp_state__t;

int connect_tcp(int send_fd, int recv_fd, struct sockaddr_in* dst_addr,
		struct sockaddr_in* src_addr);

int send_data(char* buffer, int buffer_len);

int receive_data(char* buffer, int buffer_len);

int close_tcp();

#endif /* TCP_HANDLER_H_ */
