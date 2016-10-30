/*
 * tcp_handler.c
 *
 *  Created on: Dec 8, 2015
 *      Author: Praveen
 */

#include "tcp_handler.h"

#define STARTING_SEQUENCE 1
#define TCP_WORD_LENGTH_WITH_NO_OPTIONS 5
#define HAS_TCP_OPTIONS(ptr) (ptr->doff > TCP_WORD_LENGTH_WITH_NO_OPTIONS)
#define TCP_OPTION_OFFSET(ptr) ((char*)ptr + (TCP_WORD_LENGTH_WITH_NO_OPTIONS * WORD_LENGTH))
#define TCP_OPTION_LENGTH(ptr) ((ptr->doff - TCP_WORD_LENGTH_WITH_NO_OPTIONS) * WORD_LENGTH)
#define END_OF_TCP_OPTION_CHECK(ptr) ((*ptr) == 0)
#define TCP_OPTIONS_LEN(ptr) ((ptr->doff - TCP_WORD_LENGTH_WITH_NO_OPTIONS) * WORD_LENGTH )
#define IS_NO_OPERATION(ptr) ((*ptr) == 1)
#define IS_MSS(ptr) ((*ptr) == 2)
#define OPTION_LENGTH(ptr) (*(ptr+1))
#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
#define TCP_OPTION_DATA_OFFSET 2

#define IS_DUPLICATE_TCP_SEGMENT(tcph) (ntohl(tcph->seq) < tcp_state.server_next_seq_num)
#define IS_DUPLICATE_ACK(tcph) (tcph->ack && (tcph->ack_seq == tcp_state.last_acked_seq_num) )
#define WRAP_ROUND_BUFFER_SIZE(index) \
		({ __typeof__ (index) _index = (index); \
		 ( _index + 1) > MAX_BUFFER_SIZE ? 0 : (_index + 1); })

tcp_state__t tcp_state;

/*
 Generic checksum calculation function
 */
static unsigned short csum(uint16_t *ptr, unsigned int nbytes)
{
	uint32_t sum;
	uint16_t answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		sum += *(unsigned char*) ptr;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short) ~sum;

	return (answer);
}

static void calculate_tcp_checksum(struct tcphdr* tcph,
		uint16_t tcp_payload_len, uint32_t src_addr, uint32_t dst_addr)
{
	pseudo_header psh;
	char* pseudogram;
	uint16_t tcphdr_len = (tcph->doff * WORD_LENGTH);

	// pseudoheader
	bzero(&psh, sizeof(pseudo_header));
	psh.source_address = src_addr;
	psh.dest_address = dst_addr;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(tcphdr_len + tcp_payload_len);

	int psize = sizeof(pseudo_header) + tcphdr_len + tcp_payload_len;
	pseudogram = malloc(psize);

	bzero(pseudogram, psize);
	memcpy(pseudogram, &psh, sizeof(pseudo_header));
	memcpy(pseudogram + sizeof(pseudo_header), tcph,
			tcphdr_len + tcp_payload_len);

	tcph->check = csum((uint16_t*) pseudogram, (unsigned int) psize);
	free(pseudogram);
}

static int validate_ip_checksum(struct iphdr* iph)
{
	int ret = -1;
	uint16_t received_checksum = iph->check;
	iph->check = 0;

	if (received_checksum
			== csum((uint16_t*) iph, (unsigned int) (iph->ihl * WORD_LENGTH)))
		ret = 1;

	return ret;
}

static int validate_tcp_checksum(struct tcphdr* tcph,
		uint16_t tcp_payload_length)
{
	int ret = -1;
	uint16_t received_checksum = tcph->check;
	tcph->check = 0;
	calculate_tcp_checksum(tcph, tcp_payload_length,
			*(uint32_t *) &tcp_state.session_info.dst_addr.sin_addr.s_addr,
			*(uint32_t *) &tcp_state.session_info.src_addr.sin_addr.s_addr);
	if (received_checksum == tcph->check)
		ret = 1;
	return ret;
}

static packet_t* create_packet()
{
	packet_t* packet = malloc(sizeof(packet_t));

	// send tcp syn
	bzero(packet, sizeof(packet_t));
	packet->offset[IP_OFFSET] = packet->payload;
	packet->offset[TCP_OFFSET] = packet->payload + sizeof(struct iphdr);
	packet->offset[DATA_OFFSET] = packet->payload + sizeof(struct tcphdr)
			+ sizeof(struct iphdr);
	packet->retransmit_timer_id = NULL;
	return packet;
}

static void adjust_layer_offset(packet_t* packet)
{
	struct tcphdr *tcph;
	struct iphdr *iph;

	iph = (struct iphdr *) packet->payload;
	tcph = (struct tcphdr *) (packet->payload + (iph->ihl * WORD_LENGTH));
	packet->offset[TCP_OFFSET] = (char*) tcph;
	packet->offset[DATA_OFFSET] = (char*) (packet->offset[TCP_OFFSET]
			+ (tcph->doff * WORD_LENGTH));
}

static void destroy_packet(packet_t* packet)
{
	if (packet->retransmit_timer_id != NULL)
		timer_delete(packet->retransmit_timer_id);

	free(packet);
}

static void remove_acked_entries(uint32_t next_expected_seq)
{
	pthread_mutex_lock(&tcp_state.sender_info.tcp_retx_lock);
	while ((tcp_state.sender_info.retx_buffer[tcp_state.sender_info.retx_buffer_head].packet_seq
			< next_expected_seq)
			&& !(tcp_state.sender_info.retx_buffer_head
					== tcp_state.sender_info.retx_buffer_tail))
	{
		destroy_packet(
				tcp_state.sender_info.retx_buffer[tcp_state.sender_info.retx_buffer_head].packet);
		tcp_state.sender_info.retx_buffer[tcp_state.sender_info.retx_buffer_head].packet =
		NULL;
		tcp_state.sender_info.retx_buffer_head =
		WRAP_ROUND_BUFFER_SIZE(tcp_state.sender_info.retx_buffer_head);
	}
	pthread_mutex_unlock(&tcp_state.sender_info.tcp_retx_lock);
}

static void reset_packet_retransmission_timer(timer_t* timer_id,
		uint16_t timeInSecs)
{
	struct itimerspec timer_value =
	{ 0 };
	timer_value.it_interval.tv_sec = timeInSecs;
	timer_value.it_value.tv_sec = timeInSecs;

	if (timer_settime(*timer_id, 0, &timer_value, NULL) < 0)
	{
		printf("Failed to set time!!");
		timer_delete(*timer_id);
		*timer_id = NULL;
	}
}

static void build_ip_header(struct iphdr* iph, uint16_t ip_payload_len)
{
	iph->daddr = *(uint32_t*) &tcp_state.session_info.dst_addr.sin_addr.s_addr;
	iph->saddr = *(uint32_t*) &tcp_state.session_info.src_addr.sin_addr.s_addr;
	iph->ihl = 5;
	iph->protocol = IPPROTO_TCP;
	iph->ttl = 255;
	iph->version = 4;
	iph->tot_len = sizeof(struct iphdr) + ip_payload_len;
	iph->check = csum((unsigned short*) iph, sizeof(struct iphdr));
}

static void build_tcp_header(struct tcphdr* tcph, tcp_flags_t* flags,
		uint16_t payload_len)
{
	tcph->dest = *(uint16_t*) &tcp_state.session_info.dst_addr.sin_port;
	tcph->source = *(uint16_t*) &tcp_state.session_info.src_addr.sin_port;
	tcph->window = htons(tcp_state.client_window_size);
	tcph->seq = htonl(tcp_state.client_next_seq_num);
	tcp_state.client_next_seq_num +=
			(flags->syn || flags->fin) ? 1 : payload_len;
	tcph->doff = (flags->syn) ? 6 : 5;
	tcph->syn = flags->syn;
	tcph->ack = flags->ack;
	tcph->fin = flags->fin;
	tcph->psh = flags->psh;
	tcph->ack_seq = htonl(tcp_state.server_next_seq_num);

	if (flags->syn)
	{
		char* tcp_options = ((char *) tcph) + sizeof(struct tcphdr);
		tcp_options_t mss =
		{ 0 };
		mss.option_type = 2;
		mss.option_len = 4;
		mss.option_value = htons(1460);
		memcpy(tcp_options++, &mss.option_type, sizeof(char));
		memcpy(tcp_options++, &mss.option_len, sizeof(char));
		memcpy(tcp_options, &mss.option_value, sizeof(uint16_t));
	}
}

static void build_packet_headers(packet_t* packet, int payload_len,
		tcp_flags_t* flags)
{
	struct tcphdr* tcph = (struct tcphdr*) packet->offset[TCP_OFFSET];
	struct iphdr* iph = (struct iphdr*) packet->offset[IP_OFFSET];

	build_tcp_header(tcph, flags, payload_len);
	calculate_tcp_checksum(tcph, payload_len,
			*(uint32_t *) &tcp_state.session_info.src_addr.sin_addr.s_addr,
			*(uint32_t *) &tcp_state.session_info.dst_addr.sin_addr.s_addr);
	build_ip_header(iph, ((tcph->doff * WORD_LENGTH) + payload_len));
}

static int send_packet(void *buffer, int total_packet_len)
{
	int ret = -1;

	pthread_mutex_lock(&tcp_state.session_info.send_fd_lock);
	while (total_packet_len > 0)
	{
		//Send the packet
		if ((ret = sendto(tcp_state.session_info.send_fd, buffer,
				total_packet_len, 0,
				(struct sockaddr *) &tcp_state.session_info.dst_addr,
				sizeof(struct sockaddr_in))) < 0)
		{
			if (errno == EINTR)
			{
				printf("Sendto() Interrupted!!");
				continue;
			}
			else
			{
				perror("sendto failed");
				goto EXIT;
			}
		}
		if (ret == total_packet_len)
			break;

		total_packet_len -= ret;
		buffer += ret;
	}

	EXIT: pthread_mutex_unlock(&tcp_state.session_info.send_fd_lock);
	return ret;
}

static void handle_packet_retransmission()
{
	packet_t* packet = NULL;
	pthread_mutex_lock(&tcp_state.sender_info.tcp_retx_lock);
	int index = tcp_state.sender_info.retx_buffer_head;
	while (index != tcp_state.sender_info.retx_buffer_tail)
	{
		packet = tcp_state.sender_info.retx_buffer[index].packet;
		reset_packet_retransmission_timer(&packet->retransmit_timer_id, 0);
		if (send_packet(packet->payload, packet->payload_len) < 0)
			printf("Failed to retransmit packet!!");
		reset_packet_retransmission_timer(&packet->retransmit_timer_id, 60);
		index++;
	}
	pthread_mutex_unlock(&tcp_state.sender_info.tcp_retx_lock);
}

static int send_ack_segment(uint8_t fin)
{
	int ret = -1;
	packet_t* packet = create_packet();
	tcp_flags_t flags =
	{ 0 };

	flags.ack = 1;
	flags.fin = fin;
	build_packet_headers(packet, 0, &flags);

	if ((ret = send_packet(&packet->payload,
			((struct iphdr*) packet->offset[IP_OFFSET])->tot_len)) < 0)
	{
		printf("Send error!! Exiting.. ");
	}

	EXIT: destroy_packet(packet);
	return ret;
}

static int receive_packet(packet_t *packet)
{
	int ret = -1;
	while (1)
	{
		if ((ret = recvfrom(tcp_state.session_info.recv_fd, &packet->payload,
				sizeof(packet->payload), 0,
				NULL, NULL)) < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				perror("recv failed");
				return ret;
			}

		}
		//Data received successfully
		struct iphdr *iph = (struct iphdr *) &packet->payload;
		if (validate_ip_checksum(iph) < 0)
		{
			printf("IP Checksum validation failed!! Packet dropped!!\n");
			continue;
		}

		uint16_t iphdr_len = iph->ihl * WORD_LENGTH;
		struct tcphdr *tcph = (struct tcphdr *) ((char*) iph + iphdr_len);
		uint16_t tcphdr_len = tcph->doff * WORD_LENGTH;

		if (iph->saddr != tcp_state.session_info.dst_addr.sin_addr.s_addr
				&& tcph->dest != tcp_state.session_info.src_port
				&& tcph->source != tcp_state.session_info.dst_port)
			continue;

		if (validate_tcp_checksum(tcph,
				(ntohs(iph->tot_len) - iphdr_len - tcphdr_len)) < 0)
		{
			printf("TCP Checksum validation failed!! Packet dropped!!\n");
			continue;
		}

		if ( IS_DUPLICATE_ACK(tcph))
		{
			handle_packet_retransmission();
			continue;
		}
		else if ( IS_DUPLICATE_TCP_SEGMENT(tcph))
		{
			send_ack_segment(0);
			continue;
		}

		adjust_layer_offset(packet);
		packet->payload_len = (ntohs(iph->tot_len) - iphdr_len - tcphdr_len);
		break;
	}
	return ret;
}

static void process_ack(struct tcphdr *tcph, uint16_t payload_len)
{
	tcp_state.server_next_seq_num = (ntohl(tcph->seq) + payload_len);
	tcp_state.last_acked_seq_num = (ntohl(tcph->ack_seq));

	pthread_mutex_lock(&tcp_state.tcp_state_lock);
	tcp_state.server_window_size = ntohs(tcph->window);
	tcp_state.cwindow_size =
			(++tcp_state.cwindow_size > MAX_CONGESTION_WINDOW_SIZE) ?
					MAX_CONGESTION_WINDOW_SIZE : tcp_state.cwindow_size;
	pthread_cond_signal(&tcp_state.send_window_low_thresh);
	pthread_mutex_unlock(&tcp_state.tcp_state_lock);

	remove_acked_entries(ntohl(tcph->ack_seq));

	if (HAS_TCP_OPTIONS(tcph))
	{
		char* tcp_options_offset = (char*) TCP_OPTION_OFFSET(tcph);
		uint16_t total_options_len = TCP_OPTIONS_LEN(tcph);

		while (!END_OF_TCP_OPTION_CHECK(tcp_options_offset)
				&& total_options_len > 0)
		{
			if ( IS_NO_OPERATION(tcp_options_offset))
			{
				tcp_options_offset++;
				total_options_len--;
			}
			else if ( IS_MSS(tcp_options_offset))
			{
				tcp_state.max_segment_size =
						min(tcp_state.max_segment_size,
								*((uint16_t*)(tcp_options_offset+TCP_OPTION_DATA_OFFSET)));
				tcp_options_offset += OPTION_LENGTH(tcp_options_offset);
				total_options_len -= OPTION_LENGTH(tcp_options_offset);
			}
			else
			{
				tcp_options_offset += OPTION_LENGTH(tcp_options_offset);
				total_options_len -= OPTION_LENGTH(tcp_options_offset);
			}
		}
	}
}

static void retransmission_timer_handler(union sigval value)
{
	int buffer_index = value.sival_int;
	packet_t* packet = NULL;

	pthread_mutex_lock(&tcp_state.tcp_state_lock);
	tcp_state.cwindow_size = 1;
	pthread_mutex_unlock(&tcp_state.tcp_state_lock);

	pthread_mutex_lock(&tcp_state.sender_info.tcp_retx_lock);

	if (tcp_state.sender_info.retx_buffer[buffer_index].packet == NULL
			|| buffer_index < tcp_state.sender_info.retx_buffer_head)
		goto EXIT;

	packet = tcp_state.sender_info.retx_buffer[buffer_index].packet;
	if (send_packet(&packet->payload,
			((struct iphdr*) packet->offset[IP_OFFSET])->tot_len) < 0)
	{
		printf("Failed to retransmit packet!!\n");
	}

	EXIT: pthread_mutex_unlock(&tcp_state.sender_info.tcp_retx_lock);
}

void create_retransmission_timer(timer_t* timer, int send_buffer_index)
{
	union sigval val;
	struct sigevent sev;
	struct itimerspec timer_value =
	{ 0 };

	memset(&val, 0, sizeof(val));
	memset(&sev, 0, sizeof(sev));
	val.sival_int = send_buffer_index;
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_value = val;
	sev.sigev_notify_function = retransmission_timer_handler;

	if (timer_create(CLOCK_MONOTONIC, &sev, timer) < 0)
	{
		printf("Failed to create the retransmission timer!!");
		*timer = NULL;
		goto EXIT;
	}

	timer_value.it_interval.tv_sec = 60;
	timer_value.it_value.tv_sec = 60;

	if (timer_settime(*timer, 0, &timer_value, NULL) < 0)
	{
		printf("Failed to set time!!");
		timer_delete(*timer);
		*timer = NULL;
	}

	EXIT: return;
}

static int send_tcp_segment(packet_t* packet)
{
	int ret = 0;

	if ((ret = send_packet(&packet->payload,
			((struct iphdr*) packet->offset[IP_OFFSET])->tot_len)) < 0)
	{
		printf("Send error!! Exiting.. ");
		goto EXIT;
	}

	create_retransmission_timer(&packet->retransmit_timer_id,
			tcp_state.sender_info.retx_buffer_tail);

	pthread_mutex_lock(&tcp_state.sender_info.tcp_retx_lock);

	tcp_state.sender_info.retx_buffer[tcp_state.sender_info.retx_buffer_tail].packet_seq =
			((struct tcphdr*) &packet->offset[TCP_OFFSET])->seq;
	tcp_state.sender_info.retx_buffer[tcp_state.sender_info.retx_buffer_tail].packet =
			packet;
	tcp_state.sender_info.retx_buffer_tail =
	WRAP_ROUND_BUFFER_SIZE(tcp_state.sender_info.retx_buffer_tail);

	pthread_mutex_unlock(&tcp_state.sender_info.tcp_retx_lock);

	EXIT: return ret;
}

static int send_syn()
{
	int ret = -1;
	packet_t* packet = create_packet();
	tcp_flags_t flags =
	{ 0 };

	flags.syn = 1;
	build_packet_headers(packet, 0, &flags);
	tcp_state.tcp_current_state = SYN_SENT;

	return send_tcp_segment(packet);
}

static int receive_syn_ack_segment(tcp_flags_t* flags)
{
	int ret = -1;
	packet_t* packet = create_packet();
	struct tcphdr *tcph;

	while (1)
	{
		if ((ret = receive_packet(packet)) < 0)
		{
			printf("Receive error!! Exiting.. ");
			goto EXIT;
		}

		tcph = (struct tcphdr *) packet->offset[TCP_OFFSET];

		if (tcph->ack == flags->ack && tcph->syn == flags->syn)
			break;

		if (tcph->rst || !tcp_state.syn_retries)
		{
			ret = -1;
			goto EXIT;
		}
	}

	process_ack(tcph, 1);

	EXIT: destroy_packet(packet);
	return ret;
}

static int initialize_mutex(pthread_mutex_t* mutex)
{
	int ret = -1;
	pthread_mutexattr_t mutex_attr;

	if ((ret = pthread_mutexattr_init(&mutex_attr)) != 0)
	{
		printf("Failed to initialize mutex attribute\n");
		ret = -1;
		goto EXIT;
	}

	if ((ret = pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE))
			!= 0)
	{
		printf("Failed to set mutex attribute\n");
		ret = -1;
		goto EXIT;
	}

	if ((ret = pthread_mutex_init(mutex, &mutex_attr)) != 0)
	{
		printf("Failed to initialize mutex!!\n");
		ret = -1;
	}

	EXIT: return ret;
}

static void get_wait_time(struct timespec* timeToWait, uint16_t timeInSeconds)
{
	struct timeval now;
	int rt;

	gettimeofday(&now, NULL);

	timeToWait->tv_sec = now.tv_sec + timeInSeconds;
	timeToWait->tv_nsec = 0;
}

static void* tcp_send_handler(void* args)
{
	int ret = 0;
	packet_t* packet = NULL;
	struct timespec timeToWait;

	while (1)
	{
		pthread_mutex_lock(&tcp_state.tcp_state_lock);
		if (tcp_state.tcp_write_end_closed)
		{
			pthread_mutex_unlock(&tcp_state.tcp_state_lock);
			break;
		}
		pthread_mutex_unlock(&tcp_state.tcp_state_lock);

		get_wait_time(&timeToWait, 5);
		pthread_mutex_lock(&tcp_state.sender_info.tcp_send_lock);

		if (tcp_state.sender_info.send_buffer_head
				== tcp_state.sender_info.send_buffer_tail)
		{
			if ((ret = pthread_cond_timedwait(
					&tcp_state.sender_info.send_buffer_empty,
					&tcp_state.sender_info.tcp_send_lock, &timeToWait)) != 0)
			{
				pthread_mutex_unlock(&tcp_state.sender_info.tcp_send_lock);

				if (ret == ETIMEDOUT)
					continue;
				else
					break;
			}
		}

		packet =
				tcp_state.sender_info.send_buffer[tcp_state.sender_info.send_buffer_head].packet;
		tcp_state.sender_info.send_buffer[tcp_state.sender_info.send_buffer_head].packet =
		NULL;
		tcp_state.sender_info.send_buffer_head = WRAP_ROUND_BUFFER_SIZE(
				tcp_state.sender_info.send_buffer_head);
		pthread_cond_signal(&tcp_state.sender_info.send_buffer_full);

		pthread_mutex_unlock(&tcp_state.sender_info.tcp_send_lock);

		pthread_mutex_lock(&tcp_state.tcp_state_lock);
		uint16_t cwind_size_bytes = tcp_state.cwindow_size
				* tcp_state.max_segment_size;
		if (packet->payload_len
				> min(cwind_size_bytes, tcp_state.server_window_size))
		{
			while (1)
			{
				get_wait_time(&timeToWait, 5);
				if ((ret = pthread_cond_timedwait(
						&tcp_state.send_window_low_thresh,
						&tcp_state.tcp_state_lock, &timeToWait)) != 0)
				{
					if (ret == ETIMEDOUT)
						continue;
					else
						break;
				}
			}
		}
		pthread_mutex_unlock(&tcp_state.tcp_state_lock);

		if (send_tcp_segment(packet) < 0)
			printf("TCP Segment Failed to send!!!");

	}

	return NULL;
}

static void handle_received_data(packet_t* packet)
{
	pthread_mutex_lock(&tcp_state.tcp_state_lock);
	tcp_state.client_window_size -= packet->payload_len;
	tcp_state.client_window_size =
			(tcp_state.client_window_size < 0) ?
					0 : tcp_state.client_window_size;
	pthread_mutex_unlock(&tcp_state.tcp_state_lock);

	pthread_mutex_lock(&tcp_state.recv_info.tcp_recv_lock);

	tcp_state.recv_info.recv_buffer[tcp_state.recv_info.recv_buffer_tail].packet =
			packet;
	pthread_cond_signal(&tcp_state.recv_info.recv_buffer_empty);

	if ( WRAP_ROUND_BUFFER_SIZE(tcp_state.recv_info.recv_buffer_tail)
			== tcp_state.recv_info.recv_buffer_head)
		pthread_cond_wait(&tcp_state.recv_info.recv_buffer_full,
				&tcp_state.recv_info.tcp_recv_lock);

	tcp_state.recv_info.recv_buffer_tail =
	WRAP_ROUND_BUFFER_SIZE(tcp_state.recv_info.recv_buffer_tail);

	pthread_mutex_unlock(&tcp_state.recv_info.tcp_recv_lock);

}

static void* tcp_recv_handler(void* args)
{
	packet_t* packet = NULL;
	struct tcphdr* tcph = NULL;
	struct iphdr* iph = NULL;
	int ret = 0;

	while (1)
	{
		packet = create_packet();
		if ((ret = receive_packet(packet)) < 0)
		{
			printf("Receive error!! Exiting.. ");
			continue;
		}

		tcph = (struct tcphdr*) packet->offset[TCP_OFFSET];
		iph = (struct iphdr*) packet->offset[IP_OFFSET];

		if (ntohl(tcph->seq) != (tcp_state.server_next_seq_num))
		{
			send_ack_segment(0);
			destroy_packet(packet);
			continue;
		}

		uint16_t payload_len = ntohs(iph->tot_len) - (iph->ihl * WORD_LENGTH)
				- (tcph->doff * WORD_LENGTH);

		if (tcph->rst)
		{
			send_ack_segment(0);

			pthread_mutex_lock(&tcp_state.tcp_state_lock);
			tcp_state.tcp_read_end_closed = 1;
			tcp_state.tcp_write_end_closed = 1;
			tcp_state.tcp_current_state = CLOSED;
			pthread_mutex_unlock(&tcp_state.tcp_state_lock);

			break;
		}

		if (packet->payload_len)
			handle_received_data(packet);

		if (tcph->fin && (tcp_state.tcp_current_state & ESTABLISHED))
		{
			pthread_mutex_lock(&tcp_state.tcp_state_lock);
			process_ack(tcph, 1);
			send_ack_segment(0);
			tcp_state.tcp_current_state = CLOSE_WAIT;
			tcp_state.tcp_read_end_closed = 1;
			pthread_mutex_unlock(&tcp_state.tcp_state_lock);
			continue;
		}
		else if (tcph->fin && tcph->ack
				&& (tcp_state.tcp_current_state & FIN_WAIT_1))
		{
			pthread_mutex_lock(&tcp_state.tcp_state_lock);
			process_ack(tcph, 1);
			send_ack_segment(0);
			tcp_state.tcp_read_end_closed = 1;
			tcp_state.tcp_current_state = CLOSED;
			pthread_cond_signal(&tcp_state.tcp_session_closed_notify);
			pthread_mutex_unlock(&tcp_state.tcp_state_lock);
			break;
		}
		else if (tcph->fin && (tcp_state.tcp_current_state & FIN_WAIT_1))
		{
			pthread_mutex_lock(&tcp_state.tcp_state_lock);
			process_ack(tcph, 1);
			send_ack_segment(0);
			tcp_state.tcp_read_end_closed = 1;
			tcp_state.tcp_current_state = CLOSING;
			pthread_mutex_unlock(&tcp_state.tcp_state_lock);
			continue;
		}
		else if (tcph->fin && (tcp_state.tcp_current_state & FIN_WAIT_2))
		{
			pthread_mutex_lock(&tcp_state.tcp_state_lock);
			process_ack(tcph, 1);
			send_ack_segment(0);
			tcp_state.tcp_read_end_closed = 1;
			tcp_state.tcp_current_state = CLOSED;
			pthread_cond_signal(&tcp_state.tcp_session_closed_notify);
			pthread_mutex_unlock(&tcp_state.tcp_state_lock);
			break;
		}

		process_ack(tcph, payload_len);

		if (packet->payload_len == 0)
		{
			destroy_packet(packet);

			pthread_mutex_lock(&tcp_state.tcp_state_lock);
			if ((tcp_state.tcp_current_state & CLOSING)
					|| (tcp_state.tcp_current_state & LAST_ACK))
			{
				tcp_state.tcp_current_state = CLOSED;
				pthread_cond_signal(&tcp_state.tcp_session_closed_notify);
				pthread_mutex_unlock(&tcp_state.tcp_state_lock);
				break;
			}

			if (tcp_state.tcp_current_state & FIN_WAIT_1)
				tcp_state.tcp_current_state = FIN_WAIT_2;

			pthread_mutex_unlock(&tcp_state.tcp_state_lock);
			continue;
		}

		send_ack_segment(0);
	}

	return NULL;
}

static int create_worker_threads()
{
	pthread_attr_t attr;
	int ret = 0;

	if ((ret = pthread_attr_init(&attr)) != 0)
	{
		printf("pthread attribute initialization failed!!");
		ret = -1;
		goto EXIT;
	}

	if ((ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
			!= 0)
	{
		printf("pthread attribute set detached failed!!");
		ret = -1;
		goto EXIT;
	}

	initialize_mutex(&tcp_state.sender_info.tcp_send_lock);
	initialize_mutex(&tcp_state.sender_info.tcp_retx_lock);
	if ((ret = pthread_create(&tcp_state.tcp_worker_threads[0], &attr,
			&tcp_send_handler, NULL)) != 0)
	{
		printf("pthread creation failed!!");
		ret = -1;
		goto EXIT;
	}

	initialize_mutex(&tcp_state.recv_info.tcp_recv_lock);
	if ((ret = pthread_create(&tcp_state.tcp_worker_threads[1], &attr,
			&tcp_recv_handler, NULL)) != 0)
	{
		printf("pthread creation failed!!");
		ret = -1;
		goto EXIT;
	}

	EXIT: return ret;
}

//Blocking call
int connect_tcp(int send_fd, int recv_fd, struct sockaddr_in* dst_addr,
		struct sockaddr_in* src_addr)
{
	int ret = 0;

// Initialize the TCP Session State with the given details
	bzero(&tcp_state, sizeof(tcp_state__t));
	tcp_state.max_segment_size = MAX_CLIENT_SEGMENT_SIZE;
	tcp_state.client_window_size = CLIENT_WINDOW_SIZE;
	tcp_state.client_next_seq_num = STARTING_SEQUENCE;
	tcp_state.session_info.dst_addr = *dst_addr;
	tcp_state.session_info.src_addr = *src_addr;
	tcp_state.session_info.recv_fd = recv_fd;
	tcp_state.session_info.send_fd = send_fd;
	tcp_state.syn_retries = 5;
	tcp_state.cwindow_size = 1;
	initialize_mutex(&tcp_state.tcp_state_lock);
	initialize_mutex(&tcp_state.session_info.send_fd_lock);

	tcp_flags_t flags =
	{ 0 };
	flags.ack = 1;
	flags.syn = 1;
	if (((ret = send_syn()) < 0)
			|| ((ret = receive_syn_ack_segment(&flags)) < 0) || ((ret =
					send_ack_segment(0)) < 0))
	{
		printf("Failed to set up TCP Connection!!");
		ret = -1;
		goto EXIT;
	}

	tcp_state.tcp_current_state = ESTABLISHED;

	if (((ret = create_worker_threads()) < 0))
	{
		printf("Failed to create worker threads!!\n");
		ret = -1;
	}

	EXIT: return ret;
}

static int send_fin()
{
	int ret = -1;
	packet_t* packet = create_packet();
	tcp_flags_t flags =
	{ 0 };

	flags.fin = 1;
	flags.ack = 1;
	build_packet_headers(packet, 0, &flags);

	return send_tcp_segment(packet);
}

int close_tcp()
{
	int ret = -1;
	pthread_mutex_lock(&tcp_state.tcp_state_lock);
	if (!((tcp_state.tcp_current_state & ESTABLISHED)
			|| (tcp_state.tcp_current_state & CLOSE_WAIT)))
	{
		pthread_mutex_unlock(&tcp_state.tcp_state_lock);
		goto EXIT;
	}
	pthread_mutex_unlock(&tcp_state.tcp_state_lock);

	if ((ret = send_fin()) < 0)
		goto EXIT;

	struct timespec timeToWait;
	get_wait_time(&timeToWait, 10);

	pthread_mutex_lock(&tcp_state.tcp_state_lock);

	if (tcp_state.tcp_current_state & ESTABLISHED)
		tcp_state.tcp_current_state = FIN_WAIT_1;
	else
		tcp_state.tcp_current_state = LAST_ACK;

	tcp_state.tcp_write_end_closed = 1;
	pthread_cond_timedwait(&tcp_state.tcp_session_closed_notify,
			&tcp_state.tcp_state_lock, &timeToWait);

	pthread_mutex_unlock(&tcp_state.tcp_state_lock);

	EXIT: return ret;
}

int send_data(char* buffer, int buffer_len)
{
	int ret = 0;
	int total_bytes_to_be_sent = buffer_len;
	tcp_flags_t flags =
	{ 0 };
	flags.psh = 1;
	flags.ack = 1;

	while (total_bytes_to_be_sent > 0)
	{
		pthread_mutex_lock(&tcp_state.tcp_state_lock);
		if (tcp_state.tcp_write_end_closed)
		{
			printf("TCP Client Closed!!\n");
			ret = -1;
			pthread_mutex_unlock(&tcp_state.tcp_state_lock);
			break;
		}
		pthread_mutex_unlock(&tcp_state.tcp_state_lock);

		packet_t* packet = create_packet();
		packet->payload_len =
				total_bytes_to_be_sent > tcp_state.max_segment_size ?
						tcp_state.max_segment_size : total_bytes_to_be_sent;

		memcpy(packet->offset[DATA_OFFSET], buffer, packet->payload_len);
		build_packet_headers(packet, packet->payload_len, &flags);
		total_bytes_to_be_sent -= packet->payload_len;
		ret += packet->payload_len;

		pthread_mutex_lock(&tcp_state.sender_info.tcp_send_lock);

		tcp_state.sender_info.send_buffer[tcp_state.sender_info.send_buffer_tail].packet =
				packet;
		pthread_cond_signal(&tcp_state.sender_info.send_buffer_empty);

		if (WRAP_ROUND_BUFFER_SIZE(tcp_state.sender_info.send_buffer_tail)
				== tcp_state.sender_info.send_buffer_head)
			pthread_cond_wait(&tcp_state.sender_info.send_buffer_full,
					&tcp_state.sender_info.tcp_send_lock);

		tcp_state.sender_info.send_buffer_tail =
		WRAP_ROUND_BUFFER_SIZE(tcp_state.sender_info.send_buffer_tail);

		pthread_mutex_unlock(&tcp_state.sender_info.tcp_send_lock);

	}

	EXIT: return ret;
}

static void release_and_update_recv_buffer(packet_t* packet)
{
	pthread_mutex_lock(&tcp_state.recv_info.tcp_recv_lock);

	tcp_state.recv_info.recv_buffer[tcp_state.recv_info.recv_buffer_head].packet =
	NULL;
	tcp_state.recv_info.recv_buffer_head =
	WRAP_ROUND_BUFFER_SIZE(tcp_state.recv_info.recv_buffer_head);
	destroy_packet(packet);
	pthread_cond_signal(&tcp_state.recv_info.recv_buffer_full);

	pthread_mutex_unlock(&tcp_state.recv_info.tcp_recv_lock);

}

int receive_data(char* buffer, int buffer_len)
{
	int total_bytes_read = 0, ret = -1;
	packet_t* packet = NULL;
	struct timespec timeToWait;

	while (buffer_len > 0)
	{
		get_wait_time(&timeToWait, 5);

		pthread_mutex_lock(&tcp_state.recv_info.tcp_recv_lock);
		if (tcp_state.recv_info.recv_buffer_head
				== tcp_state.recv_info.recv_buffer_tail)
		{
			if (total_bytes_read > 0)
			{
				pthread_mutex_unlock(&tcp_state.recv_info.tcp_recv_lock);
				break;
			}
			else
			{
				if ((ret = pthread_cond_timedwait(
						&tcp_state.recv_info.recv_buffer_empty,
						&tcp_state.recv_info.tcp_recv_lock, &timeToWait)) != 0)
				{
					pthread_mutex_unlock(&tcp_state.recv_info.tcp_recv_lock);
					if (ret == ETIMEDOUT)
					{
						pthread_mutex_lock(&tcp_state.tcp_state_lock);
						if (tcp_state.tcp_read_end_closed)
						{
							printf("TCP Server Closed!!\n");
							total_bytes_read = -1;
							pthread_mutex_unlock(&tcp_state.tcp_state_lock);
							break;
						}
						pthread_mutex_unlock(&tcp_state.tcp_state_lock);
						continue;
					}
					else
						break;
				}
			}
		}

		packet =
				tcp_state.recv_info.recv_buffer[tcp_state.recv_info.recv_buffer_head].packet;
		pthread_mutex_unlock(&tcp_state.recv_info.tcp_recv_lock);

		int copied_bytes = 0;
		if (packet->payload_len > buffer_len)
		{
			printf("CHUNKED TRANSFER: %d:%d\n", packet->payload_len,
					buffer_len);
			memcpy((buffer + total_bytes_read), packet->offset[DATA_OFFSET],
					buffer_len);
			packet->offset[DATA_OFFSET] += buffer_len;
			packet->payload_len -= buffer_len;
			total_bytes_read += buffer_len;
			copied_bytes = buffer_len;
			buffer_len = 0;
		}
		else
		{
			memcpy((buffer + total_bytes_read), packet->offset[DATA_OFFSET],
					packet->payload_len);
			buffer_len -= packet->payload_len;
			total_bytes_read += packet->payload_len;
			copied_bytes = packet->payload_len;
			release_and_update_recv_buffer(packet);
		}

		pthread_mutex_lock(&tcp_state.tcp_state_lock);
		tcp_state.client_window_size += copied_bytes;
		tcp_state.client_window_size =
				(tcp_state.client_window_size > CLIENT_WINDOW_SIZE) ?
						CLIENT_WINDOW_SIZE : tcp_state.client_window_size;
		pthread_mutex_unlock(&tcp_state.tcp_state_lock);
	}

	return total_bytes_read;
}
