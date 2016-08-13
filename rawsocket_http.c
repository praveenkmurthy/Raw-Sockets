#include "routing_table.h"
#include "tcp_handler.h"
#include <ctype.h>
#include <fcntl.h>

#define WRITE_BUFFER_SIZE 2048
#define RECV_BUFFER_LENGTH 32768
#define REQ_LENGTH 256
#define HAS_COMPLETE_HEADER(ptr) (strstr(ptr, "\r\n\r\n"))
#define IS_2XX_RESPONSE(ptr) (strstr(ptr, "200"))
#define IS_3XX_RESPONSE(ptr) (strstr(ptr, "302"))
#define STRIP_LEADING_NEWLINE_CHAR(ptr) \
	while(*ptr == '\n') \
		ptr++;
#define STRIP_LEADING_WHITESPACES(ptr) \
	while(*ptr == ' ') \
		ptr++;
#define STRIP_TRAILING_CARRIAGE_RETURN(ptr) (ptr[strlen(ptr)-1] = '\0')

char* stoupper(char* s)
{
	char* p = s;
	while (*p = toupper(*p))
		p++;
	return s;
}

void parseUrlInfo(char* url, char* dst_addr, char* get_request_url,
		char* dst_filename)
{
	char* tokenizer;
	char* rest_of_string;

	if (strstr(url, "http://") == NULL)
	{
		printf("Incorrect URL, Exiting\n");
		exit(1);
	}

	tokenizer = strtok((strstr(url, "http://") + 7), "/");
	strncpy(dst_addr, tokenizer, REQ_LENGTH);

	rest_of_string = (tokenizer + strlen(tokenizer) + 1);
	strncat(get_request_url, "/", REQ_LENGTH);
	strncat(get_request_url, rest_of_string, REQ_LENGTH);

	tokenizer = strtok( NULL, "/");
	if (tokenizer == NULL)
	{
		bzero(get_request_url, REQ_LENGTH);
		strcat(get_request_url, "/");
	}

	while (tokenizer != NULL)
	{
		rest_of_string = (tokenizer + strlen(tokenizer) + 1);
		memcpy(dst_filename, tokenizer, strlen(tokenizer));
		dst_filename[strlen(tokenizer)] = '\0';
		tokenizer = strtok(NULL, "/");
	}
}

int process_html_chunked_response(char* response, int res_len, FILE* file_fd,
		int* resp_offset, char* ret_buffer)
{
	int end_of_response = 0, total_payload_processed = 0;
	char* end_of_string;
	char* tmp_response = malloc((RECV_BUFFER_LENGTH + 1) * sizeof(char));
	char build_response[RECV_BUFFER_LENGTH + 1] =
	{ 0 };
	int chunk_size = 0, payload_size = 0;
	char *tokenizer = NULL;

	memset(tmp_response, 0, (RECV_BUFFER_LENGTH + 1));
	memcpy(tmp_response, response, res_len);
	if ((end_of_string = strstr(tmp_response, "\r\n")) != NULL)
	{
		*end_of_string = '\0';
		tokenizer = tmp_response;
	}

	while (tokenizer != NULL && total_payload_processed <= res_len)
	{
		total_payload_processed += (strlen(tokenizer) + 2);
		chunk_size = strtol(tokenizer, NULL, 16);

		if (chunk_size == 0)
		{
			end_of_response = 1;
			break;
		}

		if (chunk_size > (res_len - total_payload_processed))
		{
			memset(ret_buffer, 0, RECV_BUFFER_LENGTH + 1);
			memcpy(ret_buffer, tokenizer, strlen(tokenizer));
			ret_buffer[strlen(tokenizer)] = '\r';
			ret_buffer[strlen(tokenizer) + 1] = '\n';
			memcpy((ret_buffer + strlen(tokenizer) + 2),
					(tokenizer + strlen(tokenizer) + 2),
					(res_len - total_payload_processed));

			*resp_offset = strlen(tokenizer)
					+ (res_len - total_payload_processed) + 2;
			break;
		}

		tokenizer += strlen(tokenizer) + 2;

		total_payload_processed += (chunk_size + 2);
		memcpy((build_response + payload_size), tokenizer, chunk_size);
		payload_size += chunk_size;
		tokenizer = (tokenizer + chunk_size + 2);
		if ((end_of_string = strstr(tokenizer, "\r\n")) != NULL)
			*end_of_string = '\0';
		else
			tokenizer = NULL;
	}

	if ((res_len - total_payload_processed) > 0 && tokenizer == NULL)
	{
		memset(ret_buffer, 0, RECV_BUFFER_LENGTH + 1);
		memcpy(ret_buffer, &tmp_response[total_payload_processed],
				(res_len - total_payload_processed));
		*resp_offset = (res_len - total_payload_processed);
	}
	else if ((res_len - total_payload_processed) == 0 && tokenizer == NULL)
	{
		memset(ret_buffer, 0, RECV_BUFFER_LENGTH + 1);
		*resp_offset = 0;
	}

	process_html_response(build_response, payload_size, file_fd);

	free(tmp_response);
	return end_of_response;
}

int process_html_response(char* response, int res_len, FILE* file_fd)
{
	int ret = 0;
	char* test = response;
	int write_buffer_size = 0;

	while (res_len > 0)
	{
		write_buffer_size =
				(res_len > WRITE_BUFFER_SIZE) ? WRITE_BUFFER_SIZE : res_len;

		if ((ret = fwrite(response, write_buffer_size, 1, file_fd)) <= 0)
		{
			printf("Failed to write to file!!\n");
		}

		res_len -= write_buffer_size;
		response += write_buffer_size;
	}

	fflush(file_fd);
	return 0;
}

int process_header(char* response, int response_len)
{
	int ret = 0;
	int content_len = 0;
	char* dup_response = strdup(response);
	char* tmp_buffer = dup_response;
	char* tmp_str;

	tmp_str = strtok(tmp_buffer, "\r");
	while (tmp_str != NULL)
	{
		stoupper(tmp_str);
		if (strstr(tmp_str, "CONTENT-LENGTH"))
		{
			STRIP_LEADING_NEWLINE_CHAR(tmp_str);
			tmp_str = strtok(tmp_str, ":");
			tmp_str = strtok(NULL, "\r");
			STRIP_LEADING_WHITESPACES(tmp_str);
			content_len = strtol(tmp_str, NULL, 10);
			break;
		}
		else if (!strcmp(tmp_str, "\n"))
			break;

		tmp_str = strtok(NULL, "\r");
	}

	free(dup_response);
	return content_len;
}

void process_3XX_response(char* response, int response_len, char* ret_buffer,
		uint16_t ret_buffer_len)
{
	char* dup_response = strdup(response);
	char* tmp_buffer = dup_response;
	char* tmp_str;

	tmp_str = strtok(tmp_buffer, "\r");
	while (tmp_str != NULL)
	{
		stoupper(tmp_str);
		if (strstr(tmp_str, "LOCATION"))
		{
			STRIP_LEADING_NEWLINE_CHAR(tmp_str);
			tmp_str = strtok(tmp_str, ":");
			tmp_str = strtok(NULL, "\r");
			STRIP_LEADING_WHITESPACES(tmp_str);
			strncpy(ret_buffer, tmp_str, ret_buffer_len);
			break;
		}
		tmp_str = strtok(NULL, "\r");
	}

	free(dup_response);
}

void handle_http_response(FILE* file_fd, char* ret_buffer,
		uint16_t ret_buffer_len)
{
	int content_length = 0, process_response_hdr = 1, recv_offset = 0,
			resp_offset = 0, total_bytes_read = 0, ret = 0,
			chunked_transfer = 0, end_of_chunked_response = 0;
	char recv_buffer[RECV_BUFFER_LENGTH + 1] =
	{ 0 };

	do
	{
		if ((ret = receive_data(&recv_buffer[recv_offset],
				(RECV_BUFFER_LENGTH - recv_offset))) < 0)
		{
			printf("Failed to read the data!!\n");
			goto EXIT;
		}
		total_bytes_read += ret;
		if (process_response_hdr)
		{
			if (!HAS_COMPLETE_HEADER(recv_buffer))
			{
				recv_offset = ret;
				continue;
			}

			if (!IS_2XX_RESPONSE(recv_buffer))
			{
				if (IS_3XX_RESPONSE(recv_buffer))
				{
					process_3XX_response(recv_buffer, total_bytes_read,
							ret_buffer, ret_buffer_len);
					goto EXIT;
				}
				printf(
						"Received response other than 200 OR 302 Response!! Exiting!!\n");
				break;
			}

			content_length = process_header(recv_buffer, ret);
			if (content_length == 0)
				chunked_transfer = 1;

			process_response_hdr = 0;
			resp_offset = (int) (strstr(recv_buffer, "\r\n\r\n") - recv_buffer)
					+ 4;
		}

		if (chunked_transfer)
		{
			end_of_chunked_response = process_html_chunked_response(
					&recv_buffer[resp_offset], (total_bytes_read - resp_offset),
					file_fd, &recv_offset, recv_buffer);
			total_bytes_read = recv_offset;

		}
		else
		{
			if (process_html_response(&recv_buffer[resp_offset],
					(total_bytes_read - resp_offset), file_fd) < 0)
			{
				printf("Failed to process html response!!\n");
				break;
			}
			content_length -= (total_bytes_read - resp_offset);
			recv_offset = 0;
			bzero(&recv_buffer, sizeof(recv_buffer));
			total_bytes_read = 0;
		}

		resp_offset = 0;
	} while (content_length > 0
			|| (chunked_transfer && !end_of_chunked_response));

	EXIT: return;
}

int main(int argc, char** argv)
{
	int send_sock_fd = -1, recv_sock_fd = -1;
	struct sockaddr_in src_addr, dst_addr;
	struct hostent *host_details = NULL;
	char src[REQ_LENGTH], dst[REQ_LENGTH], dst_file_name[REQ_LENGTH] =
	{ 0 }, get_request_url[REQ_LENGTH] =
	{ 0 };

	packet_t packet;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	char *data = NULL;
	FILE* file_fd;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	if (argc != 2)
	{
		printf("Usage: ./rawhttpget <url>\n");
		exit(1);
	}

	parseUrlInfo(argv[1], dst, get_request_url, dst_file_name);
	if (!strcmp(dst_file_name, ""))
		strcpy(dst_file_name, "index.html");

	printf("HTTP response will be written to %s file \n", dst_file_name);

	if ((file_fd = fopen(dst_file_name, "w+")) == NULL)
	{
		printf("Failed to open the destination file: %d\n", strerror(errno));
		return -1;
	}

	if (NULL == (host_details = gethostbyname(dst)))
	{
		printf("ERROR: Failed to resolve hostname: %s\n", dst);
		exit(1);
	}

	memset(&src_addr, 0, sizeof(struct sockaddr_in));
	memset(&dst_addr, 0, sizeof(struct sockaddr_in));

	uint32_t src_address = getLocalIPAddress(
			((struct in_addr *) host_details->h_addr)->s_addr);

	src_addr.sin_family = AF_INET;
	src_addr.sin_port = htons((uint16_t) getpid());
	src_addr.sin_addr = *(struct in_addr *) &src_address;

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(HTTP_PORT);
	dst_addr.sin_addr = *((struct in_addr *) host_details->h_addr);

	send_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if (send_sock_fd < 0)
	{
		printf("Error: Creation of Raw Socket failed: %s!!\n", strerror(errno));
		exit(1);
	}

	recv_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if (recv_sock_fd < 0)
	{
		printf("Error: Creation of Raw Socket failed: %s!!\n", strerror(errno));
		exit(1);
	}

	if (bind(recv_sock_fd, (const struct sockaddr *) &src_addr,
			sizeof(struct sockaddr_in)) < 0)
	{
		printf("Error: Unable to bind the receiving socket: %s\n",
				strerror(errno));
		exit(1);
	}

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;

	if (setsockopt(recv_sock_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(1);
	}

	char psrc_addr[256] =
	{ 0 }, pdst_addr[256] =
	{ 0 };
	printf("Src Address: %s Destination Address: %s\n",
			inet_ntop(AF_INET, &src_addr.sin_addr.s_addr, psrc_addr, 256),
			inet_ntop(AF_INET, &dst_addr.sin_addr.s_addr, pdst_addr, 256));

	if (connect_tcp(send_sock_fd, recv_sock_fd, &dst_addr, &src_addr) < 0)
	{
		printf("TCP Connection Failed\n");
		goto EXIT;
	}
	else
		printf("TCP Connection Successful\n");

	while (strncmp(get_request_url, "", 256) != 0)
	{
		int ret = 0;
		char get_command[1024] =
		{ 0 };
		snprintf(get_command, 1024,
				"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nAccept: text/html\r\nAccept-Language:en-US\r\n\r\n",
				get_request_url, dst);

		if ((ret = send_data(get_command, strlen(get_command))) < 0
				|| ret != strlen(get_command))
		{
			printf("Failed to send get_request!!\n");
			goto EXIT;
		}

		memset(get_request_url, 0, sizeof(get_request_url));
		handle_http_response(file_fd, get_request_url, sizeof(get_request_url));
	}

	printf("Processing Done!!\n");
	EXIT: close_tcp();
	fclose(file_fd);
	close(send_sock_fd);
	close(recv_sock_fd);
}
