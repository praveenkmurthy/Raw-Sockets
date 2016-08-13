#include <stdio.h>
#include <stdlib.h>
#include <bits/sockaddr.h>
#include <asm/types.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#define BUFFER_LENGTH 8192
typedef struct rt_request
{
	struct nlmsghdr nl;
	struct rtmsg rt;
	char payload[BUFFER_LENGTH];
} rt_request;

uint32_t fetch_interface_ip(uint32_t if_index)
{
	int family;
	struct ifreq ifreq;
	char host[256] =
	{ 0 }, if_name[256] =
	{ 0 };
	uint32_t src_addr;
	int fd;

	if_indextoname(if_index, if_name);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	memset(&ifreq, 0, sizeof ifreq);
	strncpy(ifreq.ifr_name, if_name, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFADDR, &ifreq) != 0)
	{
		/* perror(name); */
		return -1; /* ignore */
	}

	switch (family = ifreq.ifr_addr.sa_family)
	{
	case AF_UNSPEC:
		return; /* ignore */
	case AF_INET:
	case AF_INET6:
		getnameinfo(&ifreq.ifr_addr, sizeof ifreq.ifr_addr, host, sizeof host,
				0, 0, NI_NUMERICHOST);
		break;
	default:
		sprintf(host, "unknown  (family: %d)", family);
	}
	inet_pton(AF_INET, host, &src_addr);
	close(fd);
	return src_addr;
}

void formRequest(rt_request* req)
{
	bzero(req, sizeof(req));

	req->nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->nl.nlmsg_type = RTM_GETROUTE;

	req->rt.rtm_family = AF_INET;
	req->rt.rtm_table = RT_TABLE_MAIN;

}

void sendRequest(int sock_fd, struct sockaddr_nl *pa, rt_request* req)
{
	struct msghdr msg;
	struct iovec iov;
	int rtn;

	bzero(pa, sizeof(pa));
	pa->nl_family = AF_NETLINK;

	bzero(&msg, sizeof(msg));
	msg.msg_name = pa;
	msg.msg_namelen = sizeof(*pa);

	iov.iov_base = (void *) req;
	iov.iov_len = req->nl.nlmsg_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (1)
	{
		if ((rtn = sendmsg(sock_fd, &msg, 0)) < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				printf("Error: Unable to send NetLink message:%s\n",
						strerror(errno));
				exit(1);
			}
		}
		break;
	}

}

int receiveReply(int sock_fd, char* response_buffer)
{
	char* p;
	int nll, rtl, rtn;
	struct nlmsghdr *nlp;
	struct rtmsg *rtp;

	bzero(response_buffer, BUFFER_LENGTH);
	p = response_buffer;
	nll = 0;

	while (1)
	{
		if ((rtn = recv(sock_fd, p, BUFFER_LENGTH - nll, 0)) < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				printf("Failed to read from NetLink Socket: %s\n",
						strerror(errno));
				exit(1);
			}

		}

		nlp = (struct nlmsghdr*) p;
		if (nlp->nlmsg_type == NLMSG_DONE)
			break;

		p += rtn;
		nll += rtn;
	}
	return nll;
}

uint32_t readReply(char *response, int nll, in_addr_t dst_address)
{
	struct nlmsghdr *nlp = NULL;
	struct rtmsg *rtp = NULL;
	struct rtattr *rtap = NULL;
	int rtl = 0, found_route = 0, default_route = 0;
	uint32_t route_addr, net_mask;
	uint32_t if_index = -1;

	nlp = (struct nlmsghdr*) response;
	for (; NLMSG_OK(nlp, nll); nlp = NLMSG_NEXT(nlp, nll))
	{
		rtp = (struct rtmsg *) NLMSG_DATA(nlp);

		if (rtp->rtm_table != RT_TABLE_MAIN)
			continue;

		rtap = (struct rtattr *) RTM_RTA(rtp);
		rtl = RTM_PAYLOAD(nlp);
		found_route = 0;
		default_route = 1;

		for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl))
		{
			switch (rtap->rta_type)
			{
			// destination IPv4 address
			case RTA_DST:
				default_route = 0;
				route_addr = *((uint32_t*) RTA_DATA (rtap));
				net_mask = 0xFFFFFFFF;
				net_mask <<= (32 - rtp->rtm_dst_len);
				net_mask = ntohl(net_mask);
				if (route_addr == (dst_address & net_mask))
					found_route = 1;
				else if (route_addr == 0)
					default_route = 1;
				break;

				// unique ID associated with the network
				// interface
			case RTA_OIF:
				if (found_route || default_route)
					if_index = *((uint32_t*) RTA_DATA (rtap));
				break;

			default:
				break;
			}
		}

		if (found_route)
			break;
	}

	return if_index;

}

uint32_t getLocalIPAddress(in_addr_t dst_address)
{
	int route_sock_fd = -1, res_len = 0;
	struct sockaddr_nl sa, pa;
	uint32_t if_index;

	rt_request req =
	{ 0 };
	char response_payload[BUFFER_LENGTH] =
	{ 0 };

	// Open Routing Socket
	if ((route_sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
	{
		printf("Error: Failed to open routing socket: %s\n", strerror(errno));
		exit(1);
	}

	bzero(&sa, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = getpid();

	bind(route_sock_fd, (struct sockaddr*) &sa, sizeof(sa));

	formRequest(&req);
	sendRequest(route_sock_fd, &pa, &req);
	res_len = receiveReply(route_sock_fd, response_payload);
	if_index = readReply(response_payload, res_len, dst_address);

	close(route_sock_fd);
	return fetch_interface_ip(if_index);
}

