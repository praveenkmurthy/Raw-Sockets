Project 4: Raw Sockets
Group Members:
Aravind Chinta - NUID: 001632368
Praveen Keshavamurthy - NUID: 001794337

High Level Design:

1. Finalized 'C' as the programming language to be used after exploring the python support on Raw sockets. We felt by using 'C' we will have more control on the raw socket operations & to retrieve IP informations.
2. We used Routing Sockets & ioctl commands to determine which interface IP to be used to set up the socket connection.
3. We modeled the APIs of this raw socket version of tcp/ip stack to be inline with the current OS TCP/IP stack. Basically we will have the following APIs exposed to the application layer.
	- connect_tcp(...)
	- send_data(...)
	- receive_data(...)
	- close_tcp(...)
4. High Level Design
	- The receive and send on rawsocket is handled by 2 seperate threads. The send thread reads from the buffer & writes it to the raw socket. The receive thread reads from the raw socket and writes it to receive buffer.
	- The HTTP Protocol Stack is implemented in the main thread. This mainly sends a GET Request & handles 200/302 response. Any other response, the application discards & exits.
	- The receive_data() and send_data() APIs exposed to application layer are blocking calls.
	- TCP retransmission time out is handled as a seperate thread.
5. We have implemented the following TCP features.
	- TCP Syn retry for 5 times with timeout interval being 60 seconds.
	- TCP RTO with interval of 60 seconds
	- TCP Congestion window size 1<= cwind <= 1000 at any point of time. cwind value represents multiples of MSS that can be sent.
	- Dynamic Client advertised TCP Window size
	- Implemented all the TCP States viz., SYN_SENT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, CLOSED
	- TCP fast retransmit on single duplicate ACK
	- TCP Out of order packets where the out of order packets are discarded & an ACK is sent back to the server indicating expected sequence_num. We could not implent SACK.
	
Testing Methods:
1. We hosted a HTTP Server on one of the local VMs & tested the code for the basic TCP/IP functionality.
2. We verified HTTP Chunked transfer by retrieving http://www.ccs.neu.edu webpage.

Challenges Faced:
1. We faced a very critical challenge testing & debugging in VM as the packet size received on the VM was much greater than the agreed MSS value.
2. We could not directly verify the TCP Checksum validation as the VMs are behind the NAT.