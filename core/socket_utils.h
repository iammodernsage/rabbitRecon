#ifndef RABBITRECON_SOCKET_UTILS_H
#define RABBITRECON_SOCKET_UTILS_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

// Socket creation
int create_raw_socket();
int create_connect_socket();
int create_udp_socket();

// Packet construction
void build_ip_header(struct iphdr *iph, const char *src_ip, const char *dst_ip);
void build_tcp_header(struct tcphdr *tcph, int src_port, int dst_port, int flags);

// Packet operations
int send_packet(int sock, char *packet, size_t packet_len, struct sockaddr_in *dest);
int listen_for_response(int sock, int port, int timeout_sec, int expected_flags);
int is_icmp_unreachable(char *buffer, size_t length);

// Response flags
#define RESP_SYN_ACK (TH_SYN | TH_ACK)
#define RESP_RST TH_RST

#endif // RABBITRECON_SOCKET_UTILS_H
