/*
 * rabbitRecon socket utilities - Low-level network operations
 * Designed for both direct C use and Python integration, check python wrapper
 */

#include "socket_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>

// Packet buffer size
#define PCKT_LEN 8192
// IP header length in bytes
#define IP_HDRLEN sizeof(struct iphdr)
// TCP header length in bytes
#define TCP_HDRLEN sizeof(struct tcphdr)
// UDP header length in bytes
#define UDP_HDRLEN sizeof(struct udphdr)

// Checksum calculation
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int create_raw_socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Failed to create raw socket");
        return -1;
    }

    // Enable IP_HDRINCL for manual IP header construction
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Failed to set IP_HDRINCL");
        close(sock);
        return -1;
    }

    return sock;
}

int create_connect_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Failed to create connect socket");
    }
    return sock;
}

int create_udp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Failed to create UDP socket");
    }
    return sock;
}

void build_ip_header(struct iphdr *iph, const char *src_ip, const char *dst_ip) {
    // Clear the IP header
    memset(iph, 0, IP_HDRLEN);

    // IP header configuration
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(IP_HDRLEN + TCP_HDRLEN);
    iph->id = htons(54321);  // ID of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;  // Will be calculated later

    // Source IP address
    if (src_ip) {
        inet_pton(AF_INET, src_ip, &iph->saddr);
    } else {
        iph->saddr = inet_addr("192.168.1.100");  // Default spoofed source
    }

    // Destination IP address
    inet_pton(AF_INET, dst_ip, &iph->daddr);

    // Calculate checksum
    iph->check = csum((unsigned short *)iph, IP_HDRLEN / 2);
}

void build_tcp_header(struct tcphdr *tcph, int src_port, int dst_port, int flags) {
    // Clear the TCP header
    memset(tcph, 0, TCP_HDRLEN);

    // TCP header configuration
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(rand() % 0xFFFFFFFF);
    tcph->ack_seq = 0;
    tcph->doff = 5;  // TCP header length in 32-bit words
    tcph->fin = (flags & TH_FIN) ? 1 : 0;
    tcph->syn = (flags & TH_SYN) ? 1 : 0;
    tcph->rst = (flags & TH_RST) ? 1 : 0;
    tcph->psh = (flags & TH_PUSH) ? 1 : 0;
    tcph->ack = (flags & TH_ACK) ? 1 : 0;
    tcph->urg = (flags & TH_URG) ? 1 : 0;
    tcph->window = htons(5840);  // Maximum window size
    tcph->check = 0;  // Will be calculated later
    tcph->urg_ptr = 0;

    // Pseudo header for checksum calculation
    struct pseudo_tcp_header {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char reserved;
        unsigned char protocol;
        unsigned short tcp_length;
    } pseudo_header;

    memset(&pseudo_header, 0, sizeof(pseudo_header));
    pseudo_header.src_addr = inet_addr("192.168.1.100");  // Should match IP header
    pseudo_header.dst_addr = inet_addr("127.0.0.1");     // Will be overwritten
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(TCP_HDRLEN);

    // Calculate checksum
    char pseudo_packet[sizeof(pseudo_header) + TCP_HDRLEN];
    memcpy(pseudo_packet, &pseudo_header, sizeof(pseudo_header));
    memcpy(pseudo_packet + sizeof(pseudo_header), tcph, TCP_HDRLEN);

    tcph->check = csum((unsigned short *)pseudo_packet,
                      (sizeof(pseudo_header) + TCP_HDRLEN) / 2);
}

int send_packet(int sock, char *packet, size_t packet_len, struct sockaddr_in *dest) {
    if (sendto(sock, packet, packet_len, 0,
              (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("Failed to send packet");
        return -1;
    }
    return 0;
}

int listen_for_response(int sock, int port, int timeout_sec, int expected_flags) {
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buffer[PCKT_LEN];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (1) {
        ssize_t packet_len = recvfrom(sock, buffer, sizeof(buffer), 0,
                            (struct sockaddr *)&src_addr, &addr_len);
        if (packet_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return PORT_FILTERED;  // Timeout
            }
            perror("Error receiving packet");
            return PORT_ERROR;
        }

        // Parse IP header
        struct iphdr *iph = (struct iphdr *)buffer;
        if (iph->protocol == IPPROTO_TCP) {
            // Parse TCP header (located after IP header)
            struct tcphdr *tcph = (struct tcphdr *)(buffer + (iph->ihl * 4));

            // Check if this is response to our port
            if (ntohs(tcph->dest) == port) {
                // Check for expected flags
                if ((tcph->flags & expected_flags) == expected_flags) {
                    return PORT_OPEN;
                } else if (tcph->rst) {
                    return PORT_CLOSED;
                }
            }
        }
    }
}

int is_icmp_unreachable(char *buffer, size_t length) {
    struct iphdr *iph = (struct iphdr *)buffer;
    if (iph->protocol == IPPROTO_ICMP) {
        // ICMP header is after IP header
        struct icmphdr *icmph = (struct icmphdr *)(buffer + (iph->ihl * 4));
        return (icmph->type == ICMP_DEST_UNREACH);
    }
    return 0;
}
