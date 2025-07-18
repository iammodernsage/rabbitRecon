/** rabbitRecon core scanner - TCP/UDP port scanning implementation. Supports SYN, CONNECT, and UDP scanning modes **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>

#include "scanner.h"
#include "socket_utils.h"

#define DEFAULT_TIMEOUT 2  // seconds
#define MAX_PORTS_PER_SCAN 65535
#define SCAN_BATCH_SIZE 100

// Shared scan configuration
typedef struct {
    scan_config_t config;
    port_status_t results[MAX_PORTS_PER_SCAN];
    pthread_mutex_t results_mutex;
    volatile int running;
} shared_scan_data_t;

// Thread-specific scan data
typedef struct {
    shared_scan_data_t *shared;
    int thread_id;
    int ports_to_scan[SCAN_BATCH_SIZE];
    int port_count;
} thread_data_t;

/** TCP SYN Scan Implementation **/
static int tcp_syn_scan(const char *target, int port, int timeout_sec) {
    int sock = create_raw_socket();
    if (sock < 0) {
        return PORT_ERROR;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, target, &dest_addr.sin_addr);

    // Build TCP SYN packet
    char packet[PCKT_LEN];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    build_ip_header(ip, target);
    build_tcp_header(tcp, port, TH_SYN);

    // Send packet
    if (send_packet(sock, packet, &dest_addr) < 0) {
        close(sock);
        return PORT_ERROR;
    }

    // Listen for response
    int status = listen_for_response(sock, port, timeout_sec, RESP_SYN_ACK);
    close(sock);
    return status;
}

/** TCP Connect Scan Implementation **/
static int tcp_connect_scan(const char *target, int port, int timeout_sec) {
    int sock = create_connect_socket();
    if (sock < 0) {
        return PORT_ERROR;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, target, &dest_addr.sin_addr);

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Attempt connection
    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) {
        close(sock);
        if (errno == ECONNREFUSED) {
            return PORT_CLOSED;
        }
        return PORT_FILTERED;
    }

    close(sock);
    return PORT_OPEN;
}

/** UDP Scan Implementation **/
static int udp_scan(const char *target, int port, int timeout_sec) {
    int sock = create_udp_socket();
    if (sock < 0) {
        return PORT_ERROR;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, target, &dest_addr.sin_addr);

    // Send UDP packet
    char payload[] = "\x00\x00";  // Minimal payload
    if (sendto(sock, payload, sizeof(payload), 0,
              (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        close(sock);
        return PORT_ERROR;
    }

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Check for ICMP response
    char buffer[PCKT_LEN];
    struct sockaddr_in resp_addr;
    socklen_t addr_len = sizeof(resp_addr);

    if (recvfrom(sock, buffer, sizeof(buffer), 0,
                (struct sockaddr *)&resp_addr, &addr_len) > 0) {
        // Check if this is an ICMP port unreachable message
        if (is_icmp_unreachable(buffer, sizeof(buffer))) {
            close(sock);
            return PORT_CLOSED;
        }
    }

    close(sock);
    return PORT_OPEN_OR_FILTERED;
}

/** Thread worker function **/
static void *scan_worker(void *arg) {
    thread_data_t *tdata = (thread_data_t *)arg;
    shared_scan_data_t *shared = tdata->shared;

    for (int i = 0; i < tdata->port_count && shared->running; i++) {
        int port = tdata->ports_to_scan[i];
        int status;

        switch (shared->config.scan_type) {
            case SCAN_SYN:
                status = tcp_syn_scan(
                    shared->config.target,
                    port,
                    shared->config.timeout
                );
                break;
            case SCAN_CONNECT:
                status = tcp_connect_scan(
                    shared->config.target,
                    port,
                    shared->config.timeout
                );
                break;
            case SCAN_UDP:
                status = udp_scan(
                    shared->config.target,
                    port,
                    shared->config.timeout
                );
                break;
            default:
                status = PORT_ERROR;
        }

        pthread_mutex_lock(&shared->results_mutex);
        shared->results[port] = status;
        pthread_mutex_unlock(&shared->results_mutex);
    }

    free(tdata);
    return NULL;
}

/** Main scan interface **/
int scan_ports(scan_config_t *config, port_status_t *results) {
    if (!config || !results || !config->target) {
        return SCAN_INVALID_ARGS;
    }

    // Validate port range
    if (config->start_port < 1 || config->end_port > 65535 ||
        config->start_port > config->end_port) {
        return SCAN_INVALID_PORT_RANGE;
    }

    // Initialize shared data
    shared_scan_data_t shared;
    shared.config = *config;
    shared.running = 1;
    pthread_mutex_init(&shared.results_mutex, NULL);

    // Initialize results array
    for (int i = 0; i < MAX_PORTS_PER_SCAN; i++) {
        shared.results[i] = PORT_NOT_SCANNED;
    }

    // Create worker threads
    pthread_t threads[config->thread_count];
    int ports_per_thread = (config->end_port - config->start_port + 1) / config->thread_count;
    int extra_ports = (config->end_port - config->start_port + 1) % config->thread_count;

    int current_port = config->start_port;
    for (int i = 0; i < config->thread_count; i++) {
        thread_data_t *tdata = malloc(sizeof(thread_data_t));
        if (!tdata) {
            shared.running = 0;
            break;
        }

        tdata->shared = &shared;
        tdata->thread_id = i;
        tdata->port_count = ports_per_thread + (i < extra_ports ? 1 : 0);

        for (int p = 0; p < tdata->port_count; p++) {
            tdata->ports_to_scan[p] = current_port++;
        }

        if (pthread_create(&threads[i], NULL, scan_worker, tdata) != 0) {
            free(tdata);
            shared.running = 0;
            break;
        }
    }

    // Wait for threads to complete
    for (int i = 0; i < config->thread_count; i++) {
        if (threads[i]) {
            pthread_join(threads[i], NULL);
        }
    }

    // Copy results to output
    memcpy(results, shared.results, sizeof(port_status_t) * MAX_PORTS_PER_SCAN);

    pthread_mutex_destroy(&shared.results_mutex);
    return SCAN_SUCCESS;
}
