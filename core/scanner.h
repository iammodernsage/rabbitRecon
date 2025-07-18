#ifndef RABBITRECON_SCANNER_H
#define RABBITRECON_SCANNER_H

typedef enum {
    SCAN_SYN,
    SCAN_CONNECT,
    SCAN_UDP
} scan_type_t;

typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_OPEN_OR_FILTERED,
    PORT_ERROR,
    PORT_NOT_SCANNED
} port_status_t;

typedef enum {
    SCAN_SUCCESS,
    SCAN_INVALID_ARGS,
    SCAN_INVALID_PORT_RANGE,
    SCAN_SOCKET_ERROR,
    SCAN_THREAD_ERROR
} scan_result_t;

typedef struct {
    char *target;
    int start_port;
    int end_port;
    int thread_count;
    int timeout;  // in seconds
    scan_type_t scan_type;
} scan_config_t;

/*
 * Main scanning interface
 *
 * @param config Scan configuration parameters
 * @param results Array to store port status results (must have space for 65535 elements)
 * @return scan_result_t indicating overall scan status
 */
scan_result_t scan_ports(scan_config_t *config, port_status_t *results);

#endif // RABBITRECON_SCANNER_H
