import ctypes
import os
from ctypes import Structure, c_int, c_char_p, POINTER, byref

# Load the shared library
_scanner = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libreconx.so'))

# Define C structures for Python
class ScanConfig(Structure):
    _fields_ = [
        ("target", c_char_p),
        ("start_port", c_int),
        ("end_port", c_int),
        ("thread_count", c_int),
        ("timeout", c_int),
        ("scan_type", c_int)
    ]

# Define enums matching the C side
SCAN_SYN = 0
SCAN_CONNECT = 1
SCAN_UDP = 2

PORT_OPEN = 0
PORT_CLOSED = 1
PORT_FILTERED = 2
PORT_OPEN_OR_FILTERED = 3
PORT_ERROR = 4
PORT_NOT_SCANNED = 5

# Configure function prototypes
_scanner.scan_ports.argtypes = [
    POINTER(ScanConfig),
    POINTER(c_int)  # Array of port statuses
]
_scanner.scan_ports.restype = c_int

def scan_ports(target, start_port, end_port, scan_type=SCAN_SYN,
               thread_count=10, timeout=2):
    """
    Python-friendly wrapper for the C scanner
    Returns: (result_code, port_status_array)
    """
    # Convert Python types to C types
    config = ScanConfig(
        target=target.encode('utf-8'),
        start_port=start_port,
        end_port=end_port,
        thread_count=thread_count,
        timeout=timeout,
        scan_type=scan_type
    )

    # Create array for results (65535 ports max)
    results = (c_int * 65535)()

    # Call the C function
    ret = _scanner.scan_ports(byref(config), results)

    # Convert results to Python list
    statuses = [results[i] for i in range(start_port, end_port + 1)]

    return (ret, statuses)
