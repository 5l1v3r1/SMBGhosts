#!/usr/bin/env python3
"""
Multithreaded scanner for CVE-2020-0796 - SMBv3 RCE
Based off of ollypwn/SMBGhost
"""

from queue import Queue
from threading import Thread
import argparse
import ipaddress
import socket
import struct

SMB_PACKET = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

def _scan(ip, timeout=3, verbose=False):
    sock = socket.socket(socket.AF_INET)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, 445))
    except:
        sock.close()
        if verbose:
            print("%s -- UNREACHABLE" % ip)
        return

    try:
        sock.send(SMB_PACKET)
        nb, = struct.unpack(">I", sock.recv(4))
        res = sock.recv(nb)
    except Exception as e:
        print("%s -- ERROR (%s)" % (ip, str(e)))
        return

    if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
        print("%s -- NOT VULNERABLE" % ip)
    else:
        print("%s -- VULNERABLE" % ip)

def scan(queue):
    while True:
        ip, timeout, verbose = queue.get()
        _scan(ip, timeout, verbose)
        queue.task_done()

def main(args):
    # Create a queue to handle Threads
    queue = Queue()

    # Create threads
    for _ in range(args.threads):
        thread = Thread(target=scan, args=(queue,))
        thread.setDaemon(True)
        thread.start()

    for ip in ipaddress.ip_network(args.subnet):
        queue.put((str(ip), args.timeout, args.verbose))
    queue.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Subnet/IP to be scanned (Required)
    parser.add_argument("subnet", help="IP/Subnet (eg: 192.168.1.42, 192.168.1.0/24)")

    # Optional number of Threads to use
    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=1,
        help="Number of Threads to use (Default: 1)")

    # Optional timeout for connections
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=3,
        help="Socket connection timeout (seconds) (Default: 3)")

    # Optional verbosity counter
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose (show unreachable hosts)")

    # Parse args
    args = parser.parse_args()
    main(args)