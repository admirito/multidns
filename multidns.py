#!/usr/bin/env python

#          Author:
#  --= Mohammad Razavi =--
# mrazavi64-at-gmail-dot-com

"""\
multidns will relay your DNS requsts to several DNS servers and
returns the first answer.

You can also specify an invalid address e.g. 10.10.34.34. If the
answer was 10.10.34.34 the program will continue to try other DNS
servers to find an answer that is not 10.10.34.34.

If you put an `x' character before the address of a DNS server
e.g. `x8.8.8.8:53' the request and its response will be encrypted with
a symmetrical encyption algorithm--that applying the same encryption
algorithm twice will decode to the first input. So if you relay your
DNS requst twice through two instances of this program with `x'
prefixes, the result will be a normal DNS server. But the traffic
between the two program instances will be encrypted. The encryption
algorithm is not secure at all but it is highly possible that it can
fool your government censorship devices.
"""

from __future__ import print_function

import sys, time, re, copy, socket, struct
from threading import Thread
from optparse import OptionParser

from dnslib import DNSRecord
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
from dnslib.dns import A

try:
    from socketserver import ThreadingUDPServer
except ImportError:
    from SocketServer import ThreadingUDPServer

try:
    import queue as Queue
except ImportError:
    import Queue

__version__ = "1.0.5"

class UDPServer(ThreadingUDPServer):
    allow_reuse_address = True

def encrypt(data):
    char_encrypt = lambda x: 31 - x if x < 32 else \
                             x if x == 32 else \
                             78 - x if x < 46 else \
                             x if x == 46 else \
                             173 - x if x < 127 else \
                             127 if x == 127 else \
                             383 - x
    return "".join([chr(char_encrypt(ord(ch))) for ch in data])

def EncryptDNSRecord(record):
    for q in record.questions:
        qname = str(q.get_qname())
        encrypted_qname = encrypt(qname)
        q.set_qname(encrypted_qname)

    for rr in record.rr:
        rname = str(rr.get_rname())
        encrypted_rname = encrypt(rname)
        rr.set_rname(encrypted_rname)

    for auth in record.auth:
        rname = str(auth.get_rname())
        encrypted_rname = encrypt(rname)
        auth.set_rname(encrypted_rname)

    for ar in record.ar:
        rname = str(ar.get_rname())
        encrypted_rname = encrypt(rname)
        ar.set_rname(encrypted_rname)

def IsAcceptable(reply):
    global OPTIONS
    try:
        #return reply.get_a().rdata != A("10.10.34.34")
        return not bool(re.match(OPTIONS.invalid_resolve,
                                 str(reply.get_a().rdata)))
    except:
        return True

def request_send(self, dest, port = 53, tcp = False, timeout = None, \
                 bind_address = None):
    """\
    Send packet to nameserver and return response

    This is dnslib DNSRecord.send in dns.py but with a "bind_address"
    extra parameter
    """
    data = self.pack()
    if tcp:
        if len(data) > 65535:
            raise ValueError("Packet length too long: %d" % len(data))
        data = struct.pack("!H",len(data)) + data
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        if timeout is not None:
            sock.settimeout(timeout)
        if bind_address:
            sock.bind((bind_address, 0))
        sock.connect((dest,port))
        sock.sendall(data)
        response = sock.recv(8192)
        length = struct.unpack("!H",bytes(response[:2]))[0]
        while len(response) - 2 < length:
            response += sock.recv(8192)
        sock.close()
        response = response[2:]
    else:
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        if timeout is not None:
            sock.settimeout(timeout)
        if bind_address:
            sock.bind((bind_address, 0))
        sock.sendto(self.pack(),(dest,port))
        response,server = sock.recvfrom(8192)
        sock.close()
    return response

class ProxyResolver(BaseResolver):
    def __init__(self, addresses, request_bind_address = None):
        self.addresses = addresses
        self.request_bind_address = request_bind_address
        
    def resolve(self, request, handler):
        global OPTIONS

        queue = Queue.Queue()

        reply = None
        for i in range(OPTIONS.retry):
            for addr in self.addresses:
                request2 = copy.deepcopy(request)

                encrypted = addr[0][:1] in ["x", "X"]
                if encrypted:
                    addr = (addr[0][1:],) + addr[1:]
                    EncryptDNSRecord(request2)

                def put(request, encrypted, *send_args, **send_kwargs):
                    try:
                        if self.request_bind_address:
                            result = request_send(request, *send_args, \
                                                  bind_address = \
                                                  self.request_bind_address, \
                                                  **send_kwargs)
                        else:
                            result = request.send(*send_args, **send_kwargs)
                    except socket.timeout:
                        pass
                    else:
                        queue.put((encrypted, result))

                t = Thread(target = put, \
                           args = (request2, encrypted,) + addr, \
                           kwargs = {"timeout": OPTIONS.timeout})
                t.daemon = True
                t.start()

            for _ in self.addresses:
                try:
                    encrypted, r = queue.get(timeout = OPTIONS.timeout)
                except Queue.Empty:
                    continue

                reply = DNSRecord.parse(r)
                if encrypted:
                    EncryptDNSRecord(reply)

                if IsAcceptable(reply):
                    return reply

        return reply

def main():
    global OPTIONS, ARGS

    parser = OptionParser()

    parser.add_option("-b", "--bind", dest = "bind", \
                      type = "string", default = "127.0.0.7:53", \
                      help = "set bind address/port to IP[:PORT]. " \
                      "Default value is `127.0.0.7:53'.", \
                      metavar = "IP[:PORT]")
    parser.add_option("-t", "--timeout", dest = "timeout", \
                      type = "int", default = "5", \
                      help = "set DNS resolving timeout to SECONDS", \
                      metavar = "SECONDS")
    parser.add_option("-r", "--retry", dest = "retry", \
                      type = "int", default = "3", \
                      help = "set retry count to COUNT", metavar = "COUNT")
    parser.add_option("-i", "--invalid-resolve", dest = "invalid_resolve", \
                      type = "string", default = r"10\.10\.34\.\d+", \
                      help = "REGEX is a an IP address or a regular " \
                      "expression that will not be prefered on DNS " \
                      "resolving. Default value is `10.10.34.\\d+'.", \
                      metavar = "REGEX")
    parser.add_option("--request-bind", dest = "request_bind", \
                      type = "string", default = "", \
                      help = "bind to IP address before sending DNS " \
                      "requests.", metavar = "IP")
    parser.add_option("-q", "--quiet", dest = "quiet", \
                      action = "store_true", default = False, \
                      help = "do not print any log")
    
    parser.set_usage("%s [OPTION]... DNS_SERVER[:PORT]..." % \
                     sys.argv[0])
    parser.set_description(__doc__)

    OPTIONS, ARGS = parser.parse_args()

    if len(ARGS) < 1:
        parser.print_help()
        exit(1)

    def get_address_port(arg):
        address_port = arg if ":" in arg else "%s:53" % arg
        address_port = address_port.split(":")
        return address_port[0], int(address_port[1])

    bind_address, bind_port = get_address_port(OPTIONS.bind)
    dns_servers = [get_address_port(arg) for arg in ARGS]

    resolver = ProxyResolver(dns_servers, request_bind_address = \
                             (OPTIONS.request_bind or None))
    logger = DNSLogger("request,reply,truncated,error", False) \
             if not OPTIONS.quiet else \
             DNSLogger("-request,-reply,-truncated,-error,-log_recv," \
                       "-log_send,-log_data", False)
    udp_server = DNSServer(resolver,
                           port = bind_port,
                           address = bind_address,
                           logger = logger if not OPTIONS.quiet else None,
                           handler = DNSHandler,
                           server = UDPServer)

    udp_server.start_thread()

    try:
        while udp_server.isAlive():
            time.sleep(1)
    except KeyboardInterrupt:
        if not OPTIONS.quiet:
            print("Shutting down the server with user request...")
        udp_server.stop()
        exit(0)

if __name__ == "__main__":
    main()
