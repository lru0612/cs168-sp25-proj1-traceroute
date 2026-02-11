import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.b=b
        self.version=int(b[:4],2)
        self.header_len=int(b[4:8],2)*4
        self.tos=int(b[8:16],2)
        self.length=int(b[16:32],2)
        self.id=int(b[32:48],2)
        self.flags=int(b[48:51],2)
        self.frag_offset=int(b[51:64],2)
        self.ttl=int(b[64:72],2)
        self.proto=int(b[72:80],2)
        self.cksum=int(b[80:96],2)
        self.src=str(int(b[96:104],2))+'.'+str(int(b[104:112],2))+'.'+str(int(b[112:120],2))+'.'+str(int(b[120:128],2))
        self.dst=str(int(b[128:136],2))+'.'+str(int(b[136:144],2))+'.'+str(int(b[144:152],2))+'.'+str(int(b[152:160],2))
        self.payload=buffer[self.header_len:]
    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"
    def is_icmp(self) -> bool:
        return self.proto==1 or self.proto==58
    def is_valid(self) -> bool:
        # icmp check:
        if not self.is_icmp():
            return False
        else:
            icmp=ICMP(self.payload)
            if not icmp.is_valid():
                return False
        return True
def IPv4_lencheck(buffer) -> bool:
    b = ''.join(format(byte, '08b') for byte in [*buffer])
    if len(b)< int(b[16:32],2)*8:
        print("len(b)< (int(b[4:8],2)*32+int(b[16:32],2)*8)")
        print(len(b))
        print(int(b[4:8],2)*32+int(b[16:32],2)*8)
        return False
    else:
        ipv4=IPv4(buffer)
        if len(ipv4.payload)<8:
            return False
    return True
        

class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        if len(buffer) < 8: 
            raise ValueError(f"ICMP buffer too short: {len(buffer)} bytes")
    
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.type=int(b[:8],2)
        self.code=int(b[8:16],2)
        self.cksum=int(b[16:32],2)
        if len(buffer)>28:
            self.ipv4=IPv4(buffer[8:])
            udp_start=8+self.ipv4.header_len
            if len(buffer) >= udp_start + 8:  
                self.udp=UDP(buffer[udp_start:])
            else:
                self.udp = None 

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"

    def is_valid(self) -> bool:
        return self.type==3 or (self.type==11 and self.code==0)


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port=int(b[0:16],2)
        self.dst_port=int(b[16:32],2)
        self.len=int(b[32:48],2)
        self.cksum=int(b[48:64],2)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like
def convert_set2list(listofset):
    ls=[]
    for set in listofset:
        ls.append(list(set))
    return ls
def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    ips=[]
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        ips.append(set())
        attempt=0
        while attempt < PROBE_ATTEMPT_COUNT:
            attempt+=1
            sendsock.set_ttl(ttl)
            sendsock.sendto("hello".encode(), (ip, TRACEROUTE_PORT_NUMBER+ttl))
        attempt=0
        while attempt < PROBE_ATTEMPT_COUNT:
            if recvsock.recv_select():  # Check if there's a packet to process.
                buf, address = recvsock.recvfrom()  # Receive the packet.
                if not IPv4_lencheck(buf):
                    print("IPv4_lencheck failed")
                    continue
                ipv4=IPv4(buf)
                if not ipv4.is_valid():
                    print("IPv4 is_valid failed")
                    continue
                icmp=ICMP(ipv4.payload)
                this_ttl=icmp.udp.dst_port-TRACEROUTE_PORT_NUMBER
                print(this_ttl)
                if this_ttl==ttl:
                    ips[this_ttl-1].add(address[0])
                elif not (this_ttl > 0 and this_ttl <=30) or this_ttl>ttl:
                    continue
                else:
                    attempt=attempt-1
                    ips[this_ttl-1].add(address[0])
                if icmp.type==3:
                    ips=convert_set2list(ips)
                    # for ttl, this_addresses in enumerate(ips):
                    #     util.print_result(this_addresses, ttl+1)
                    return ips
    ips=convert_set2list(ips)
    # for ttl, this_addresses in enumerate(ips):
    #     util.print_result(this_addresses, ttl+1)
    return ips
    # sendsock.set_ttl(TRACEROUTE_MAX_TTL)
    # sendsock.sendto("Hello".encode(), (ip, TRACEROUTE_PORT_NUMBER))
    # if recvsock.recv_select():  # Check if there's a packet to process.
    #     buf, address = recvsock.recvfrom()  # Receive the packet.

    #     # Print out the packet for debugging.
    #     print(f"Packet bytes: {buf.hex()}")
    #     print(f"Packet is from IP: {address[0]}")
    #     print(f"Packet is from port: {address[1]}")


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
