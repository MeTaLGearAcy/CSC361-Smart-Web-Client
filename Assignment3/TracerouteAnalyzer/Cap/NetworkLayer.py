from Cap.PCapDateTime import PCapDateTime
from utils import int_to_ipv4, int_to_ipv6
import struct
from collections import namedtuple


class NetworkLayer:
    tp_obj = None
    link_obj = None
    # Has this packet been used (for statistic)?
    used = False
    timestamp = None

    def __init__(self, link_layer_obj):
        self.link_obj = link_layer_obj
        try:
            self.timestamp = self.link_obj.get_physics()["timestamp"]
        except:
            self.timestamp = 0

    def generate_tp_obj(self):
        pass

    def get_tp_obj(self):
        return self.tp_obj

    def get_link_obj(self):
        return self.link_obj

    def gc(self):
        if self.get_link_obj():
            self.get_link_obj().gc()
        if self.link_obj:
            del self.link_obj


class IP(NetworkLayer):
    """
    Parent class of IP layer.
    """
    ip_header = None
    payload = ""
    fragmented = False
    fragments = 0
    last_offset = 0
    used_for_fragments = False

    def __init__(self, link_layer_obj):
        super().__init__(link_layer_obj)

    def get_header(self):
        """
        Simple getter of private ip_header.

        :return: IP header.
        """
        return self.ip_header

    def get_payload(self):
        """
        Simple getter of private payload.

        :return: Payload of IP packet (TCP/UDP/ICMP).
        """
        return self.payload

    def generate_tp_obj(self):
        if len(self.get_payload()) <= 0:
            return
        from .TransportLayer import TCP, UDP, ICMP
        if self.get_header().protocol == 1:
            # ICMP
            self.tp_obj = ICMP(self)
        elif self.get_header().protocol == 6:
            # TCP
            self.tp_obj = TCP(self)
        elif self.get_header().protocol == 17:
            # UDP
            self.tp_obj = UDP(self)
        elif self.get_header().protocol == 41:
            # 6in4
            self.tp_obj = IPv6(self)

    def __str__(self):
        return str(self.get_header())

    def __hash__(self):
        return str(hex(hash(str(self.get_header().src) + " -> " + str(self.get_header().dst))))

    def is_fragmented(self):
        return self.fragmented

    def get_fragments(self):
        return self.fragments


class IPv6(IP):
    __ip6_tuple__ = namedtuple("__ipv6", "len, protocol, src, dst")
    fragmented = False
    __first = False
    fragments = 0

    def __init__(self, link_obj):
        packet = link_obj.get_payload()
        super().__init__(link_obj)
        __version = struct.unpack("!B", packet[:1])[0] >> 4
        assert __version == 6
        __temp_struct = struct.unpack("!IHBBHHHHHHHHHHHHHHHH", packet[:40])
        self.ip_header = self.__ip6_tuple__(__temp_struct[1], __temp_struct[2], int_to_ipv6(__temp_struct[4:12]),
                                            int_to_ipv6(__temp_struct[12:20]))
        self.payload = packet[40:40 + self.ip_header.len]
        self.generate_tp_obj()

    # IPv6 always does not have fragmentation, so ignore that.
    def add(self, ip: IP):
        pass


class IPv4(IP):
    __ip4_tuple__ = namedtuple("__ipv4", "IHL, tos, len, id, flags, fragment_offset, "
                                         "ttl, protocol, checksum, src, dst")
    timestamp = None
    used_time = 0
    fragmented = False
    __first = False
    fragments = 0
    used_for_fragments = False
    last_offset = 0

    def __init__(self, link_obj):
        super().__init__(link_obj)
        packet = link_obj.get_payload()
        __version_and_IHL = struct.unpack("!B", packet[:1])[0]
        __version = __version_and_IHL >> 4
        __IHL = __version_and_IHL & 0x0f
        assert __version == 4
        (__tos, __len, __id) = struct.unpack("!BHH", packet[1:6])
        __flag1 = struct.unpack("!B", packet[6:7])[0]
        __offset = (struct.unpack("!H", packet[6:8])[0] & 0x1fff) << 3
        __ttl, __protocol, __chksum, __src, __dst = struct.unpack('!BBHII', packet[8:20])
        __DF = (__flag1 >> 5) & 0b010
        __MF = (__flag1 >> 5) & 0b001

        if __DF == 0 and __MF == 1:
            # fragment
            self.fragmented = True
            if __offset == 0:
                self.__first = True
        try:
            self.timestamp = self.get_link_obj().get_physics()["timestamp"]
        except:
            self.timestamp = 0
        self.ip_header = self.__ip4_tuple__(__IHL, __tos, __len, __id, (__flag1 >> 5),
                                            __offset,
                                            __ttl, __protocol, __chksum, int_to_ipv4(__src), int_to_ipv4(__dst))
        self.payload = packet[(self.ip_header.IHL * 4):self.ip_header.len]
        if not self.fragmented:
            self.generate_tp_obj()

    def add(self, ip: IP):
        self.payload = bytearray(self.get_payload())
        self.payload.extend(ip.get_payload())
        self.fragments += 1
        self.used_time += (self.timestamp - ip.timestamp - self.used_time) / self.fragments
        self.last_offset = ip.get_header().fragment_offset
        if ip.get_header().flags == 0:
            self.generate_tp_obj()
