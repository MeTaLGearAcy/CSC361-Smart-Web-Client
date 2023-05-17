import struct
from collections import namedtuple
from utils import deprecated


class TransportLayer:
    app_obj = None
    net_obj = None
    payload = None
    header = None
    # Has this packet been used (for statistic)?
    used = False

    def __init__(self, net_obj):
        self.net_obj = net_obj

    def generate_app_obj(self):
        # To be continued
        pass

    def get_app_obj(self):
        return self.app_obj

    def get_net_obj(self):
        return self.net_obj

    def gc(self):
        if self.get_net_obj():
            self.get_net_obj().gc()
        if self.net_obj:
            del self.net_obj

    def get_payload(self):
        return self.payload

    def get_header(self):
        return self.header


class TCP(TransportLayer):
    """
    TCP packet. One instance means one packet.
    """

    # TCP tuple without timestamp
    __tcp_without_ts_tuple__ = namedtuple("__tcp",
                                          "src, src_port, dst, dst_port, seq, ack_num, ack, rst, syn, fin, window, "
                                          "payload_size")

    # TCP tuple with timestamp
    __tcp_tuple__ = namedtuple("__tcp",
                               "src, "
                               "src_port, dst, dst_port, seq, ack_num, "
                               "ack, rst, syn, fin, window, payload_size, ts")

    def __init__(self, ip_obj):
        """
        Packet init method, should be called by IP header object to provide TCP header to unpack.

        :param ip_obj: IPvN object to extract TCP header.
        """
        super().__init__(ip_obj)
        __packet = ip_obj.get_payload()
        (__src, __dst) = (ip_obj.get_header().src, ip_obj.get_header().dst)
        (__src_port, __dst_port) = struct.unpack("!HH", __packet[:4])
        (__seq, __ack_num) = struct.unpack("!II", __packet[4:12])
        __args = struct.unpack("!B", __packet[13:14])[0]
        __args = __args << 3 >> 3

        __ack = (__args & 0b00010000) >> 4
        __rst = (__args & 0b00000100) >> 2
        __syn = (__args & 0b00000010) >> 1
        __fin = __args & 0b00000001
        __offset = (struct.unpack("!B", __packet[12:13])[0] >> 4) * 5
        if __offset < 20:
            __payload_size = 0
        else:
            __payload_size = len(__packet[__offset * 5:])
        self.header = self.__tcp_tuple__(__src, str(__src_port), __dst, str(__dst_port), __seq,
                                             __ack_num,
                                             __ack, __rst, __syn, __fin,
                                             struct.unpack("!H", __packet[15:17])[0],
                                             __payload_size,
                                             self.get_net_obj().get_link_obj().get_physics()["timestamp"])
        self.gc()

    def __hash__(self):
        """
        For statistic, treat as a same direction of TCP connections when packets with same source and destination.

        Use hash(dst + ":" + dst_port + src + ":" + src_port) to get the opposite direction.

        :return: str(hex(hash(src + ":" + src_port + dst + ":" + dst_port)))
        """
        # single direction.
        # for finding opposite direction of tcp packets, just use hash(dst+src)
        return str(hex(hash(self.header.src + ":" + self.header.src_port +
                            self.header.dst + ":" + self.header.dst_port)))

    @deprecated("Timestamp should generate during TCP object generating.")
    def set_timestamp(self, timestamp):
        """
        Should be called by layer with timestamp to set current timestamp of this packet.

        :param timestamp: Timestamp in some format.
        :return: Nothing to return.
        """
        self.header = self.__tcp_tuple__(self.header.src, self.header.src_port, self.header.dst,
                                         self.header.dst_port, self.header.seq, self.header.ack_num,
                                         self.header.ack, self.header.rst, self.header.syn,
                                         self.header.fin, self.header.window, self.header.payload_size,
                                         timestamp)


class UDP(TransportLayer):
    __udp_tuple__ = namedtuple("__udp", "src_port, dst_port, len, checksum")

    def __init__(self, net_obj):
        super().__init__(net_obj)
        __src_port, __dst_port, __len, __checksum = struct.unpack("!HHHH", net_obj.get_payload()[:8])
        self.header = self.__udp_tuple__(__src_port, __dst_port, __len, __checksum)
        self.payload = net_obj.get_payload()[8:]
        self.gc()


class ICMP(TransportLayer):
    __icmp_tuple__ = namedtuple("__icmp", "type, code, checksum, rest")

    def __init__(self, net_obj):
        super().__init__(net_obj)
        __type, __code, __checksum = struct.unpack("!BBH", net_obj.get_payload()[:4])
        self.header = self.__icmp_tuple__(__type, __code, __checksum, net_obj.get_payload()[4:8])
        self.payload = net_obj.get_payload()[8:]
        self.gc()

