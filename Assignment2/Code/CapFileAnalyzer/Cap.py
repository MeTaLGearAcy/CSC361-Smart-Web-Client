import os
import struct
from collections import namedtuple
from decimal import Decimal

import ProgressBar


def int_to_ipv6(ip):
    __return_ip = ""
    for i in range(len(ip)):
        if i == 0:
            __return_ip += hex(ip[i])[2:] + ":"
            continue
        if ip[i] == 0 and ip[i - 1] == 0:
            continue
        if ip[i] == 0:
            __return_ip += ":"
            continue
        __return_ip += hex(ip[i])[2:] + ":"
    return __return_ip[:-1]


def int_to_ipv4(ip: int):
    return "{}.{}.{}.{}".format(ip >> 24, (ip & 0x00ffffff) >> 16, (ip & 0x0000ffff) >> 8, (ip & 0x000000ff))


class TCP:
    __tcp_without_ts_tuple__ = namedtuple("__tcp",
                                          "src, src_port, dst, dst_port, seq, ack_num, ack, rst, syn, fin, window, "
                                          "payload_size")
    __tcp_tuple__ = namedtuple("__tcp",
                               "src, "
                               "src_port, dst, dst_port, seq, ack_num, "
                               "ack, rst, syn, fin, window, payload_size, ts")
    tcp_header = None
    used = False

    def __init__(self, ip_obj):
        __packet = ip_obj.get_payload()
        (__src, __dst) = (ip_obj.get_ip_header().src, ip_obj.get_ip_header().dst)
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
        self.tcp_header = self.__tcp_without_ts_tuple__(__src, str(__src_port), __dst, str(__dst_port), __seq,
                                                        __ack_num,
                                                        __ack, __rst, __syn, __fin,
                                                        struct.unpack("!H", __packet[15:17])[0],
                                                        __payload_size)

    def __hash__(self):
        # single direction.
        # for finding opposite direction of tcp packets, just use hash(dst+src)
        return str(hex(hash(self.tcp_header.src + ":" + self.tcp_header.src_port +
                            self.tcp_header.dst + ":" + self.tcp_header.dst_port)))

    def get_tcp_header(self):
        return self.tcp_header

    def set_timestamp(self, timestamp):
        self.tcp_header = self.__tcp_tuple__(self.tcp_header.src, self.tcp_header.src_port, self.tcp_header.dst,
                                             self.tcp_header.dst_port, self.tcp_header.seq, self.tcp_header.ack_num,
                                             self.tcp_header.ack, self.tcp_header.rst, self.tcp_header.syn,
                                             self.tcp_header.fin, self.tcp_header.window, self.tcp_header.payload_size,
                                             timestamp)


def TCPIPWrapper(link_type, ip_header) -> tuple or None:
    try:
        if link_type == "IPv4":
            __temp_ip = IPv4(ip_header)
        elif link_type == "IPv6":
            __temp_ip = IPv6(ip_header)
        else:
            # not IP Header, skip
            return None
        if __temp_ip.get_ip_header().protocol != 6:
            # not TCP, pass
            return None
        return __temp_ip, TCP(__temp_ip)
    except Exception:
        return None


class IP:
    ip_header = None
    payload = None

    def get_ip_header(self):
        return self.ip_header

    def get_payload(self):
        return self.payload


class IPv6(IP):
    __ip6_tuple__ = namedtuple("__ipv6", "len, protocol, src, dst")

    def __init__(self, packet):
        super().__init__()
        __version = struct.unpack("!B", packet[:1])[0] >> 4
        if __version != 6:
            raise TypeError("Not IPv6 Header.")
        __temp_struct = struct.unpack("!IHBBHHHHHHHHHHHHHHHH", packet[:40])
        self.ip_header = self.__ip6_tuple__(__temp_struct[1], __temp_struct[2], int_to_ipv6(__temp_struct[4:12]),
                                            int_to_ipv6(__temp_struct[12:20]))
        self.payload = packet[40:40 + self.ip_header.len]


class IPv4(IP):
    __ip4_tuple__ = namedtuple("__ipv4", "IHL, tos, len, id, flags, fragment_offset, ttl, protocol, chksum, src, dst")

    def __init__(self, packet):
        super().__init__()
        __version_and_IHL = struct.unpack("!B", packet[:1])[0]
        __version = __version_and_IHL >> 4
        __IHL = __version_and_IHL & 0x0f
        if __version != 4:
            raise TypeError("Not IPv4 Header.")
        (__tos, __len, __id, __temp_off_flag, __ttl, __protocol, __chksum, __src, __dst) = struct.unpack('!BHHHBBHII',
                                                                                                         packet[1:20])
        self.ip_header = self.__ip4_tuple__(__IHL, __tos, __len, __id, __temp_off_flag >> 13,
                                            __temp_off_flag & 0x1fff,
                                            __ttl, __protocol, __chksum, int_to_ipv4(__src), int_to_ipv4(__dst))
        self.payload = packet[(self.ip_header.IHL * 4):self.ip_header.len]


class LinkLayer:
    tcp_obj = None
    ip_obj = None
    __name__ = "LinkLayer"

    def get_tcp_obj(self):
        return self.tcp_obj

    def get_ip_obj(self):
        return self.ip_obj


class Ethernet(LinkLayer):
    __ethernet_tuple__ = namedtuple("__ethernet", "dst_mac, src_mac, type")
    __eth_header = None
    __name__ = "Ethernet"

    def __init__(self, packet):
        # should be device independent
        (__dst_mac, __src_mac, __temp_type) = struct.unpack("!6s6sH", packet[:14])
        # TCP analyzer, just need IP Header, which is IPv4 or IPv6
        if __temp_type == 0x0800:
            __type = "IPv4"
        elif __temp_type == 0x86DD:
            __type = "IPv6"
        else:
            __type = ""
        self.__eth_header = self.__ethernet_tuple__(bytearray(__dst_mac).hex(), bytearray(__src_mac).hex(), __type)
        __temp_objs = TCPIPWrapper(self.__eth_header.type, packet[14:])
        if __temp_objs:
            self.ip_obj, self.tcp_obj = __temp_objs
        else:
            self.ip_obj, self.tcp_obj = None, None


class Cap:
    __header_tuple__ = namedtuple("__header", "magic_number, major_version, minor_version, reserved1, reserved2, "
                                              "snap_len, link_type, order, ns")
    __packet_tuple__ = namedtuple("__packet", "timestamp, capture_len, packet_len")
    __file_obj = None

    # two magic numbers represent to ms/s or ns
    __MAGIC_NUMBER__ = 0xA1B23C4D
    __MAGIC_NUMBER_NS__ = 0xA1B2C3D4

    __header = None
    __progress = None
    __packets = []
    # tend to support Wi-Fi but it is too difficult
    __LINK_TYPE__ = {1: Ethernet}
    __instant = False

    def __init__(self, file_path: str, instant=False):
        # The File Header length is 24 octets, try to read first 24 bytes.
        self.__instant = instant
        print("Start reading file.")
        try:
            fp = open(file_path, 'rb')
            if not self.__instant:
                self.__progress = ProgressBar.ProgressBar(os.path.getsize(file_path), scale=40)
            __raw_header = fp.read(24)
        except UnicodeDecodeError as ue:
            # This may cause error, such as invalidate header or something
            raise IOError("Could not open and read file in binary mode, details {}.".format(ue))

        # big endian
        if __raw_header[:4] in [struct.pack(">I", self.__MAGIC_NUMBER__),
                                struct.pack(">I", self.__MAGIC_NUMBER_NS__)]:
            __order = "big"
            __temp_header = struct.unpack(">IHHIIII", __raw_header)
        # little endian
        elif __raw_header[:4] in [struct.pack("<I", self.__MAGIC_NUMBER__),
                                  struct.pack("<I", self.__MAGIC_NUMBER_NS__)]:
            __order = "little"
            __temp_header = struct.unpack("<IHHIIII", __raw_header)
        # invalid header/magic number/format
        else:
            raise SyntaxError("Invalid file with unknown magic number.")
        # try to solve with fcs, but seems like example file and file I captured by wireshark does not have this
        (__magic_number, __major_version, __minor_version, __reserved1, __reserved2, __snap_len,
         __link_type) = __temp_header
        self.__header = self.__header_tuple__(__magic_number, __major_version, __minor_version, __reserved1,
                                              __reserved2,
                                              __snap_len, __link_type, __order,
                                              __magic_number == self.__MAGIC_NUMBER_NS__)
        if not self.__validate_header():
            raise SyntaxError("Invalid header.")
        if __link_type not in self.__LINK_TYPE__.keys():
            raise TypeError("Does not support this link type: {}".format(__link_type))
        print("Reading version {}.{} {} endian order file {} with {} link type and {} snap length in {} mode.".format(
            __major_version,
            __minor_version,
            __order,
            file_path,
            self.__LINK_TYPE__[__link_type].__name__,
            __snap_len,
            "INSTANT" if instant else "FULL"))
        if not self.__instant:
            self.__progress.next(24)
            # Then read packets
            self.__file_obj = fp
            __read_pkt = 1
            __all_pkt = 1
            __pkt = self.__read_single_packet()
            while __pkt:
                if __pkt[1].get_ip_obj() is not None and __pkt[1].get_tcp_obj() is not None:
                    self.__packets.append(__pkt)
                    __read_pkt += 1
                __pkt = self.__read_single_packet()
                __all_pkt += 1
            self.__file_obj.close()
            print("Read {} packets from {} packets.".format(__read_pkt, __all_pkt))
        else:
            self.__file_obj = fp
            self.__packets = self

    def __validate_header(self):
        # reserved1 and 2 is not used - SHOULD be filled with 0 by pcap file writers, and MUST be ignored by pcap
        # file readers.
        if self.__header.reserved1 or self.__header.reserved2:
            return False
        if self.__header.magic_number not in [self.__MAGIC_NUMBER__, self.__MAGIC_NUMBER_NS__]:
            return False
        return True

    def __read_single_packet(self):
        __raw_pkt_header = self.__file_obj.read(16)
        # prevent from broken file
        if not __raw_pkt_header or len(__raw_pkt_header) != 16:
            return False
        if not self.__instant:
            self.__progress.next(16)
        # 16*8=128bits, 4*uint32
        # first with big endian
        if self.__header.order == "big":
            __packet_header = struct.unpack(">IIII", __raw_pkt_header)
        else:
            __packet_header = struct.unpack("<IIII", __raw_pkt_header)
        (__timestamp, __timestamp_us, __capture_len, __packet_len) = __packet_header
        __temp_packet_header = self.__packet_tuple__(Decimal(str(__timestamp) + "." + "{:0>6d}".format(__timestamp_us)),
                                                     __capture_len, __packet_len)

        # Then read packet data
        __raw_pkt_data = self.__file_obj.read(__capture_len)
        if not self.__instant:
            self.__progress.next(__capture_len)
        # also prevent from broken file
        if not __raw_pkt_data or len(__raw_pkt_data) != __capture_len:
            return False
        return __temp_packet_header, self.__LINK_TYPE__[self.__header.link_type](__raw_pkt_data)

    def __iter__(self):
        return self

    def __next__(self):
        __temp_result = self.__read_single_packet()
        if __temp_result:
            return __temp_result
        else:
            self.__file_obj.close()
            raise StopIteration

    def get_header(self):
        return self.__header

    def get_packets(self):
        return self.__packets
