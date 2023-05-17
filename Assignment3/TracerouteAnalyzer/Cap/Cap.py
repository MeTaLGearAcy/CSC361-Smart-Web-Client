import os
import struct
from collections import namedtuple
from copy import deepcopy
from decimal import Decimal

import ProgressBar
from . import LinkLayer
from .PCapDateTime import PCapDateTime


class Cap:
    """
    Cap file object.
    """
    __header_tuple__ = namedtuple("__header", "magic_number, major_version, minor_version, reserved1, reserved2, "
                                              "snap_len, link_type, order, ns")
    __packet_tuple__ = namedtuple("__packet", "timestamp, capture_len, packet_len, link_obj")

    # two magic numbers represent to ms/s or ns
    __MAGIC_NUMBER__ = 0xA1B23C4D
    __MAGIC_NUMBER_NS__ = 0xA1B2C3D4
    # tend to support Wi-Fi but it is too difficult
    __LINK_TYPE__ = {1: LinkLayer.Ethernet}

    def __init__(self, file_path: str, instant=False, printout=True):
        """
        Open PCap file and try to read it header.

        :param file_path: PCap file path to open.
        :param instant: Instant mode, default is False. Process bar will show if True.
        """
        # The file Header length is 24 octets, try to read first 24 bytes.
        self.instant = instant
        self.packets = deepcopy([])
        if printout:
            print("Start reading file.")
        try:
            fp = open(file_path, 'rb')
            if not self.instant:
                self.progress = ProgressBar.ProgressBar(os.path.getsize(file_path), scale=40)
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
        self.header = self.__header_tuple__(__magic_number, __major_version, __minor_version, __reserved1,
                                            __reserved2,
                                            __snap_len, __link_type, __order,
                                            __magic_number == self.__MAGIC_NUMBER_NS__)
        if not self.__validate_header():
            raise SyntaxError("Invalid header.")
        if __link_type not in self.__LINK_TYPE__.keys():
            raise TypeError("Does not support this link type: {}".format(__link_type))
        if printout:
            print("Reading version {}.{} {} endian order file {} with {} link type and {} snap length in {} mode.".format(
                __major_version,
                __minor_version,
                __order,
                file_path,
                self.__LINK_TYPE__[__link_type].__name__,
                __snap_len,
                "INSTANT" if instant else "FULL"))
        if not self.instant:
            self.progress.next(24)
            # Then read packets
            self.file_obj = fp
            __read_pkt = 1
            __all_pkt = 1
            __pkt = self.read_single_packet()
            while __pkt:
                # Judgement should be the problem of statistic. I just need to pack all link layer packet.
                # if __pkt[1].get_ip_obj() is not None and __pkt[1].get_tcp_obj() is not None:
                self.packets.append(__pkt)
                __read_pkt += 1
                __pkt = self.read_single_packet()
                __all_pkt += 1
            self.file_obj.close()
            print("Read {} packets from {} packets.".format(__read_pkt, __all_pkt))
        else:
            self.file_obj = fp
            self.packets = self

    def __validate_header(self):
        """
        Validate pcap file header.

        :return: True if it is valid.
        """
        # > reserved1 and 2 is not used - SHOULD be filled with 0 by pcap file writers, and MUST be ignored by pcap
        # file readers.
        if self.header.reserved1 or self.header.reserved2:
            return False
        if self.header.magic_number not in [self.__MAGIC_NUMBER__, self.__MAGIC_NUMBER_NS__]:
            return False
        return True

    def read_single_packet(self):
        """
        Read next one packet.

        :return: This pcap header and link layer packet.
        """
        __raw_pkt_header = self.file_obj.read(16)
        # prevent from broken file
        if not __raw_pkt_header or len(__raw_pkt_header) != 16:
            return False
        if not self.instant:
            self.progress.next(16)
        # 16*8=128bits, 4*uint32
        # first with big endian
        if self.header.order == "big":
            __packet_header = struct.unpack(">IIII", __raw_pkt_header)
        else:
            __packet_header = struct.unpack("<IIII", __raw_pkt_header)
        (__timestamp, __timestamp_us, __capture_len, __packet_len) = __packet_header
        # Then read packet data
        __raw_pkt_data = self.file_obj.read(__capture_len)
        if not self.instant:
            self.progress.next(__capture_len)
        # also prevent from broken file
        if not __raw_pkt_data or len(__raw_pkt_data) != __capture_len:
            return False
        if self.header.ns:
            __temp_ts = Decimal(str(__timestamp) + "." + "{:0<9d}".format(__timestamp_us))
        else:
            __temp_ts = Decimal(str(__timestamp) + "." + "{:0>9d}".format(__timestamp_us))
        __temp_ts_obj = PCapDateTime(__temp_ts)
        __temp_packet_header = self.__packet_tuple__(__temp_ts_obj,
                                                     __capture_len, __packet_len,
                                                     self.__LINK_TYPE__[self.header.link_type]({
                                                         "timestamp": __temp_ts_obj,
                                                         "capture_len": __capture_len,
                                                         "packet_len": __packet_len,
                                                         "raw_packet_data": __raw_pkt_data}))

        return __temp_packet_header

    def __iter__(self):
        """
        For instant mode.

        :return: Self.
        """
        return self

    def __next__(self):
        """
        For instant mode, returns an iterator which is function __read_single_packet().

        :return: Iterator, generated by function __read_single_packet().
        """
        __temp_result = self.read_single_packet()
        if __temp_result:
            return __temp_result
        else:
            self.file_obj.close()
            raise StopIteration

    def get_header(self):
        """
        Simple getter of PCap file header.

        :return: Header.
        """
        return self.header

    def get_packets(self):
        """
        Simple getter of packets(iterator).

        :return: Packets list or packets iterator(for p in get_packets():).
        """
        return self.packets
