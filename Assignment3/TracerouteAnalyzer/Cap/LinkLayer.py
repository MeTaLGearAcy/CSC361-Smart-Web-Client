import struct
from collections import namedtuple

from Cap.NetworkLayer import IP, IPv4, IPv6
from Cap.TransportLayer import TCP


class LinkLayer:
    """
    Link layer parent class.
    """

    # Facilitate statistic.
    net_obj = None
    payload = None
    physics = None
    header = None

    __name__ = "LinkLayer"

    def __init__(self, physics):
        self.physics = physics

    # @deprecated("Use get_net_obj().get_tp_obj() instead and judge it by yourself.")
    def get_tcp_obj(self):
        """
        Suit for older call.

        :return: TCP object.
        """
        if isinstance(self.get_net_obj(), IP):
            if isinstance(self.get_net_obj().get_tp_obj(), TCP):
                return self.get_net_obj().get_tp_obj()
        return None

    # @deprecated("Use get_net_obj() instead and judge it by yourself.")
    def get_ip_obj(self):
        """
        Suit for older call.

        :return: IP object.
        """
        if isinstance(self.get_net_obj(), IP):
            return self.get_net_obj()
        return None

    def get_net_obj(self):
        """
        Simple getter return network layer object.

        :return: Network layer object.
        """
        return self.net_obj

    def generate_net_obj(self, protocol_type):
        """
        Generate network layer object.

        :param protocol_type: Type of protocol to judge.
        """
        pass

    def get_payload(self):
        """
        Simple getter of payload of link layer(network layer packet).
        :return: Payload in link layer.
        """
        return self.payload

    def get_physics(self):
        return self.physics

    def get_header(self):
        return self.header

    def gc(self):
        del self.physics


class Ethernet(LinkLayer):
    """
    Ethernet kind of link layer.
    """
    __ethernet_tuple__ = namedtuple("__ethernet", "dst_mac, src_mac")

    __name__ = "Ethernet"

    def __init__(self, physics):
        """
        Just give me a raw eth packet.

        :param physics: Physics layer obj(PCap packet obj).
        """
        # should be device independent
        super().__init__(physics)
        packet = physics["raw_packet_data"]
        (__dst_mac, __src_mac, __temp_type) = struct.unpack("!6s6sH", packet[:14])
        self.header = self.__ethernet_tuple__(bytearray(__dst_mac).hex(), bytearray(__src_mac).hex())
        self.payload = packet[14:]
        self.generate_net_obj(__temp_type)

    def generate_net_obj(self, protocol_type):
        # TCP/IP analyzer, just need IP Header, which is IPv4 or IPv6
        try:
            if protocol_type == 0x0800:
                self.net_obj = IPv4(self)
            elif protocol_type == 0x86DD:
                self.net_obj = IPv6(self)
        except AssertionError:
            pass
