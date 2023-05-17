import struct
from copy import deepcopy
from decimal import Decimal

import ProgressBar
from Cap.NetworkLayer import IPv4, IP, IPv6
from Cap.PCapDateTime import PCapDateTime
from Cap.TransportLayer import ICMP, UDP


def get_feature(ip_obj: IP):
    if isinstance(ip_obj.get_tp_obj(), ICMP):
        __os = "Windows"
        # Echo ping has seq number
        __feature = struct.unpack("!HH", ip_obj.get_tp_obj().get_header().rest)[1]
    else:
        if (ip_obj.get_tp_obj().get_header().dst_port >= 33434) \
                and (ip_obj.get_tp_obj().get_header().dst_port <= 33529):
            __os = "Linux"
            __feature = "{}".format(int(str(ip_obj.get_tp_obj().get_header().dst_port)))
        else:
            return None
    return __os, __feature


def unpack(ip_obj: IP):
    # Unpack, check packet pass in is ICMP packet
    if (not isinstance(ip_obj.get_tp_obj(), ICMP)) and (not isinstance(ip_obj.get_tp_obj(), UDP)):
        return None
    __temp_tp = ip_obj.get_tp_obj()
    if isinstance(__temp_tp, ICMP) and (__temp_tp.get_header().type == 11 or
                                        __temp_tp.get_header().type == 3):
        # Only ICMP 11 and 3 needs to unpack
        try:
            __temp_ip = IPv4(__temp_tp)
            __temp_ip.generate_tp_obj()
        except AssertionError:
            try:
                __temp_ip = IPv6(__temp_tp)
                __temp_ip.generate_tp_obj()
            except AssertionError:
                __temp_ip = ip_obj
    else:
        __temp_ip = ip_obj

    # See if it is UDP or ICMP
    if (not isinstance(__temp_ip.get_tp_obj(), ICMP)) and (not isinstance(__temp_ip.get_tp_obj(), UDP)):
        # conflict
        return None

    __temp_return = get_feature(__temp_ip)
    if __temp_return:
        __os, __feature = __temp_return
        return __temp_ip, __os, __feature
    return None


class Traceroute:
    def __init__(self, first_router_ip_datagram: IP):
        self.__src = ""
        self.__dst = ""
        self.__feature = 0  # if Linux, it is UDP dst port, if Windows, it is ICMP sequence number
        self.__os = ""
        self.__route = deepcopy([])
        self.__statistics = {}.copy()
        self.__last_offset = 0
        self.__now_route_pointer = 0
        self.__probes = deepcopy({1: 0})

        __temp_return = unpack(first_router_ip_datagram)
        assert __temp_return
        __temp_ip, __os, __feature = __temp_return
        if isinstance(__temp_ip.get_tp_obj(), ICMP):
            assert __temp_ip.get_tp_obj().get_header().type == 8
        elif isinstance(__temp_ip.get_tp_obj(), UDP):
            assert 33434 <= __temp_ip.get_tp_obj().get_header().dst_port <= 33529
        self.__src = __temp_ip.get_header().src
        self.__dst = __temp_ip.get_header().dst
        self.__os = __os
        self.__feature = __feature
        self.add_send(first_router_ip_datagram)

    def __hash__(self):
        return hash("{0} -> {1} [{2}, {3}]".format(
            str(self.__src), str(self.__dst), str(self.__feature), self.__os))

    def get_route(self):
        return self.__route

    def add_send(self, ip_datagram: IP):
        __temp_return = unpack(ip_datagram)
        if __temp_return:
            __temp_ip, __os, __feature = __temp_return
        else:
            return
        self.__probes[ip_datagram.get_header().ttl] = self.__probes.get(ip_datagram.get_header().ttl, 0) + 1
        self.__route.append(ip_datagram)
        self.__feature = int(__feature)
        self.__now_route_pointer += 1

    def add_receive(self, ip_datagram: IP):
        __temp_return = unpack(ip_datagram)
        if __temp_return:
            __temp_ip, __os, __feature = __temp_return
            self.__feature += 1
            self.__route.append(ip_datagram)
            self.__now_route_pointer += 1
        else:
            return

    def add_void_receive(self):
        self.__feature += 1
        self.__route.append(None)
        self.__now_route_pointer += 1

    def get_src(self):
        return self.__src

    def get_dst(self):
        return self.__dst

    def get_os(self):
        return self.__os

    def __str__(self):
        # for debug
        return "Traceroute: [{} -> {}, {}, {} packets]".format(self.__src, self.__dst, self.__os, len(self.__route))

    def statistics(self):
        __send_ts = None
        __routes = deepcopy([])
        __now_route = None
        __rtt = deepcopy([])
        __sd = deepcopy([])
        __fragments = deepcopy([])
        __last_offsets = deepcopy([])
        __used_time = None

        __avg_rtt = PCapDateTime(Decimal(0), calculated=True)
        __now_rtt = deepcopy({})

        for key in range(len(self.__route)):
            if not __send_ts:
                if not self.__route[key]:
                    # TODO: Fix: Continuous empty packets can not be record properly.
                    #  Comment: No need to fix because there's no continuous empty packets.
                    # Send could not be none because it is generated by local
                    continue
                if self.__route[key].is_fragmented() and not self.__route[key].used_for_fragments:
                    # fragmentation details
                    __fragments.append(self.__route[key].get_fragments())
                    __last_offsets.append(self.__route[key].last_offset)

                if self.__route[key].get_header().src == self.__src and self.__route[
                    key].get_header().dst == self.__dst:
                    # new send side packet
                    # init timestamp and fragmentation used_time
                    __send_ts = self.__route[key].timestamp
                    __used_time = self.__route[key].used_time

            else:
                # next is sending packet
                if not self.__route[key]:
                    # no response
                    __send_ts = None
                    continue

                __now_route = self.__route[key].get_header().src

                if __now_route not in __routes:
                    # new route
                    __routes.append(__now_route)
                __temp_rtt = __now_rtt.get(__now_route, deepcopy([]))
                __temp_rtt.append(
                    PCapDateTime(self.__route[key].timestamp - __send_ts - __used_time, calculated=True))
                __now_rtt[__now_route] = __temp_rtt
                __send_ts = None

        for route in __routes:
            __avg_rtt = sum(rtt for rtt in __now_rtt[route]) / len(__now_rtt[route])
            __rtt.append(__avg_rtt)
            __sd.append(Decimal(
                sum((rtt - __avg_rtt).get_source_ts() ** 2 for rtt in __now_rtt[route]) / len(__now_rtt[route])).sqrt())

        return __routes, __rtt, __sd, __fragments, __last_offsets, max(self.__probes.values())


class Statistic:

    def __init__(self, packets, instant=False, ns=False, printout=True):
        self.win_traceroute_pkt = []
        self.linux_traceroute_pkt = []
        self.sessions = []
        self.ip_list = deepcopy([])
        self.complete_ip_list = []

        self.ns = ns
        if printout:
            print("Traceroute statistic in progress.")
        if not instant:
            __p = ProgressBar.ProgressBar(len(packets), scale=40)
        for packet in packets:
            if not instant:
                __p.next()
            try:
                if packet.link_obj.get_net_obj() is None:
                    continue
            except:
                continue
            if isinstance(packet.link_obj.get_net_obj(), IP):
                self.ip_list.append(packet.link_obj.get_net_obj())

        for frag in range(len(self.ip_list)):
            # print(self.ip_list[frag], self.ip_list[frag].fragmented, self.ip_list[frag].used_for_fragments)
            if self.ip_list[frag].fragmented and not self.ip_list[frag].used_for_fragments:
                self.ip_list[frag].used_for_fragments = False
                for find in range(frag + 1, len(self.ip_list)):
                    if self.ip_list[find].used_for_fragments:
                        continue
                    if self.ip_list[frag].get_header().id == self.ip_list[find].get_header().id:
                        # fragments, but not itself
                        self.ip_list[find].used_for_fragments = True
                        self.ip_list[frag].add(self.ip_list[find])

        for complete_ips in self.ip_list:
            if not complete_ips.used_for_fragments:
                self.complete_ip_list.append(complete_ips)

        for ip in self.complete_ip_list:
            if (isinstance(ip.get_tp_obj(), ICMP)
                    and (ip.get_tp_obj().get_header().type == 8 or
                         ip.get_tp_obj().get_header().type == 11 or
                         ip.get_tp_obj().get_header().type == 0)):
                self.win_traceroute_pkt.append(ip)

            if ((isinstance(ip.get_tp_obj(), UDP) and
                 (33434 <= ip.get_tp_obj().get_header().dst_port <= 33529)) or
                    (isinstance(ip.get_tp_obj(), ICMP) and
                     (ip.get_tp_obj().get_header().type == 3 or
                      ip.get_tp_obj().get_header().type == 11))):
                self.linux_traceroute_pkt.append(ip)

        __now_session = None
        # TODO: Fix: When multiple Traceroute runs in parallel,
        #   packets are added in a chaotic order,
        #   and the sending and receiving packets do not correspond to each other.
        #  COMMENT: No need to fix because there's no multiple Traceroute client runs in parallel.
        #   BTW, when multiple Traceroute client exist, the sequence/port number should not be the identity.
        for ip in self.win_traceroute_pkt:
            if ip.used:
                continue
            if isinstance(ip.get_tp_obj(), ICMP) and ip.get_tp_obj().get_header().type == 8:
                __send_flag = False
                __recv_flag = False
                __now_session = None
                __temp_return = get_feature(ip)
                if __temp_return:
                    _, __send_feature = __temp_return
                else:
                    continue
                __send_hash = hash("{0} -> {1} [{2}, {3}]".format(
                    str(ip.get_header().src),
                    str(ip.get_header().dst),
                    str(__send_feature), "Windows"))

                for i in range(len(self.sessions)):
                    if self.sessions[i].__hash__() == __send_hash:
                        ip.used = True
                        self.sessions[i].add_send(ip)
                        __now_session = self.sessions[i]
                        __send_flag = True
                        break

                if not __send_flag and (ip.get_header().ttl == 1):
                    ip.used = True
                    __temp_session = Traceroute(ip)

                    self.sessions.append(__temp_session)
                    __now_session = __temp_session

                if not __send_flag and not __now_session:
                    continue

                for recv_pkt in self.win_traceroute_pkt:
                    if recv_pkt.used:
                        continue
                    if isinstance(recv_pkt.get_tp_obj(), ICMP) \
                            and (recv_pkt.get_tp_obj().get_header().type == 11 or
                                 recv_pkt.get_tp_obj().get_header().type == 0):
                        if recv_pkt.get_tp_obj().get_header().type != 0:
                            __temp_return = unpack(recv_pkt)
                            if __temp_return:
                                __temp_ip, _, __temp_feature = __temp_return
                                __temp_hash = hash("{0} -> {1} [{2}, {3}]".format(
                                    str(__temp_ip.get_header().src), str(__temp_ip.get_header().dst),
                                    str(__temp_feature), "Windows"))
                        else:
                            _, __temp_feature = get_feature(recv_pkt)
                            __temp_hash = hash("{0} -> {1} [{2}, {3}]".format(
                                str(recv_pkt.get_header().dst), str(recv_pkt.get_header().src),
                                str(__temp_feature), "Windows"))
                        if __send_hash == __temp_hash:
                            recv_pkt.used = True
                            __now_session.add_receive(recv_pkt)
                            __recv_flag = True
                            break
                        else:
                            continue
                if not __recv_flag:
                    __now_session.add_void_receive()

        for ip in self.linux_traceroute_pkt:
            if ip.used:
                continue
            if isinstance(ip.get_tp_obj(), UDP):
                __send_flag = False
                __recv_flag = False
                __now_session = None
                __temp_return = get_feature(ip)
                if __temp_return:
                    _, __send_feature = __temp_return
                else:
                    continue
                __send_hash = hash("{0} -> {1} [{2}, {3}]".format(
                    str(ip.get_header().src),
                    str(ip.get_header().dst),
                    str(__send_feature), "Linux"))

                for i in range(len(self.sessions)):
                    if self.sessions[i].__hash__() == __send_hash:
                        ip.used = True
                        self.sessions[i].add_send(ip)
                        __now_session = self.sessions[i]
                        __send_flag = True
                        break

                if not __send_flag and (ip.get_header().ttl == 1):
                    ip.used = True
                    __temp_session = Traceroute(ip)

                    self.sessions.append(__temp_session)
                    __now_session = __temp_session

                if not __send_flag and not __now_session:
                    continue

                for recv_pkt in self.linux_traceroute_pkt:
                    if recv_pkt.used:
                        continue
                    if isinstance(recv_pkt.get_tp_obj(), ICMP) \
                            and (recv_pkt.get_tp_obj().get_header().type == 11 or
                                 recv_pkt.get_tp_obj().get_header().type == 3):

                        __temp_return = unpack(recv_pkt)
                        if __temp_return:
                            __temp_ip, _, __temp_feature = __temp_return
                            __temp_hash = hash("{0} -> {1} [{2}, {3}]".format(
                                str(__temp_ip.get_header().src), str(__temp_ip.get_header().dst),
                                str(__temp_feature), "Linux"))

                        if __send_hash == __temp_hash:
                            recv_pkt.used = True
                            __now_session.add_receive(recv_pkt)
                            __recv_flag = True
                            break
                        else:
                            continue
                if not __recv_flag:
                    __now_session.add_void_receive()

    def get_statistics_data(self):
        if not self.sessions:
            return None
        for i in self.sessions:
            __routes, __rtt, __sd, __fragments, __last_offsets, __max_probes = i.statistics()
        return __routes, __rtt, __sd, __fragments, __last_offsets, __max_probes

    def print(self):
        __protocols = []
        __protocols_dict = {1: "ICMP", 17: "UDP", 6: "TCP", 41: "IPv6"}

        for ip in self.complete_ip_list:
            if ip:
                __protocols.append(ip.get_header().protocol)

        for i in self.sessions:
            print(i)
            print()
            # below is for debug
            # continue
            # for r in range(len(i.get_route())):
            # if not i.get_route()[r]:
            # continue
            # print(i.get_route()[r].get_header().src, i.get_route()[r].get_header().ttl, i.get_route()[r].timestamp)
            # pass
            __routes, __rtt, __sd, __fragments, __last_offsets, _ = i.statistics()
            print("The IP address of the source node: {}".format(i.get_src()))
            print("The IP address of ultimate destination node: {}".format(i.get_dst()))
            print("The IP addresses of the intermediate destination nodes:")
            for index in range(len(__routes)):
                if index != len(__routes) - 1:
                    print("\troute {}: {},".format(index + 1, __routes[index]))
                else:
                    print("\troute {}: {}.".format(index + 1, __routes[index]))
            print()
            print("The values in the protocol field of IP headers:")
            for p in sorted(set(__protocols)):
                if p:
                    print("\t{}: {}".format(p, __protocols_dict[p]))
            print()
            if len(__fragments) <= 1:
                print("The number of fragments created from the original datagram is: {}".format(
                    __fragments[0] if __fragments else 0))
                print("The offset of the last fragment is: {}".format(__last_offsets[0] if __last_offsets else 0))
            else:
                for index in range(len(__fragments)):
                    print(
                        "The number of fragments created from the original datagram D{} is: {}".format(index + 1,
                                                                                                       __fragments[
                                                                                                           index]))
                    print("The offset of the last fragment is: {}".format(__last_offsets[index]))
            print()
            for index in range(len(__routes)):
                print("The avg RTT between {} and {} is: {}, the s.d. is: {:.4f}".format(i.get_src(), __routes[index],
                                                                                         __rtt[index], __sd[index]))
            print()
            print()
