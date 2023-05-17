import ProgressBar
from Cap import TCP


class TCPConnection:
    # I'm trying to use dict first, but the dict takes the same memory even after I use copy.deepcopy()
    src = ""
    src_port = ""
    dst = ""
    dst_port = ""
    flags = ""
    complete = False
    start = 0.0
    end = 0.0
    last_time = 0.0
    last_ack = -1
    last_send_seq = -1
    last_recv_seq = -1
    last_size = -1
    open = False
    duration = 0.0
    send_packets = 0
    recv_packets = 0
    packets = 0
    send_bytes = 0
    recv_bytes = 0
    max_rtt = 0
    min_rtt = 999999999
    mean_rtt = 0
    last_send_index = -1
    last_recv_index = -1
    max_window = 0
    min_window = 999999999
    mean_window = 0
    last_status = "send"
    rtt_num = 0

    def __init__(self, init_packet: TCP, index):
        # Trust init_packet
        self.src = init_packet.get_tcp_header().src
        self.src_port = init_packet.get_tcp_header().src_port
        self.dst = init_packet.get_tcp_header().dst
        self.dst_port = init_packet.get_tcp_header().dst_port
        self.start = init_packet.get_tcp_header().ts
        self.max_window = init_packet.get_tcp_header().window
        self.min_window = init_packet.get_tcp_header().window
        self.mean_window = init_packet.get_tcp_header().window
        self.last_time = init_packet.get_tcp_header().ts
        self.last_ack = init_packet.get_tcp_header().ack_num
        self.send_packets = 1
        self.packets = 1
        self.flags += self.generate_flag(init_packet)
        self.last_send_seq = init_packet.get_tcp_header().seq
        self.last_send_index = index

    def generate_flag(self, pkt: TCP):
        __rtn_flags = ""
        if pkt.get_tcp_header().syn == 1:
            __rtn_flags += "S"
        elif pkt.get_tcp_header().fin == 1:
            __rtn_flags += "F"
        if pkt.get_tcp_header().rst == 1:
            __rtn_flags += "R"
        return __rtn_flags

    def add_send(self, pkt: TCP, index):
        self.last_ack = pkt.get_tcp_header().ack_num
        self.last_size = pkt.get_tcp_header().payload_size
        self.flags += self.generate_flag(pkt)
        self.send_packets += 1
        self.packets += 1
        self.send_bytes += pkt.get_tcp_header().payload_size
        if self.last_status != "send":
            # calculate RTT
            self.rtt_num += 1
            __temp_rtt = abs(pkt.get_tcp_header().ts - self.last_time)
            if __temp_rtt >= self.max_rtt:
                self.max_rtt = __temp_rtt
            if __temp_rtt <= self.min_rtt:
                self.min_rtt = __temp_rtt
            self.mean_rtt += (__temp_rtt - self.mean_rtt) / self.rtt_num
        self.last_status = "send"
        self.last_time = pkt.get_tcp_header().ts
        # calculate window
        self.mean_window = abs(pkt.get_tcp_header().window - self.mean_window) / self.packets
        if pkt.get_tcp_header().window >= self.max_window:
            self.max_window = pkt.get_tcp_header().window
        if pkt.get_tcp_header().window <= self.min_window:
            self.min_window = pkt.get_tcp_header().window
        self.last_send_seq = pkt.get_tcp_header().seq
        self.last_send_index = index

    def add_recv(self, pkt: TCP, index):
        self.last_time = pkt.get_tcp_header().ts
        self.last_ack = pkt.get_tcp_header().ack_num
        self.last_size = pkt.get_tcp_header().payload_size
        self.flags += self.generate_flag(pkt)
        self.recv_packets += 1
        self.packets += 1
        self.recv_bytes += pkt.get_tcp_header().payload_size
        if self.last_status != "recv":
            # calculate RTT
            self.rtt_num += 1
            __temp_rtt = abs(pkt.get_tcp_header().ts - self.last_time)
            if __temp_rtt >= self.max_rtt:
                self.max_rtt = __temp_rtt
            if __temp_rtt <= self.min_rtt:
                self.min_rtt = __temp_rtt
            self.mean_rtt += (__temp_rtt - self.mean_rtt) / self.rtt_num
        self.last_status = "recv"
        # calculate window
        self.mean_window = abs(pkt.get_tcp_header().window - self.mean_window) / self.packets
        if pkt.get_tcp_header().window >= self.max_window:
            self.max_window = pkt.get_tcp_header().window
        if pkt.get_tcp_header().window <= self.min_window:
            self.min_window = pkt.get_tcp_header().window
        self.last_recv_seq = pkt.get_tcp_header().seq
        self.last_recv_index = index

    def close(self, close_pkt: TCP):
        # Trust close packet
        self.complete = True
        self.end = close_pkt.get_tcp_header().ts
        self.duration = self.end - self.start
        if self.src == close_pkt.get_tcp_header().src:
            # close by client
            self.add_send(close_pkt, -1)
        else:
            self.add_recv(close_pkt, -1)


class Statistic:
    __tcps = {}
    __tcp_connections = []

    def __init__(self, packets, instant=False, ns=False):
        self.ns = ns
        print("TCP connections statistic in progress.")
        if not instant:
            __p = ProgressBar.ProgressBar(len(packets), scale=40)
        for link_pkt, net_pkt in packets:
            try:
                if net_pkt.get_ip_obj() is None or net_pkt.get_tcp_obj() is None:
                    continue
            except:
                continue

            __temp_list = self.__tcps.get(net_pkt.get_tcp_obj().__hash__(), [])
            net_pkt.get_tcp_obj().set_timestamp(link_pkt.timestamp)
            __temp_list.append(net_pkt.get_tcp_obj())
            self.__tcps[net_pkt.get_tcp_obj().__hash__()] = __temp_list
            if not instant:
                __p.next(1)
        # First sort with timestamp because there could be more than one direction with same (src:port, dst:port)
        for i in self.__tcps.keys():
            self.__tcps[i] = sorted(self.__tcps[i], key=lambda t: t.get_tcp_header().ts)

        for i in self.__tcps.keys():
            for tcp in range(len(self.__tcps[i])):

                if self.__tcps[i][tcp].used:
                    continue
                if self.__tcps[i][tcp].get_tcp_header().syn == 1 and self.__tcps[i][tcp].get_tcp_header().ack == 0 and \
                        self.__tcps[i][tcp].get_tcp_header().fin == 0:
                    # valid start packet, track this connection
                    self.__tcps[i][tcp].used = True

                    temp_tcp_connection = TCPConnection(self.__tcps[i][tcp], tcp)

                    # find from dst to src
                    __dst_hash = \
                        str(hex(
                            hash(
                                temp_tcp_connection.dst + ":"
                                + temp_tcp_connection.dst_port
                                + temp_tcp_connection.src + ":" + temp_tcp_connection.src_port)))
                    if self.__tcps.get(__dst_hash, None):
                        for dst_tcp in range(len(self.__tcps[__dst_hash])):
                            if self.__tcps[__dst_hash][dst_tcp].used:
                                continue
                            if self.__tcps[__dst_hash][dst_tcp].get_tcp_header().ack_num == (
                                    self.__tcps[i][tcp].get_tcp_header().seq + 1):
                                if self.__tcps[__dst_hash][dst_tcp].get_tcp_header().syn == 1 and \
                                        self.__tcps[__dst_hash][dst_tcp].get_tcp_header().ack == 1:
                                    # found valid response
                                    self.__tcps[__dst_hash][dst_tcp].used = True
                                    temp_tcp_connection.add_recv(self.__tcps[__dst_hash][dst_tcp], dst_tcp)

                                    # continue tracing client
                                    for tcp_1 in range(len(self.__tcps[i])):
                                        if self.__tcps[i][tcp_1].get_tcp_header().ack_num == (
                                                self.__tcps[__dst_hash][dst_tcp].get_tcp_header().seq + 1):
                                            if self.__tcps[i][tcp_1].get_tcp_header().ack == 1:
                                                # found valid client
                                                # open but not close
                                                temp_tcp_connection.open = True
                                                self.__tcps[i][tcp_1].used = True
                                                temp_tcp_connection.add_send(self.__tcps[i][tcp_1], tcp_1)
                                            if self.__tcps[i][tcp_1].get_tcp_header().rst == 1:
                                                self.__tcps[i][tcp_1].used = True
                                                temp_tcp_connection.add_recv(self.__tcps[i][tcp_1], tcp_1)
                                                break
                                if self.__tcps[__dst_hash][dst_tcp].get_tcp_header().rst == 1:
                                    self.__tcps[__dst_hash][dst_tcp].used = True
                                    temp_tcp_connection.add_recv(self.__tcps[__dst_hash][dst_tcp], dst_tcp)
                                    break
                    if "R" in temp_tcp_connection.flags:
                        temp_tcp_connection.open = False
                    if temp_tcp_connection.open:
                        # continue tracing
                        __no_more = False
                        while not __no_more:
                            __no_more = True
                            for normal_send in range(len(self.__tcps[i])):
                                if self.__tcps[i][normal_send].used:
                                    continue

                                if self.__tcps[i][normal_send].get_tcp_header().seq == \
                                        temp_tcp_connection.last_ack:
                                    # found pkt send by client
                                    __no_more = False
                                    self.__tcps[i][normal_send].used = True
                                    # try find
                                    # continue checking if more pkt send before server's ack
                                    temp_tcp_connection.add_send(self.__tcps[i][normal_send], normal_send)
                                    for more_send in range(len(self.__tcps[i])):
                                        if self.__tcps[i][more_send].used:
                                            continue
                                        if self.__tcps[i][more_send].get_tcp_header().seq == \
                                                temp_tcp_connection.last_ack + \
                                                temp_tcp_connection.last_size:
                                            # found more
                                            self.__tcps[i][more_send].used = True
                                            temp_tcp_connection.add_send(self.__tcps[i][more_send], more_send)
                                            # continue finding more
                                            continue
                                    for recv in range(len(self.__tcps[__dst_hash])):
                                        if self.__tcps[__dst_hash][recv].used:
                                            continue
                                        if self.__tcps[__dst_hash][recv].get_tcp_header().seq == \
                                                temp_tcp_connection.last_ack + \
                                                temp_tcp_connection.last_size:
                                            # found more
                                            self.__tcps[__dst_hash][recv].used = True
                                            temp_tcp_connection.add_recv(self.__tcps[__dst_hash][recv], recv)
                                            # continue finding more
                                            continue
                        # find close packets
                        # RST shows only after steps above
                        __rst = False
                        for client_tcp in range(len(self.__tcps[i])):
                            # find client first. it can close by any direction

                            if self.__tcps[i][client_tcp].get_tcp_header().fin == 1:
                                self.__tcps[i][client_tcp].used = True
                                temp_tcp_connection.add_send(self.__tcps[i][client_tcp], client_tcp)
                                # check if rst
                                if self.__tcps[i][client_tcp].get_tcp_header().seq == \
                                        temp_tcp_connection.last_send_seq + 1 and \
                                        self.__tcps[i][client_tcp].get_tcp_header().rst == 1:
                                    # RST send by client
                                    temp_tcp_connection.add_send(self.__tcps[i][client_tcp], client_tcp)
                                    __rst = True
                                    break
                                # check recv's ack
                                for server_tcp in range(len(self.__tcps[__dst_hash])):
                                    if self.__tcps[__dst_hash][server_tcp].used:
                                        continue
                                    if self.__tcps[__dst_hash][server_tcp].get_tcp_header().fin == 0 and \
                                            self.__tcps[__dst_hash][server_tcp].get_tcp_header().ack_num == \
                                            self.__tcps[i][client_tcp].get_tcp_header().seq + 1:
                                        self.__tcps[__dst_hash][server_tcp].used = True
                                        temp_tcp_connection.add_recv(self.__tcps[__dst_hash][server_tcp], server_tcp)
                                        # check recv's fin
                                        if server_tcp + 1 >= len(self.__tcps[__dst_hash]):
                                            break
                                        if self.__tcps[__dst_hash][server_tcp + 1].get_tcp_header().fin == 1:
                                            self.__tcps[__dst_hash][server_tcp + 1].used = True
                                            temp_tcp_connection.add_recv(
                                                self.__tcps[__dst_hash][server_tcp + 1], server_tcp + 1)
                                            # check client's ack
                                            for client_ack_tcp in range(len(self.__tcps[i])):
                                                if self.__tcps[i][client_ack_tcp].used:
                                                    continue
                                                if self.__tcps[i][client_ack_tcp].get_tcp_header().fin == 1 \
                                                        and self.__tcps[i][
                                                    client_ack_tcp].get_tcp_header().ack_num == \
                                                        temp_tcp_connection.last_recv_seq + 1:
                                                    self.__tcps[i][client_ack_tcp].used = True
                                                    temp_tcp_connection.close(
                                                        self.__tcps[i][client_ack_tcp])
                                                    # check if rst
                                                if self.__tcps[i][client_ack_tcp].get_tcp_header().seq == \
                                                        temp_tcp_connection.last_recv_seq + 1 and \
                                                        self.__tcps[i][
                                                            client_ack_tcp].get_tcp_header().rst == 1:
                                                    # RST send by client
                                                    temp_tcp_connection.add_send(
                                                        self.__tcps[i][client_ack_tcp], client_ack_tcp)
                                                    __rst = True
                                                    break
                                            # check if rst
                                            if self.__tcps[__dst_hash][server_tcp].get_tcp_header().seq == \
                                                    temp_tcp_connection.last_recv_seq + 1 and \
                                                    self.__tcps[__dst_hash][
                                                        server_tcp].get_tcp_header().rst == 1:
                                                # RST send by client
                                                temp_tcp_connection.add_send(self.__tcps[__dst_hash][server_tcp],
                                                                             server_tcp)
                                                __rst = True
                                                break

                                    # check if rst
                                    if self.__tcps[__dst_hash][server_tcp].get_tcp_header().seq == \
                                            temp_tcp_connection.last_recv_seq + 1 and \
                                            self.__tcps[__dst_hash][server_tcp].get_tcp_header().rst == 1:
                                        # RST send by client
                                        temp_tcp_connection.add_send(self.__tcps[__dst_hash][server_tcp], server_tcp)
                                        __rst = True
                                        break

                            if self.__tcps[i][client_tcp].get_tcp_header().seq == \
                                    temp_tcp_connection.last_send_seq + 1 and \
                                    self.__tcps[i][client_tcp].get_tcp_header().rst == 1:
                                # RST send by client
                                temp_tcp_connection.add_send(self.__tcps[i][client_tcp], client_tcp)
                                __rst = True
                                break
                        if "FF" in temp_tcp_connection.flags:
                            # close manually
                            temp_tcp_connection.complete = True
                            temp_tcp_connection.end = temp_tcp_connection.last_time
                            temp_tcp_connection.duration = temp_tcp_connection.end - temp_tcp_connection.start

                        if not __rst and not temp_tcp_connection.complete:
                            for serv_tcp in range(len(self.__tcps[__dst_hash])):
                                # find client first. it can close by any direction

                                if self.__tcps[__dst_hash][serv_tcp].get_tcp_header().fin == 1:
                                    self.__tcps[__dst_hash][serv_tcp].used = True
                                    temp_tcp_connection.add_send(self.__tcps[__dst_hash][serv_tcp], serv_tcp)
                                    # check if rst
                                    if self.__tcps[__dst_hash][serv_tcp].get_tcp_header().seq == \
                                            temp_tcp_connection.last_send_seq + 1 and \
                                            self.__tcps[__dst_hash][serv_tcp].get_tcp_header().rst == 1:
                                        # RST send by client
                                        temp_tcp_connection.add_send(self.__tcps[__dst_hash][serv_tcp], serv_tcp)
                                        __rst = True
                                        break
                                    # check recv's ack
                                    for clien_tcp in range(len(self.__tcps[i])):
                                        if self.__tcps[i][clien_tcp].used:
                                            continue
                                        if self.__tcps[i][clien_tcp].get_tcp_header().fin == 0 and \
                                                self.__tcps[i][clien_tcp].get_tcp_header().ack_num == \
                                                self.__tcps[__dst_hash][serv_tcp].get_tcp_header().seq + 1:
                                            self.__tcps[i][clien_tcp].used = True
                                            temp_tcp_connection.add_recv(self.__tcps[i][clien_tcp], clien_tcp)
                                            # check recv's fin
                                            if clien_tcp + 1 >= len(self.__tcps[i]):
                                                break
                                            if self.__tcps[i][clien_tcp + 1].get_tcp_header().fin == 1:
                                                self.__tcps[i][clien_tcp + 1].used = True
                                                temp_tcp_connection.add_recv(
                                                    self.__tcps[i][clien_tcp + 1], clien_tcp + 1)
                                                # check client's ack
                                                for client_ack_tcp in range(len(self.__tcps[__dst_hash])):
                                                    if self.__tcps[__dst_hash][client_ack_tcp].used:
                                                        continue
                                                    if self.__tcps[__dst_hash][client_ack_tcp].get_tcp_header().fin == 1 \
                                                            and self.__tcps[__dst_hash][
                                                        client_ack_tcp].get_tcp_header().ack_num == \
                                                            temp_tcp_connection.last_recv_seq + 1:
                                                        self.__tcps[__dst_hash][client_ack_tcp].used = True
                                                        temp_tcp_connection.close(
                                                            self.__tcps[__dst_hash][client_ack_tcp])
                                                        # check if rst
                                                    if self.__tcps[__dst_hash][client_ack_tcp].get_tcp_header().seq == \
                                                            temp_tcp_connection.last_recv_seq + 1 and \
                                                            self.__tcps[__dst_hash][
                                                                client_ack_tcp].get_tcp_header().rst == 1:
                                                        # RST send by client
                                                        temp_tcp_connection.add_send(
                                                            self.__tcps[__dst_hash][client_ack_tcp], client_ack_tcp)
                                                        __rst = True
                                                        break
                                                # check if rst
                                                if self.__tcps[i][clien_tcp].get_tcp_header().seq == \
                                                        temp_tcp_connection.last_recv_seq + 1 and \
                                                        self.__tcps[i][
                                                            clien_tcp].get_tcp_header().rst == 1:
                                                    # RST send by client
                                                    temp_tcp_connection.add_send(self.__tcps[i][clien_tcp], clien_tcp)
                                                    __rst = True
                                                    break

                                        # check if rst
                                        if self.__tcps[i][clien_tcp].get_tcp_header().seq == \
                                                temp_tcp_connection.last_recv_seq + 1 and \
                                                self.__tcps[i][clien_tcp].get_tcp_header().rst == 1:
                                            # RST send by client
                                            temp_tcp_connection.add_send(self.__tcps[i][clien_tcp], clien_tcp)
                                            __rst = True
                                            break

                                if self.__tcps[__dst_hash][serv_tcp].get_tcp_header().seq == \
                                        temp_tcp_connection.last_send_seq + 1 and \
                                        self.__tcps[__dst_hash][serv_tcp].get_tcp_header().rst == 1:
                                    # RST send by client
                                    temp_tcp_connection.add_send(self.__tcps[__dst_hash][serv_tcp], serv_tcp)
                                    __rst = True
                                    break

                    if "FF" in temp_tcp_connection.flags:
                        # close manually
                        temp_tcp_connection.complete = True
                        temp_tcp_connection.end = temp_tcp_connection.last_time
                        temp_tcp_connection.duration = temp_tcp_connection.end - temp_tcp_connection.start
                    self.__tcp_connections.append(temp_tcp_connection)

    def print(self):
        print("A) Total number of connections: {}".format(len(self.__tcp_connections)))
        print("-" * 50)
        print("B) Connection details:")
        connection = 1
        complete_connection = 0
        reset_connection = 0
        open_but_not_close = 0
        max_duration = 0
        min_duration = 99999
        mean_duration = 0
        min_rtt = 99999
        max_rtt = 0
        mean_rtt = 0
        max_pkt = 0
        min_pkt = 0
        mean_pkt = 0
        min_window = 0
        max_window = 0
        mean_window = 0

        for c in self.__tcp_connections:
            print("Connection {}:".format(connection))
            print("Source Address: {}".format(c.src))
            print("Destination Address: {}".format(c.dst))
            print("Source Port: {}".format(c.src_port))
            print("Destination Port: {}".format(c.dst_port))
            if "R" in c.flags:
                reset_connection += 1
            print("Status: S{}F{}, R{}".format(c.flags.count("S"), c.flags.count("F"), c.flags.count("R")))

            if c.complete:
                complete_connection += 1
                max_duration = c.duration if c.duration >= max_duration else max_duration
                min_duration = c.duration if c.duration <= min_duration else min_duration
                mean_duration += (c.duration - mean_duration) / complete_connection

                min_rtt = c.min_rtt if c.min_rtt <= min_rtt else min_rtt
                max_rtt = c.max_rtt if c.max_rtt >= max_rtt else max_rtt
                mean_rtt += (c.mean_rtt - mean_rtt) / complete_connection

                min_pkt = c.packets if c.packets <= min_pkt else min_pkt
                max_pkt = c.packets if c.packets >= max_pkt else max_pkt
                mean_pkt += (c.packets - mean_pkt) / complete_connection

                min_window = c.min_window if c.min_window <= min_window else min_window
                max_window = c.max_window if c.max_window >= max_window else max_window
                mean_window += (c.mean_window - mean_window) / complete_connection

                print("Start Time: {}".format("{}s".format(str(c.start).split(".")[0])
                                              if not self.ns else "{}, {}ns"
                                              .format(str(c.start).split(".")[0], str(c.start).split(".")[1])))
                print("End Time: {}".format("{}s".format(str(c.end).split(".")[0])
                                            if not self.ns else "{}, {}ns"
                                            .format(str(c.end).split(".")[0], str(c.end).split(".")[1])))

                print("Duration: {}".format("{}s".format(str(c.duration).split(".")[0])
                                            if not self.ns else "{}s, {}ns"
                                            .format(str(c.duration).split(".")[0], str(c.duration).split(".")[1])))
                print("Number of packets sent from Source to Destination: {}".format(c.send_packets))
                print("Number of packets sent from Destination to Source: {}".format(c.recv_packets))
                print("Total number of packets: {}".format(c.packets))
                print("Number of data bytes sent from Source to Destination: {}".format(c.send_bytes))
                print("Number of data bytes sent from Destination to Source: {}".format(c.recv_bytes))
                print("Total number of data bytes: {}".format(c.send_bytes + c.recv_bytes))

            if c.open and not c.complete:
                open_but_not_close += 1

            print("END")
            print("+" * 30)
            connection += 1

        print("-" * 50)
        print("C) General")
        print("Total number of complete TCP connections: {}".format(complete_connection))
        print("Number of reset TCP connections: {}".format(reset_connection))
        print("Number of TCP connections that were still open when the trace capture ended: {}".format(
            open_but_not_close))
        print("-" * 50)
        print("D) Complete TCP connections:")
        print("Minimum time duration: {}".format("{}s".format(str(min_duration).split(".")[0])
                                                 if not self.ns else "{}s, {:.6}ns"
                                                 .format(str(min_duration).split(".")[0],
                                                         str(min_duration).split(".")[1])))
        print("Mean time duration: {}".format("{}s".format(str(mean_duration).split(".")[0])
                                              if not self.ns else "{}s, {:.6}ns"
                                              .format(str(mean_duration).split(".")[0],
                                                      str(mean_duration).split(".")[1])))
        print("Maximum time duration: {}".format("{}s".format(str(max_duration).split(".")[0])
                                                 if not self.ns else "{}s, {:.6}ns"
                                                 .format(str(max_duration).split(".")[0],
                                                         str(max_duration).split(".")[1])))

        print()
        print("Minimum RTT value: {}".format("{}s".format(str(min_rtt).split(".")[0])
                                             if not self.ns else "{}s, {:.6}ns"
                                             .format(str(min_rtt).split(".")[0],
                                                     str(min_rtt).split(".")[1])))
        print("Mean RTT value: {}".format("{}s".format(str(mean_rtt).split(".")[0])
                                          if not self.ns else "{}s, {:.6}ns"
                                          .format(str(mean_rtt).split(".")[0],
                                                  str(mean_rtt).split(".")[1])))
        print("Maximum RTT value: {}".format("{}s".format(str(max_rtt).split(".")[0])
                                             if not self.ns else "{}s, {:6}ns"
                                             .format(str(max_rtt).split(".")[0],
                                                     str(max_rtt).split(".")[1])))

        print()
        print("Minimum number of packets including both send/received: {}".format(min_pkt))
        print("Mean number of packets including both send/received: {:.10}".format(mean_pkt))
        print("Maximum number of packets including both send/received: {}".format(max_pkt))

        print()
        print("Minimum receive window size including both send/received: {}".format(min_window))
        print("Mean receive window size including both send/received: {:.10}".format(mean_window))
        print("Maximum receive window size including both send/received: {}".format(max_window))

        print("-" * 50)
