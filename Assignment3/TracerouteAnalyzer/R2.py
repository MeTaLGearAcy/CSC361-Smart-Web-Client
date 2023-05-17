import time

import Cap.Cap as Cap
import Statistic as Statistic
import gc

if __name__ == '__main__':
    gc.enable()

    for group in range(1, 3):
        datas = []
        print("Statistics group{}.".format(group))
        for trace in range(1, 6):
            instant = True
            c = Cap.Cap("PCaps/group{}-trace{}.pcap".format(group, trace), instant=instant, printout=False)
            s = Statistic.Statistic(c.get_packets(), instant=instant, printout=False)
            temp_data = s.get_statistics_data()
            # s.print()
            if temp_data:
                datas.append(temp_data)

            del c, s
            gc.collect()
        r2_routes = []
        r2_probes = []
        r2_rtt = []
        for d in datas:
            __routes, __rtt, __sd, __fragments, __last_offsets, __max_probes = d
            r2_routes.append(__routes)
            r2_probes.append(__max_probes)
            r2_rtt.append(__rtt)
        i = 0
        for i in range(len(r2_routes) - 1):
            if len(set(r2_routes[i] + r2_routes[i + 1])) != len(r2_routes[i]):
                break
        print("In this group, max probes is: {}, probes used: {}".format(max(r2_probes), set(r2_probes)))
        if i >= len(r2_routes) - 2:
            print("In group {}, all intermediate routes/destinations are same, list statistics data.".format(group))
            print("-" * 80)
            print("TTL\t\t" + "AVG RTT in\t" * 5 + "AVG RTT")
            print("\t\ttrace {0}\t\ttrace {1}\t\ttrace {2}\t\ttrace {3}\t\ttrace {4}\t\tthis line".format(1, 2, 3, 4, 5))
            print("-" * 80)

            for ttls in range(len(r2_rtt[0])):
                temp_avg = 0
                for index in range(5):
                    temp_avg += r2_rtt[index][ttls]
                temp_avg /= 5
                print("{}\t\t{}\t\t{}\t\t{}\t\t{}\t\t{}\t\t{}".format(ttls + 1, r2_rtt[0][ttls], r2_rtt[1][ttls], r2_rtt[2][ttls]
                                                                , r2_rtt[3][ttls], r2_rtt[4][ttls], temp_avg))
                print("-" * 80)
            print("As table above, it is obviously to say that hop 8 is mainly likely to incur the maximum delay.")
            print("Because its avg delay is highest.")
            print("Hop 8 is 209.85.249.249, which still belongs to Google LLC.")
            print("I searched for hop 8 and 7's location: the hop 8 209.85.249.249 is in Fremont,")
            print("and hop 7 108.170.245.113 is in Des Moines.")
            print("I think the two location of these two hops is the mainly problem of this delay issue.")

        else:
            print("In group {}, some intermediate routes/destinations are different, list difference.".format(group))
            different_routes = []
            for i in range(len(r2_routes) - 1):
                if len(set(r2_routes[i] + r2_routes[i + 1])) != len(r2_routes[i]):
                    print("Difference between group{}-trace{} and trace{}: ".format(group, i + 1, i + 2))
                    print(set(r2_routes[i]).difference(set(r2_routes[i + 1])))
            print("It is because that two device used in group {}: 192.168.0.16 and 192.168.100.17"
                  " (use s.print() in this program can see).".format(group))
            print("Also, 209.85.0.0/16 and 74.125.37.0/24 is belongs to Google LLC, it has traffic load shunting server"
                  ".\nWhen traffic hitting its server it will choose a random one to response.\nThat's why there's more"
                  " than one intermediate routes respond for same ttl request.")

        print("=" * 50)


