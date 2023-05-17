# PCap File Analyzer

## Usage
```shell
python3 main.py [--instant] file_path.pcap
```

--instant flag means load packet one by one in analyzing, use less memory and time but would not show the progress bar.
You must always put the file name in the last.
## Display

### Full Mode
In full mode, you will see displays like below first:
```text
Start reading file.
Reading version 2.4 little endian order file test2.pcap with Ethernet link type and 262144 snap length in FULL mode.
29 %[###########->.............................] 1173396/4076414 3.58s->8.85s, 327881.20it/s
```
It shows that the filename, link layer type and reading status. For example, 3.58s above means time that already takes,
8.85s means ETA time.

When reading complete, you will see displays like this:
```text
Read 11987 packets from 18765 packets.
TCP connections statistic in progress.
44 %[#################->.......................] 5246/11986 0.41s->0.52s, 12846.00it/s
```
It shows how many TCP/IP packets read from cap file. My test file didn't set filter, so it has ARP and other packets.
And it shows the process of statistic.

If it takes too much time, you can use instant mode, which is faster than full mode(5min->20sec faster).

Displays after these are as same as instant mode.

### Instant Mode
Use `--instant` flag to use this mode, for example:
```shell
python3 main.py --instant test2.pcap
```
You always need to put the file name in the last.

In instant mode you will see same start in full mode like:
```text
Start reading file.
Reading version 2.4 little endian order file test2.pcap with Ethernet link type and 262144 snap length in INSTANT mode.
TCP connections statistic in progress.
```
Actually in this mode reading is just for the pcap head, then it returns an iterator for statistic directly.
There's no process bar in this mode, just wait for a while, and you will get the output below.

### Common Output
In whichever mode, you will see these output like:
```text
A) Total number of connections: 258
--------------------------------------------------
B) Connection details:
Connection 1:
Source Address: ****:ad58:ca2c:8d29:3d3d
Destination Address: 2600:1406:4200:3::1748:5a8d
Source Port: 2675
Destination Port: 443
Status: S2F2, R1
Start Time: 1645769470, 935556ns
End Time: 1645769472, 093197ns
Duration: 1s, 157641ns
Number of packets sent from Source to Destination: 5
Number of packets sent from Destination to Source: 3
Total number of packets: 8
Number of data bytes sent from Source to Destination: 100
Number of data bytes sent from Destination to Source: 0
Total number of data bytes: 100
END
++++++++++++++++++++++++++++++
--------------------------------------------------
C) General
Total number of complete TCP connections: 64
Number of reset TCP connections: 71
Number of TCP connections that were still open when the trace capture ended: 119
--------------------------------------------------
D) Complete TCP connections:
Minimum time duration: 0s, 022214ns
Mean time duration: 6s, 215858ns
Maximum time duration: 102s, 060642ns

Minimum RTT value: 0s, 000000ns
Mean RTT value: 0s, 050334ns
Maximum RTT value: 5s, 042968ns

Minimum number of packets including both send/received: 0
Mean number of packets including both send/received: 7.6875
Maximum number of packets including both send/received: 10

Minimum receive window size including both send/received: 0
Mean receive window size including both send/received: 1309.501551
Maximum receive window size including both send/received: 65531
--------------------------------------------------
```
As the indication of the outputformat, it is generally suite the standard of the outputformat.