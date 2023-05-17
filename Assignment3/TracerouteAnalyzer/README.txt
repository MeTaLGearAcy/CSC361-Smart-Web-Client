# Lab 3
## R1
### Usage
Same as the previous lab, it provides --instant flag to accurate reading speed.
--instant flag is optional.

```shell
python3 R1.py [--instant] [filename]
```
Notice that the filename should always be in the last argument.

### Output
```text
Start reading file.
Reading version 2.4 little endian order file PCaps/traceroute-frag.pcap with Ethernet link type and 65535 snap length in INSTANT mode.
Traceroute statistic in progress.
```
You will first see these output above, this gives you basic information about the file.
Then you will see:
```text
Traceroute: [192.168.0.108 -> 4.2.2.2, Linux, 104 packets]
```
It means the program detected a Traceroute client, with source -> destination, operating system, packets include in this connection.

After is the requirements of R1:
```text
The IP address of the source node: 192.168.0.108
The IP address of ultimate destination node: 4.2.2.2
The IP addresses of the intermediate destination nodes:
	route 1: 142.104.69.243,
	route 2: 142.104.68.1,
	route 3: 192.168.9.5,
	route 4: 192.168.10.1,
	route 5: 142.104.252.246,
	route 6: 142.104.250.37,
	route 7: 207.23.241.221,
	route 8: 67.69.244.53,
	route 9: 64.230.122.248,
	route 10: 64.230.77.230,
	route 11: 64.230.77.228,
	route 12: 64.230.79.98,
	route 13: 64.230.125.233,
	route 14: 64.230.125.231,
	route 15: 4.71.152.53,
	route 16: 4.69.152.15,
	route 17: 4.2.2.2.

The values in the protocol field of IP headers:
	1: ICMP
	6: TCP
	17: UDP

The number of fragments created from the original datagram D1 is: 1
...
The number of fragments created from the original datagram D52 is: 1
The offset of the last fragment is: 1480

The avg RTT between 192.168.0.108 and 142.104.69.243 is: 9.4 ms, the s.d. is: 0.0051
The avg RTT between 192.168.0.108 and 142.104.68.1 is: 17.6 ms, the s.d. is: 0.0002
The avg RTT between 192.168.0.108 and 192.168.9.5 is: 18.4 ms, the s.d. is: 0.0002
The avg RTT between 192.168.0.108 and 192.168.10.1 is: 19.9 ms, the s.d. is: 0.0000
The avg RTT between 192.168.0.108 and 142.104.252.246 is: 12.2 ms, the s.d. is: 0.0002
The avg RTT between 192.168.0.108 and 142.104.250.37 is: 15.2 ms, the s.d. is: 0.0000
The avg RTT between 192.168.0.108 and 207.23.241.221 is: 55.4 ms, the s.d. is: 0.0046
The avg RTT between 192.168.0.108 and 67.69.244.53 is: 11.3 ms, the s.d. is: 0.0011
The avg RTT between 192.168.0.108 and 64.230.122.248 is: 13.9 ms, the s.d. is: 0.0004
The avg RTT between 192.168.0.108 and 64.230.77.230 is: 15.0 ms, the s.d. is: 0.0000
The avg RTT between 192.168.0.108 and 64.230.77.228 is: 15.5 ms, the s.d. is: 0.0015
The avg RTT between 192.168.0.108 and 64.230.79.98 is: 15.4 ms, the s.d. is: 0.0010
The avg RTT between 192.168.0.108 and 64.230.125.233 is: 18.7 ms, the s.d. is: 0.0000
The avg RTT between 192.168.0.108 and 64.230.125.231 is: 19.1 ms, the s.d. is: 0.0001
The avg RTT between 192.168.0.108 and 4.71.152.53 is: 127.6 ms, the s.d. is: 0.0003
The avg RTT between 192.168.0.108 and 4.69.152.15 is: 30.7 ms, the s.d. is: 0.0010
The avg RTT between 192.168.0.108 and 4.2.2.2 is: 29.1 ms, the s.d. is: 0.0011
```

## R2
### Usage
```shell
python3 R2.py
```
Notice that I set the default PCaps directory is "./PCaps/", which means you need to put all .pcap files under ./PCaps/ (Base with R2's directory). Or please keep the directory structure or change the code at line 15 in R2.py.

### Output with Conclusion
When running R2, it will read 2 groups in PCaps and print out the statistics and my answer/conclusion to Requirement 2.
```text
Statistics group1.
In this group, max probes is: 3, probes used: {3}
In group 1, some intermediate routes/destinations are different, list difference.
Difference between group1-trace1 and trace2: 
{'209.85.249.155', '209.85.250.121', '209.85.249.153'}
Difference between group1-trace2 and trace3: 
{'209.85.250.57', '209.85.246.219', '209.85.249.109'}
Difference between group1-trace3 and trace4: 
{'209.85.249.155', '209.85.247.63'}
Difference between group1-trace4 and trace5: 
{'209.85.250.123', '209.85.246.219', '74.125.37.91', '209.85.245.65'}
It is because that two device used in group 1: 192.168.0.16 and 192.168.100.17 (use s.print() in this program can see).
Also, 209.85.0.0/16 and 74.125.37.0/24 is belongs to Google LLC, it has traffic load shunting server.
When traffic hitting its server it will choose a random one to response.
That's why there's more than one intermediate routes respond for same ttl request.
==================================================
Statistics group2.
In this group, max probes is: 3, probes used: {3}
In group 2, all intermediate routes/destinations are same, list statistics data.
--------------------------------------------------------------------------------
TTL		AVG RTT in	AVG RTT in	AVG RTT in	AVG RTT in	AVG RTT in	AVG RTT
		trace 1		trace 2		trace 3		trace 4		trace 5		this line
--------------------------------------------------------------------------------
1		3.3 ms		2.7 ms		7.9 ms		3.4 ms		1.7 ms		3.8 ms
--------------------------------------------------------------------------------
2		15.8 ms		17.1 ms		11.8 ms		13.2 ms		16.2 ms		14.8 ms
--------------------------------------------------------------------------------
3		18.9 ms		20.1 ms		22.6 ms		21.7 ms		21.6 ms		21.0 ms
--------------------------------------------------------------------------------
4		22.8 ms		19.4 ms		19.5 ms		19.8 ms		18.6 ms		20.0 ms
--------------------------------------------------------------------------------
5		26.5 ms		21.6 ms		20.3 ms		35.8 ms		20.7 ms		25.0 ms
--------------------------------------------------------------------------------
6		24.3 ms		20.0 ms		21.8 ms		22.7 ms		43.5 ms		26.4 ms
--------------------------------------------------------------------------------
7		18.4 ms		51.7 ms		22.8 ms		18.3 ms		26.9 ms		27.6 ms
--------------------------------------------------------------------------------
8		23.0 ms		108.7 ms		20.6 ms		24.6 ms		25.6 ms		40.5 ms
--------------------------------------------------------------------------------
9		18.1 ms		21.9 ms		23.1 ms		19.9 ms		21.4 ms		20.9 ms
--------------------------------------------------------------------------------
As table above, it is obviously to say that hop 8 is mainly likely to incur the maximum delay.
Because its avg delay is highest.
Hop 8 is 209.85.249.249, which still belongs to Google LLC.
I searched for hop 8 and 7's location: the hop 8 209.85.249.249 is in Fremont,
and hop 7 108.170.245.113 is in Des Moines.
I think the two location of these two hops is the mainly problem of this delay issue.
==================================================
```
