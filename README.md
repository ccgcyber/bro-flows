# Application for BRO
## Packet matching

The documentation used is provided by BRO through its [web](https://www.bro.org/documentation/index.html "BRO documentation")

It consists of a script for BRO which, through DPI, matches the packets.

At this time it packs the TCP, UDP and ICMP packets, by managing different events.

To execute the script it will be enough to install BRO as it says in the documentation and in the root folder to use:
First
`````````````
export PATH=/usr/local/bro/bin:$PATH

`````````````
And then:

``````````````

~$ bro -b -r pcap/nitroba.pcap scripts/aprox2.bro

``````````````

Obviously you can use another pcap file or any other BRO script.

The function that will be used for the pairing of flows will be the one given in the article "A generalizable dynamic flow pairing method for traffic classification"

`````````````````

result=(Nip-1)+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2))

`````````````````
Where Nip is the number of flows with the same IP and port, Po1, Pd1, Po2 and Pd2 are the source and destination ports of the two packets, k1 and k2 are variables that we put and dt is the time difference between the first package of the first flow and the first package of the second flow.
