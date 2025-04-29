from scapy.all import *

# replace with your filtered vps ip
vps_ip = "216.239.38.120"



tcp_options=[
        ('MSS', 1452),  # Maximum Segment Size
        ('WScale', 8),  # Window Scale
        ('SAckOK', ''),  # Selective ACK Permitted
    ]


pkt = IP(dst=vps_ip) / TCP(sport=54740, dport=29745, seq=1 , flags="AP", ack=1 , options=tcp_options) / "sample msg"


send(pkt, count=1, verbose=1)

