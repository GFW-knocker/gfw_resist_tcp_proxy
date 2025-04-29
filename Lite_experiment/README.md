# Lite Experiment
simple test to see if this method work on your ISP

# send custom tcp packet to filtered ip
1. in your pc with root or admin access:
    <code>
    install wireshark with npcap if you are on windows
    pip install scapy
    python send_pkt.py
    </code>

2. in vps , listen for packet using tcpdump
    <code>
    sudo tcpdump -i any -n -A -vv -s 0 -c 100 port 29745
    </code>
    <code>
    -i eth0 : capture intface
    -n : no dns resolve
    -vv: verbose level 2
    -s 0: max packet size to capture 0:unlimited
    -c 100: capture max 100 packet and exit
    -A : print ascii
    </code>

3. if your packet received at server , you successfully bypass filtered ip
4. backward direction from server to client, is a bit complex , because you need to identify which port opened by NAT and reply to it. but principle is same
