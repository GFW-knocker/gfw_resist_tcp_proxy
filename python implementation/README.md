# TCP Violation method:
Implementation 1:<br>
python asyncio + aioquic + scapy<br><br>
<img src="/slide2.png?raw=true" width="800" >
<br><br>

# Requirenemts:
- a VPS with filtered ip
- in windows: Npcap (can be installed with wireshark)
- python 3.10+
- scapy and aioquic (python library)

# How to run:
- if you are on windows install Npcap or wireshark
- install python library using
    <code>
    pip install aioquic
    pip install scapy
    </code>
    or if you want system-wide
    <code>
    sudo apt-get install python3-scapy
    sudo apt-get install python3-aioquic
    </code>
- setup `port_mapping` and `vps_ip` in parameters.py
- make sure `vio_tcp_server_port` & `vio_tcp_client_port` closed by ufw and windows firewall is on
    <code>
    sudo ufw deny 45000
    </code>
    yes we drill blocked port :)<br>
    make sure tcp violation port blocked by ufw<br>
    to avoid unwanted RST packet sent by os<br>
- copy all files in both server and your pc (need ROOT/ADMIN)
- run in server and client
    <code>
    sudo python3 mainserver.py
    python mainclient.py
    </code>
- enjoy bypassing

# port mapping guide:
example:<br>
tcp_port_mapping = {14000:443}<br>
put `127.0.0.1:14000` in client config to point to `mainclient.py`<br>
create a config on port 443 on server side to accept from `mainserver.py`<br>
data tunneled from `client:tcp:14000` to `server:tcp:443`<br>

    
  



