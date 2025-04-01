# gfw_resist_tcp_proxy
knock up IP blockage

# goodbye IP filtering & goodbye GFW mf'er
<img src="/meme.jpg?raw=true" width="300" >
<br>

# main Idea -> TCP violation:
- GFW needs to check every packet against large list of filtered ip in order to drop them<br>
- since its not practical in huge traffic, they separate tcp handshake (SYN) and check them only.<br>
- in fact, they only drop SYN packet with blocked ip in both direction.
- so we can bypass ip filtering by building communication link without tcp handshake.<br><br>
<img src="/slide1.png?raw=true" width="800" >
<br><br>


# how important is it?
- it bypass ip blockage, so it bypass principal core of filtering
- it change the paradigm of anti-censorship from "hiding traffic" / "escaping from blockage" to "drilling whatever blocked"
- what more can a censorman do after detecting a VPN, beside blocking ip?
- similar to [fragment that bypass SNI](https://github.com/GFW-knocker/gfw_resist_tls_proxy) , it operate at the lower network layer
- no matter which protocol used at upper level, it can drill everything, even blocked port

# can GFW block tcp violation method?
- this method is not based on a bug nor a protocol at application layer
- it operate on lowest possible layer of network (transport and ip layer)
- need lots of dedicated Hardware to fight with (not achievable in software)
- we use TCP ACK/PUSH packets which is 100000X more frequent than SYN
- they have large list of blocked ip that want to drop
- they simply cant hold & check every single packet in high speed traffic. (unless with millions of dollar HW investment)

# how to run
- tcp violation need root/admin access to midify/send/sniff crafted packet
- we implement method1 : a prototype for proof-of-concept
- its not ready for production yet but we plan to build stable and standalone version in near future
