# client:server port mapping
# for example 14000:443 means client listen on tcp:14000 and it forward data to server tcp:443
tcp_port_mapping = {14000: 443, 
                    15000: 2096,
                    16000: 10809
                    }

udp_port_mapping = {17000: 945, 
                    18000: 1014,
                    }

# vps_ip that blocked by Great!(())FireWall
vps_ip = "192.168.1.5"  # replace by your vps_ip

# remote xray ip address (set 127.0.0.1 if xray and MainServer.py run on same VPS)
xray_server_ip_address = "127.0.0.1"

# violate_client_port (port must be closed , windows:firewall on , linux:sudo ufw deny portnum)
vio_tcp_server_port = 45000
vio_tcp_client_port = 40000

# violate_udp_port (used for communicating between quic and vio tunnel)
vio_udp_server_port = 35000
vio_udp_client_port = 30000

# used for outter quic tunnel
quic_server_port = 25000
quic_client_port = 20000

quic_local_ip = "127.0.0.1"

# how many second quic tunnel wait in idle before closing (recommended=86400)
quic_idle_timeout = 86400

# how many second a udp socket can be in idle (recommended=300)
udp_timeout = 300

# verify cert root (set to true only if you have valid cert)
quic_verify_cert = False

# quic carrier mtu(recommended=1420) must be grater than wireguard mtu(recommended=800) in your config
quic_mtu = 1420

quic_cert_filepath = ('cert.pem', 'key.pem')

quic_max_data = 1000 * 1024 * 1024  # 1 GB total, then send ack to sender to receive more 
quic_max_stream_data = 1000 * 1024 * 1024  # 1 GB per stream, then send ack to sender to receive more

quic_auth_code = "jd!gn0s4"   # used for internal quic auth between client and server , its an abritrary pwd

# === New parameters for improved connection management ===
retry_interval = 5           # Seconds to wait before retrying QUIC connection
max_retry_attempts = 5       # Maximum number of retry attempts for QUIC connection
heartbeat_interval = 30      # Seconds between heartbeat messages for connection stability