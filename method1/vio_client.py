from scapy.all import AsyncSniffer, IP, TCP, Raw, conf
import asyncio
import time
import random
import parameters
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VioClient")

vps_ip = parameters.vps_ip
vio_tcp_server_port = parameters.vio_tcp_server_port
vio_tcp_client_port = parameters.vio_tcp_client_port
vio_udp_client_port = parameters.vio_udp_client_port
quic_local_ip = parameters.quic_local_ip
quic_client_port = parameters.quic_client_port

tcp_options = [
    ('MSS', 1280),
    ('WScale', 8),
    ('SAckOK', ''),
]

async def async_sniff_realtime(qu1):
    logger.info("Sniffer started")
    try:
        def process_packet(packet):
            if packet.haslayer(TCP) and packet[IP].src == vps_ip and packet[TCP].sport == vio_tcp_server_port and packet[TCP].flags == 'AP':
                data1 = packet[TCP].load
                qu1.put_nowait(data1)

        async def start_sniffer():
            sniffer = AsyncSniffer(
                prn=process_packet,
                filter=f"tcp and src host {vps_ip} and src port {vio_tcp_server_port}",
                store=False
            )
            sniffer.start()
            return sniffer
                
        sniffer = await start_sniffer()
        return sniffer
    except Exception as e:
        logger.info(f"Sniffer error: {e}")

async def forward_vio_to_quic(qu1, transport):
    logger.info("Starting vio to QUIC forwarding")
    addr = (quic_local_ip, quic_client_port)
    try:
        while True:
            data = await qu1.get()
            if data is None:
                break
            transport.sendto(data, addr)
    except Exception as e:
        logger.info(f"Error forwarding vio to QUIC: {e}")
    finally:
        logger.info("Vio to QUIC forwarding ended")

basepkt = IP(dst=vps_ip) / TCP(sport=vio_tcp_client_port, dport=vio_tcp_server_port, seq=0, flags="AP", ack=0, options=tcp_options) / Raw(load=b"")
skt = conf.L3socket()

def send_to_violated_TCP(binary_data):
    new_pkt = basepkt.copy()
    new_pkt[TCP].load = binary_data
    skt.send(new_pkt)

async def forward_quic_to_vio(protocol):
    logger.info("Starting QUIC to vio forwarding")
    try:
        while True:
            data = await protocol.queue.get()
            if data is None:
                break
            send_to_violated_TCP(data)
    except Exception as e:
        logger.info(f"Error forwarding QUIC to vio: {e}")
    finally:
        logger.info("QUIC to vio forwarding ended")

async def start_udp_server(qu1):
    while True:
        try:
            logger.warning(f"Listening on QUIC:{vio_udp_client_port} -> forwarding to violated TCP:{vio_tcp_server_port}")
            loop = asyncio.get_event_loop()
            transport, udp_protocol = await loop.create_datagram_endpoint(
                lambda: UdpProtocol(),
                local_addr=('0.0.0.0', vio_udp_client_port)
            )
            task1 = asyncio.create_task(forward_quic_to_vio(udp_protocol))
            task2 = asyncio.create_task(forward_vio_to_quic(qu1, transport))
            while not udp_protocol.has_error:
                await asyncio.sleep(0.05)
        except Exception as e:
            logger.info(f"Vio client error: {e}")
        finally:
            transport.close()
            await asyncio.sleep(0.5)
            transport.abort()
            logger.info("UDP transport aborted")
            await asyncio.sleep(1.5)

class UdpProtocol:
    def __init__(self):
        self.transport = None
        self.has_error = False
        self.queue = asyncio.Queue()

    def connection_made(self, transport):
        logger.info("New UDP listener created")
        self.transport = transport

    def datagram_received(self, data, addr):
        self.queue.put_nowait(data)

    def error_received(self, exc):
        logger.info(f"UDP error received: {exc}")
        self.has_error = True
        if self.transport:
            self.transport.close()

    def connection_lost(self, exc):
        logger.info(f"UDP connection lost: {exc}")
        self.has_error = True
        if self.transport:
            self.transport.close()

async def run_vio_client():
    try:
        qu1 = asyncio.Queue()
        sniffer = await async_sniff_realtime(qu1)
        await start_udp_server(qu1)
    except Exception as e:
        logger.info(f"Unexpected error: {e}")
    finally:
        sniffer.stop()
        logger.info("Sniffer stopped")

if __name__ == "__main__":
    asyncio.run(run_vio_client())
