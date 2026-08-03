from scapy.all import AsyncSniffer,IP,TCP,Raw,conf
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


tcp_options=[
        ('MSS', 1280),  # Maximum Segment Size
        ('WScale', 8),  # Window Scale
        ('SAckOK', ''),  # Selective ACK Permitted
    ]




async def async_sniff_realtime(qu1):
    logger.info("sniffer started")
    try:
        def process_packet(packet):
            # logger.info(f"sniffed before if at {time.time()}")
            if packet.haslayer(TCP) and packet[IP].src == vps_ip and packet[TCP].sport == vio_tcp_server_port and packet[TCP].flags == 'AP':
                data1 = packet[TCP].load
                qu1.put_nowait(data1)
                # logger.info(f"sniffed {data1} at {time.time()}")

        async def start_sniffer():
            sniffer = AsyncSniffer(prn=process_packet,
                                    filter=f"tcp and src host {vps_ip} and src port {vio_tcp_server_port}",
                                    store=False)
            sniffer.start()
            return sniffer
                
        sniffer = await start_sniffer()
        return sniffer
    except Exception as e:
        logger.info(f"sniff Generic error: {e}....")
    



async def forward_vio_to_quic(qu1, transport):
    logger.info(f"Task vio to Quic started")
    addr = (quic_local_ip,quic_client_port)
    # addr = ("192.168.1.132",quic_client_port)
    try:
        while True:
            data = await qu1.get()
            # logger.info(f"data qu1 fetched {data} at {time.time()}")
            if(data == None):
                break
            transport.sendto(data , addr)
            # logger.info(f"data sent to udp {data} -> {addr} at {time.time()}")
            # q1.task_done()
    except Exception as e:
        logger.info(f"Error forwarding vio to Quic: {e}")
    finally:
        logger.info(f"Task vio to Quic Ended.")



basepkt = IP(dst=vps_ip) / TCP(sport=vio_tcp_client_port, dport=vio_tcp_server_port, seq=0, flags="AP", ack=0, options=tcp_options) / Raw(load=b"")

skt = conf.L3socket()

def send_to_violated_TCP(binary_data):
    new_pkt = basepkt.copy()
    # new_pkt[TCP].seq = random.randint(1024,1048576)
    # new_pkt[TCP].ack = random.randint(1024,1048576)
    new_pkt[TCP].load = binary_data
    skt.send(new_pkt)




async def forward_quic_to_vio(protocol):
    logger.info(f"Task QUIC to vio started")
    try:
        while True:
            data = await protocol.queue.get()  # Wait for data from UDP
            if(data == None):
                break
            send_to_violated_TCP(data)
            # logger.info(f"data sent to tcp {data} at {time.time()}")
    except Exception as e:
        logger.info(f"Error forwarding QUIC to vio: {e}")
    finally:
        logger.info(f"Task QUIC to vio Ended.")



async def start_udp_server(qu1):
        while True:
            try:
                logger.warning(f"listen quic:{vio_udp_client_port} -> violated tcp:{vio_tcp_server_port}")
                loop = asyncio.get_event_loop()
                transport, udp_protocol = await loop.create_datagram_endpoint(
                    lambda: UdpProtocol(),
                    local_addr=('0.0.0.0', vio_udp_client_port)
                )
                task1 = asyncio.create_task(forward_quic_to_vio(udp_protocol))
                task2 = asyncio.create_task(forward_vio_to_quic(qu1,transport))
                
                while True:
                    await asyncio.sleep(0.02) # this make async loop to switch better between process
                    if(udp_protocol.has_error):
                        task1.cancel()
                        task2.cancel()
                        await asyncio.sleep(1)
                        logger.info(f"all task cancelled")
                        break
                
            except Exception as e:
                logger.info(f"vioclient ERR: {e}")
            finally:
                transport.close()
                await asyncio.sleep(0.5)
                transport.abort()
                logger.info("aborting transport ...")
                await asyncio.sleep(1.5)
                logger.info("vio inner finished")




class UdpProtocol:
    def __init__(self):
        self.transport = None
        self.has_error = False
        self.queue = asyncio.Queue()

    def connection_made(self, transport):
        logger.info("NEW DGRAM listen created")
        logger.info(transport.get_extra_info('socket'))
        self.transport = transport
    
    def pause_writing(self):
        pass  # UDP doesn't need flow control, but we had to implement

    def resume_writing(self):
        pass  # UDP doesn't need flow control, but we had to implement

    def datagram_received(self, data, addr):
        self.queue.put_nowait(data)
        # logger.info(f"data received from udp {data} at {time.time()}")                

    def error_received(self, exc):
        logger.info(f"UDP error received: {exc}")
        self.has_error = True
        if(self.transport):
            self.transport.close()
            logger.info("UDP transport closed")

    def connection_lost(self, exc):
        logger.info(f"UDP lost. {exc}")
        self.has_error = True
        if(self.transport):
            self.transport.close()
            logger.info("UDP transport closed")




async def run_vio_client():
    try:
        qu1 = asyncio.Queue()
        sniffer = await async_sniff_realtime(qu1)
        
        await asyncio.gather(
            start_udp_server(qu1),
            return_exceptions=True
        )
    
        logger.info("end ?")
    except SystemExit as e:
        logger.info(f"Caught SystemExit: {e}")
    except asyncio.CancelledError as e:
        logger.info(f"cancelling error: {e}")
    except ConnectionError as e:
        logger.info(f"Connection error: {e}")
    except Exception as e:
        logger.info(f"Generic error: {e}")
    finally:
        sniffer.stop()
        logger.info("stop sniffer")
        # sys.exit()


if __name__ == "__main__":
    asyncio.run(run_vio_client())


    

