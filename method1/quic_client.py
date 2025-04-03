import asyncio
import logging
import sys
import time
import multiprocessing
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset
import parameters

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("QuicClient")

# Global list to track active protocol instances
active_protocols = []
global is_quic_established

class TunnelClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        global is_quic_established
        is_quic_established = False
        super().__init__(*args, **kwargs)
        self.loop = asyncio.get_event_loop()
        self.tcp_connections = {}  # Map TCP connections to QUIC streams
        self.tcp_syn_wait = {}     # Map TCP half opened to QUIC streams
        self.udp_addr_to_stream = {}
        self.udp_stream_to_addr = {}
        self.udp_stream_to_transport = {}
        self.udp_last_activity = {}  # Track last activity time of UDP sockets
        active_protocols.append(self)
        asyncio.create_task(self.cleanup_stale_udp_connections())
        asyncio.create_task(self.check_start_connectivity())
        asyncio.create_task(self.send_heartbeat())  # Heartbeat task added

    async def check_start_connectivity(self):
        global is_quic_established
        try:
            await asyncio.sleep(7)
            if is_quic_established:
                logger.info("Quic Established!")
            else:
                logger.info("Quic FAILED to connect")
                self.connection_lost("quic connectivity")
        except Exception as e:
            logger.info(f"connectivity error: {e}")

    async def send_heartbeat(self):
        # Send heartbeat messages periodically to keep connection alive
        while True:
            try:
                await asyncio.sleep(parameters.heartbeat_interval)
                if self._quic and is_quic_established:
                    # Using a simple ping message (could be refined)
                    heartbeat_msg = parameters.quic_auth_code + "heartbeat"
                    # Sending heartbeat as a datagram frame
                    self._quic.send_datagram_frame(heartbeat_msg.encode("utf-8"))
                    self.transmit()
                    logger.info("Heartbeat sent")
            except Exception as e:
                logger.info(f"Heartbeat error: {e}")

    def connection_lost(self, exc):
        super().connection_lost(exc)
        self.close_all_tcp_connections()
        logger.info("QUIC connection lost. exit")
        for protocol in active_protocols:
            protocol.close_all_tcp_connections()
            protocol.close_all_udp_connections()
            protocol.close()
        if self in active_protocols:
            active_protocols.remove(self)
        time.sleep(1)
        sys.exit()

    def close_all_tcp_connections(self):
        logger.info("close all tcp")
        for stream_id, (reader, writer) in self.tcp_connections.items():
            logger.info(f"Closing TCP connection for stream {stream_id}...")
            try:
                writer.close()
            except Exception as e:
                logger.info(f"Error closing tcp socket: {e}")
        for stream_id, (reader, writer) in self.tcp_syn_wait.items():
            logger.info(f"Closing TCP connection for stream {stream_id}...")
            try:
                writer.close()
            except Exception as e:
                logger.info(f"Error closing tcp socket: {e}")
        self.tcp_connections.clear()
        self.tcp_syn_wait.clear()

    def close_all_udp_connections(self):
        logger.info("close all udp")
        self.udp_addr_to_stream.clear()
        self.udp_stream_to_addr.clear()
        self.udp_last_activity.clear()
        self.udp_stream_to_transport.clear()

    def close_this_stream(self, stream_id):
        try:
            logger.info(f"FIN to stream={stream_id} sent")
            self._quic.send_stream_data(stream_id, b"", end_stream=True)  # Send FIN flag
            self.transmit()  # Send the FIN flag over the network
        except Exception as e:
            logger.info(f"Error closing stream at client: {e}")
        try:
            if stream_id in self.tcp_connections:
                writer = self.tcp_connections[stream_id][1]
                writer.close()
                del self.tcp_connections[stream_id]
            if stream_id in self.tcp_syn_wait:
                writer = self.tcp_syn_wait[stream_id][1]
                writer.close()
                del self.tcp_syn_wait[stream_id]
            if stream_id in self.udp_stream_to_addr:
                addr = self.udp_stream_to_addr.get(stream_id)
                del self.udp_addr_to_stream[addr]
                del self.udp_stream_to_addr[stream_id]
                del self.udp_last_activity[stream_id]
                del self.udp_stream_to_transport[stream_id]
        except Exception as e:
            logger.info(f"Error closing socket at client: {e}")

    async def cleanup_stale_udp_connections(self):
        logger.info("UDP cleanup task running!")
        check_time = min(parameters.udp_timeout, 60)
        while True:
            await asyncio.sleep(check_time)
            current_time = self.loop.time()
            stale_streams = [stream_id for stream_id, last_time in self.udp_last_activity.items()
                             if current_time - last_time > parameters.udp_timeout]
            for stream_id in stale_streams:
                logger.info(f"idle UDP stream={stream_id} timeout reached")
                self.close_this_stream(stream_id)

    async def forward_tcp_to_quic(self, stream_id):
        logger.info("Task TCP to QUIC started")
        try:
            (reader, writer) = self.tcp_syn_wait[stream_id]
            self.tcp_connections[stream_id] = (reader, writer)
            del self.tcp_syn_wait[stream_id]
            while True:
                data = await reader.read(4096)  # Read data from TCP socket
                if not data:
                    break
                self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=False)
                self.transmit()  # flush
        except Exception as e:
            logger.info(f"Error forwarding TCP to QUIC: {e}")
        finally:
            logger.info("Task TCP to QUIC Ended")
            self.close_this_stream(stream_id)

    async def handle_tcp_connection(self, reader, writer, target_port):
        try:
            # Assign a new QUIC stream for this TCP connection
            stream_id = self._quic.get_next_available_stream_id()
            self.tcp_syn_wait[stream_id] = (reader, writer)
            req_data = parameters.quic_auth_code + "connect,tcp," + str(target_port) + ",!###!"
            self._quic.send_stream_data(stream_id=stream_id, data=req_data.encode("utf-8"), end_stream=False)
            self.transmit()  # flush
        except Exception as e:
            logger.info(f"Client Error handle tcp connection: {e}")
            self.close_this_stream(stream_id)

    async def forward_udp_to_quic(self, udp_protocol):
        logger.info("Task UDP to Quic started")
        try:
            while True:
                data, addr = await udp_protocol.queue.get()
                if addr in self.udp_addr_to_stream:
                    stream_id = self.udp_addr_to_stream.get(addr)
                    self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=False)
                    self.transmit()  # flush
                    self.udp_last_activity[stream_id] = self.loop.time()
                else:
                    stream_id = self.new_udp_stream(addr, udp_protocol)
                    if stream_id is not None:
                        await asyncio.sleep(0.1)
                        self.udp_last_activity[stream_id] = self.loop.time()
                        self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=False)
                        self.transmit()  # flush
        except Exception as e:
            logger.info(f"Error forwarding UDP to QUIC: {e}")
        finally:
            logger.info("Task UDP to QUIC Ended")
            self.close_this_stream(stream_id)

    def new_udp_stream(self, addr, udp_protocol):
        logger.info(f"new stream for UDP addr {addr} -> {udp_protocol.target_port}")
        try:
            stream_id = self._quic.get_next_available_stream_id()
            self.udp_addr_to_stream[addr] = stream_id
            self.udp_stream_to_addr[stream_id] = addr
            self.udp_stream_to_transport[stream_id] = udp_protocol.transport
            self.udp_last_activity[stream_id] = self.loop.time()
            req_data = parameters.quic_auth_code + "connect,udp," + str(udp_protocol.target_port) + ",!###!"
            self._quic.send_stream_data(stream_id=stream_id, data=req_data.encode("utf-8"), end_stream=False)
            self.transmit()  # flush
            return stream_id
        except Exception as e:
            logger.info(f"Client Error creating new udp stream: {e}")
        return None

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            try:
                if event.end_stream:
                    logger.info(f"Stream={event.stream_id} closed by server.")
                    self.close_this_stream(event.stream_id)
                elif event.stream_id in self.tcp_connections:
                    writer = self.tcp_connections[event.stream_id][1]
                    writer.write(event.data)
                    asyncio.create_task(writer.drain())
                elif event.stream_id in self.udp_stream_to_addr:
                    addr = self.udp_stream_to_addr[event.stream_id]
                    transport = self.udp_stream_to_transport[event.stream_id]
                    transport.sendto(event.data, addr)
                elif event.stream_id in self.tcp_syn_wait:
                    if event.data == (parameters.quic_auth_code + "i am ready,!###!").encode("utf-8"):
                        asyncio.create_task(self.forward_tcp_to_quic(event.stream_id))
                else:
                    logger.warning("unknown Data arrived to client")
            except Exception as e:
                logger.info(f"Quic event client error: {e}")
        elif isinstance(event, StreamReset):
            logger.info(f"Stream {event.stream_id} reset unexpectedly.")
            self.close_this_stream(event.stream_id)
        elif isinstance(event, ConnectionTerminated):
            logger.info(f"Connection lost: {event.reason_phrase}")
            self.connection_lost(event.reason_phrase)

async def run_client():
    global is_quic_established
    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = parameters.quic_verify_cert
    configuration.max_data = parameters.quic_max_data
    configuration.max_stream_data = parameters.quic_max_stream_data
    configuration.idle_timeout = parameters.quic_idle_timeout
    configuration.max_datagram_size = parameters.quic_mtu

    retry_attempts = 0
    while retry_attempts < parameters.max_retry_attempts:
        try:
            logger.warning("Attempting to connect to QUIC server...")
            async with connect(parameters.quic_local_ip,
                               parameters.vio_udp_client_port,
                               configuration=configuration,
                               create_protocol=TunnelClientProtocol,
                               local_port=parameters.quic_client_port) as client:
                
                async def start_tcp_server(local_port, target_port):
                    logger.warning(f"client listen tcp:{local_port} -> to server tcp:{target_port}")
                    server = await asyncio.start_server(
                        lambda r, w: asyncio.create_task(handle_tcp_client(r, w, target_port)),
                        '0.0.0.0', local_port
                    )
                    async with server:
                        await server.serve_forever()
                    logger.info("tcp server finished")

                async def handle_tcp_client(reader, writer, target_port):
                    while not active_protocols:
                        logger.info("Waiting for an active QUIC connection...")
                        await asyncio.sleep(1)
                    protocol = active_protocols[-1]
                    await protocol.handle_tcp_connection(reader, writer, target_port)

                async def start_udp_server(local_port, target_port):
                    while True:
                        try:
                            logger.warning(f"client listen udp:{local_port} -> to server udp:{target_port}")
                            loop = asyncio.get_event_loop()
                            transport, udp_protocol = await loop.create_datagram_endpoint(
                                lambda: UdpProtocol(client, target_port),
                                local_addr=('0.0.0.0', local_port)
                            )
                            mytask = asyncio.create_task(handle_udp_client(udp_protocol))
                            while True:
                                await asyncio.sleep(0.05)
                                if udp_protocol.has_error:
                                    mytask.cancel()
                                    await asyncio.sleep(1)
                                    break
                            logger.info("udp server finished")
                        except Exception as e:
                            logger.info(f"start_udp_server ERR: {e}")

                async def handle_udp_client(udp_protocol):
                    logger.info("creating udp task ....")
                    while not active_protocols:
                        logger.info("Waiting for an active QUIC connection...")
                        await asyncio.sleep(1)
                    protocol = active_protocols[-1]
                    await protocol.forward_udp_to_quic(udp_protocol)

                class UdpProtocol:
                    def __init__(self, client, target_port):
                        self.transport = None
                        self.client = client
                        self.target_port = target_port
                        self.has_error = False
                        self.queue = asyncio.Queue()

                    def connection_made(self, transport):
                        logger.info("NEW DGRAM listen created")
                        logger.info(transport.get_extra_info('socket'))
                        self.transport = transport

                    def datagram_received(self, data, addr):
                        self.queue.put_nowait((data, addr))

                    def error_received(self, exc):
                        logger.info(f"UDP error received: {exc}")
                        self.has_error = True
                        if self.transport:
                            self.transport.close()
                            logger.info("UDP transport closed")

                    def connection_lost(self, exc):
                        logger.info(f"UDP lost. {exc}")
                        self.has_error = True
                        if self.transport:
                            self.transport.close()
                            logger.info("UDP transport closed")

                is_quic_established = True

                tcp_servers_list = []
                for lport, tport in parameters.tcp_port_mapping.items():
                    tcp_servers_list.append(start_tcp_server(lport, tport))

                udp_servers_list = []
                for lport, tport in parameters.udp_port_mapping.items():
                    udp_servers_list.append(start_udp_server(lport, tport))

                await asyncio.gather(
                    asyncio.Future(),  # Run QUIC client forever
                    *tcp_servers_list,
                    *udp_servers_list
                )
        except Exception as e:
            logger.info(f"QUIC connection error: {e}. Retrying in {parameters.retry_interval} seconds...")
            retry_attempts += 1
            await asyncio.sleep(parameters.retry_interval)
    logger.info("Max retry attempts reached. Exiting.")
    sys.exit()

def Quic_client():
    asyncio.run(run_client())

if __name__ == "__main__":
    while True:
        process = multiprocessing.Process(target=Quic_client)
        process.start()
        while process.is_alive():
            time.sleep(5)
        logger.info("client is dead. restarting ...")
        time.sleep(1)