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
        active_protocols.append(self)  # Add this protocol instance to the list 
        asyncio.create_task(self.cleanup_stale_udp_connections())
        asyncio.create_task(self.check_start_connectivity())

    async def check_start_connectivity(self):
        global is_quic_established
        try:
            await asyncio.sleep(7)
            if is_quic_established:
                logger.info(f"QUIC connection established successfully!")
            else:
                logger.info(f"QUIC failed to connect")
                self.connection_lost("QUIC connectivity failed")
        except SystemExit as e:
            logger.info(f"Connectivity check interrupted: {e}")
        except Exception as e:
            logger.info(f"Error in connectivity check: {e}")

    def connection_lost(self, exc):
        super().connection_lost(exc)
        self.close_all_tcp_connections()
        logger.info(f"QUIC connection lost: {exc}")
        for protocol in active_protocols:
            protocol.close_all_tcp_connections()
            protocol.close_all_udp_connections()
            protocol.close()
        if self in active_protocols:
            active_protocols.remove(self)
        time.sleep(1)
        sys.exit()

    def close_all_tcp_connections(self):
        logger.info("Closing all TCP connections...")
        for stream_id, (reader, writer) in self.tcp_connections.items():
            logger.info(f"Closing TCP connection for stream {stream_id}...")
            try:
                writer.close()
                writer.write_eof()
                await writer.drain()
            except Exception as e:
                logger.info(f"Error closing TCP socket: {e}")
        for stream_id, (reader, writer) in self.tcp_syn_wait.items():
            logger.info(f"Closing TCP connection for stream {stream_id}...")
            try:
                writer.close()
                writer.write_eof()
                await writer.drain()
            except Exception as e:
                logger.info(f"Error closing TCP socket: {e}")
        self.tcp_connections.clear()
        self.tcp_syn_wait.clear()

    def close_all_udp_connections(self):
        logger.info("Closing all UDP connections...")
        self.udp_addr_to_stream.clear()
        self.udp_stream_to_addr.clear()
        self.udp_last_activity.clear()
        for stream_id, transport in self.udp_stream_to_transport.items():
            try:
                transport.close()
            except Exception as e:
                logger.info(f"Error closing UDP transport: {e}")
        self.udp_stream_to_transport.clear()

    async def close_this_stream(self, stream_id):
        try:
            logger.info(f"Sending FIN to stream={stream_id}")
            self._quic.send_stream_data(stream_id, b"", end_stream=True)
            self.transmit()
        except Exception as e:
            logger.info(f"Error closing stream: {e}")
        
        try:
            if stream_id in self.tcp_connections:
                writer = self.tcp_connections[stream_id][1]
                writer.close()
                writer.write_eof()
                await writer.drain()
                del self.tcp_connections[stream_id]
            if stream_id in self.tcp_syn_wait:
                writer = self.tcp_syn_wait[stream_id][1]
                writer.close()
                writer.write_eof()
                await writer.drain()
                del self.tcp_syn_wait[stream_id]
            if stream_id in self.udp_stream_to_addr:
                addr = self.udp_stream_to_addr.get(stream_id)
                transport = self.udp_stream_to_transport.get(stream_id)
                if transport:
                    transport.close()
                del self.udp_addr_to_stream[addr]
                del self.udp_stream_to_addr[stream_id]
                del self.udp_last_activity[stream_id]
                del self.udp_stream_to_transport[stream_id]
        except Exception as e:
            logger.info(f"Error closing socket: {e}")

    async def cleanup_stale_udp_connections(self):
        logger.info("UDP cleanup task started")
        check_time = min(parameters.udp_timeout, 60)
        while True:
            await asyncio.sleep(check_time)
            current_time = self.loop.time()
            stale_streams = [
                stream_id for stream_id, last_time in self.udp_last_activity.items()
                if current_time - last_time > parameters.udp_timeout
            ]
            for stream_id in stale_streams:
                logger.info(f"Idle UDP stream={stream_id} timed out")
                await self.close_this_stream(stream_id)

    async def forward_tcp_to_quic(self, stream_id):
        logger.info(f"Starting TCP to QUIC forwarding for stream {stream_id}")
        try:
            (reader, writer) = self.tcp_syn_wait[stream_id]
            self.tcp_connections[stream_id] = (reader, writer)
            del self.tcp_syn_wait[stream_id]

            while True:
                data = await reader.read(4096)
                if not data:
                    break
                self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=False)
                self.transmit()
        except Exception as e:
            logger.info(f"Error forwarding TCP to QUIC: {e}")
        finally:
            logger.info(f"TCP to QUIC forwarding ended for stream {stream_id}")
            await self.close_this_stream(stream_id)

    async def handle_tcp_connection(self, reader, writer, target_port):
        try:
            stream_id = self._quic.get_next_available_stream_id()
            self.tcp_syn_wait[stream_id] = (reader, writer)
            req_data = parameters.quic_auth_code + "connect,tcp," + str(target_port) + ",!###!"
            self._quic.send_stream_data(stream_id=stream_id, data=req_data.encode("utf-8"), end_stream=False)
            self.transmit()
        except Exception as e:
            logger.info(f"Error handling TCP connection: {e}")
            await self.close_this_stream(stream_id)

    async def forward_udp_to_quic(self, udp_protocol):
        logger.info("Starting UDP to QUIC forwarding")
        try:
            while True:
                data, addr = await udp_protocol.queue.get()
                stream_id = self.udp_addr_to_stream.get(addr)
                if stream_id is not None:
                    self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=False)
                    self.transmit()
                    self.udp_last_activity[stream_id] = self.loop.time()
                else:
                    stream_id = self.new_udp_stream(addr, udp_protocol)
                    if stream_id is not None:
                        await asyncio.sleep(0.1)
                        self.udp_last_activity[stream_id] = self.loop.time()
                        self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=False)
                        self.transmit()
        except Exception as e:
            logger.info(f"Error forwarding UDP to QUIC: {e}")
        finally:
            logger.info("UDP to QUIC forwarding ended")
            await self.close_all_udp_connections()

    def new_udp_stream(self, addr, udp_protocol):
        logger.info(f"Creating new UDP stream for addr {addr} -> port {udp_protocol.target_port}")
        try:
            stream_id = self._quic.get_next_available_stream_id()
            self.udp_addr_to_stream[addr] = stream_id
            self.udp_stream_to_addr[stream_id] = addr
            self.udp_stream_to_transport[stream_id] = udp_protocol.transport
            self.udp_last_activity[stream_id] = self.loop.time()
            req_data = parameters.quic_auth_code + "connect,udp," + str(udp_protocol.target_port) + ",!###!"
            self._quic.send_stream_data(stream_id=stream_id, data=req_data.encode("utf-8"), end_stream=False)
            self.transmit()
            return stream_id
        except Exception as e:
            logger.info(f"Error creating new UDP stream: {e}")
            return None

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            try:
                if event.end_stream:
                    logger.info(f"Stream={event.stream_id} closed by server")
                    await self.close_this_stream(event.stream_id)
                elif event.stream_id in self.tcp_connections:
                    writer = self.tcp_connections[event.stream_id][1]
                    writer.write(event.data)
                    await writer.drain()
                elif event.stream_id in self.udp_stream_to_addr:
                    addr = self.udp_stream_to_addr[event.stream_id]
                    transport = self.udp_stream_to_transport[event.stream_id]
                    transport.sendto(event.data, addr)
                elif event.stream_id in self.tcp_syn_wait:
                    if event.data == (parameters.quic_auth_code + "i am ready,!###!").encode("utf-8"):
                        asyncio.create_task(self.forward_tcp_to_quic(event.stream_id))
                else:
                    logger.warning("Received unknown data from server")
            except Exception as e:
                logger.info(f"Error processing QUIC event: {e}")
        elif isinstance(event, StreamReset):
            logger.info(f"Stream {event.stream_id} reset unexpectedly")
            await self.close_this_stream(event.stream_id)
        elif isinstance(event, ConnectionTerminated):
            logger.info(f"Connection terminated: {event.reason_phrase}")
            self.connection_lost(event.reason_phrase)

async def run_client():
    global is_quic_established
    configuration = QuicConfiguration(is_client=True)
    configuration.verify_mode = parameters.quic_verify_cert
    configuration.max_data = parameters.quic_max_data
    configuration.max_stream_data = parameters.quic_max_stream_data
    configuration.idle_timeout = parameters.quic_idle_timeout
    configuration.max_datagram_size = parameters.quic_mtu
    try:
        logger.warning("Attempting to connect to QUIC server...")
        async with connect(parameters.quic_local_ip,
                           parameters.vio_udp_client_port,
                           configuration=configuration,
                           create_protocol=TunnelClientProtocol,
                           local_port=parameters.quic_client_port) as client:
            async def start_tcp_server(local_port, target_port):
                logger.warning(f"Client listening on TCP:{local_port} -> forwarding to server TCP:{target_port}")
                server = await asyncio.start_server(
                    lambda r, w: asyncio.create_task(handle_tcp_client(r, w, target_port)),
                    '0.0.0.0', local_port
                )
                async with server:
                    await server.serve_forever()

            async def handle_tcp_client(reader, writer, target_port):
                while not active_protocols:
                    logger.info("Waiting for an active QUIC connection...")
                    await asyncio.sleep(1)
                protocol = active_protocols[-1]
                await protocol.handle_tcp_connection(reader, writer, target_port)

            async def start_udp_server(local_port, target_port):
                while True:
                    try:
                        logger.warning(f"Client listening on UDP:{local_port} -> forwarding to server UDP:{target_port}")
                        loop = asyncio.get_event_loop()
                        transport, udp_protocol = await loop.create_datagram_endpoint(
                            lambda: UdpProtocol(client, target_port),
                            local_addr=('0.0.0.0', local_port)
                        )
                        mytask = asyncio.create_task(handle_udp_client(udp_protocol))
                        while not udp_protocol.has_error:
                            await asyncio.sleep(0.05)
                    except Exception as e:
                        logger.info(f"UDP server error: {e}")
                        await asyncio.sleep(1)
                    finally:
                        transport.close()
                        await asyncio.sleep(0.5)
                        transport.abort()
                        logger.info("UDP transport aborted")
                        await asyncio.sleep(1.5)

            async def handle_udp_client(udp_protocol):
                logger.info("Starting UDP client task...")
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
                    logger.info("New UDP listener created")
                    self.transport = transport

                def datagram_received(self, data, addr):
                    self.queue.put_nowait((data, addr))

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

            is_quic_established = True
            tcp_servers_list = [start_tcp_server(lport, tport) for lport, tport in parameters.tcp_port_mapping.items()]
            udp_servers_list = [start_udp_server(lport, tport) for lport, tport in parameters.udp_port_mapping.items()]
            await asyncio.gather(
                asyncio.Future(),
                *tcp_servers_list,
                *udp_servers_list
            )
    except SystemExit as e:
        logger.info(f"System exit: {e}")
    except asyncio.CancelledError as e:
        logger.info(f"Task cancelled: {e}")
    except ConnectionError as e:
        logger.info(f"Connection error: {e}")
    except Exception as e:
        logger.info(f"Unexpected error: {e}")

def Quic_client():
    asyncio.run(run_client())

if __name__ == "__main__":
    while True:
        process = multiprocessing.Process(target=Quic_client)
        process.start()
        while process.is_alive():
            time.sleep(5)
        logger.info("Client process terminated, restarting...")
        time.sleep(1)
