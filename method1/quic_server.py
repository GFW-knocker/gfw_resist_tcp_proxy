import asyncio
import logging
import signal
import sys
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset
import parameters

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("QuicServer")

# Global list to track active protocol instances
active_protocols = []

class TunnelServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.loop = asyncio.get_event_loop()
        self.tcp_connections = {}
        self.udp_connections = {}
        self.udp_last_activity = {}
        active_protocols.append(self)
        asyncio.create_task(self.cleanup_stale_udp_connections())

    def connection_lost(self, exc):
        logger.info(f"QUIC connection lost: {exc}")
        if self in active_protocols:
            active_protocols.remove(self)
        super().connection_lost(exc)
        self.close_all_tcp_connections()
        self.close_all_udp_connections()

    def close_all_tcp_connections(self):
        logger.info("Closing all TCP connections from server...")
        for stream_id, (reader, writer) in self.tcp_connections.items():
            logger.info(f"Closing TCP connection for stream {stream_id}...")
            try:
                writer.close()
                writer.write_eof()
                await writer.drain()
            except Exception as e:
                logger.info(f"Error closing TCP socket: {e}")
        self.tcp_connections.clear()

    def close_all_udp_connections(self):
        logger.info("Closing all UDP connections from server...")
        for stream_id, (transport, _) in self.udp_connections.items():
            logger.info(f"Closing UDP connection for stream {stream_id}...")
            try:
                transport.close()
            except Exception as e:
                logger.info(f"Error closing UDP transport: {e}")
        self.udp_connections.clear()
        self.udp_last_activity.clear()

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
            if stream_id in self.udp_connections:
                transport, _ = self.udp_connections[stream_id]
                transport.close()
                del self.udp_connections[stream_id]
                del self.udp_last_activity[stream_id]
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

    async def forward_tcp_to_quic(self, stream_id, reader):
        logger.info(f"Starting TCP to QUIC forwarding for stream {stream_id}")
        try:
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

    async def connect_tcp(self, stream_id, target_port):
        logger.info(f"Connecting to TCP:{target_port}...")
        try:
            reader, writer = await asyncio.open_connection(parameters.xray_server_ip_address, target_port)
            logger.info(f"TCP connection established for stream {stream_id} to port {target_port}")
            asyncio.create_task(self.forward_tcp_to_quic(stream_id, reader))
            resp_data = parameters.quic_auth_code + "i am ready,!###!"
            self._quic.send_stream_data(stream_id=stream_id, data=resp_data.encode("utf-8"), end_stream=False)
            self.transmit()
            self.tcp_connections[stream_id] = (reader, writer)
        except Exception as e:
            logger.info(f"Failed to establish TCP connection to port {target_port}: {e}")
            await self.close_this_stream(stream_id)

    async def forward_udp_to_quic(self, stream_id, protocol):
        logger.info(f"Starting UDP to QUIC forwarding for stream {stream_id}")
        try:
            while True:
                data, _ = await protocol.queue.get()
                if data is None:
                    break
                self._quic.send_stream_data(stream_id, data)
                self.transmit()
                self.udp_last_activity[stream_id] = self.loop.time()
        except Exception as e:
            logger.info(f"Error forwarding UDP to QUIC: {e}")
        finally:
            logger.info(f"UDP to QUIC forwarding ended for stream {stream_id}")
            await self.close_this_stream(stream_id)

    async def connect_udp(self, stream_id, target_port):
        class UdpProtocol:
            def __init__(self):
                self.transport = None
                self.queue = asyncio.Queue()
                self.stream_id = stream_id

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.queue.put_nowait((data, addr))

            def error_received(self, exc):
                logger.info(f"UDP error received: {exc}")
                self.queue.put_nowait((None, None))
                if self.transport:
                    self.transport.close()

            def connection_lost(self, exc):
                logger.info("UDP connection lost")
                self.queue.put_nowait((None, None))
                if self.transport:
                    self.transport.close()

        try:
            logger.info(f"Connecting to UDP:{target_port}...")
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                UdpProtocol,
                remote_addr=(parameters.xray_server_ip_address, target_port)
            )
            self.udp_connections[stream_id] = (transport, protocol)
            self.udp_last_activity[stream_id] = self.loop.time()
            logger.info(f"UDP connection established for stream {stream_id} to port {target_port}")
            asyncio.create_task(self.forward_udp_to_quic(stream_id, protocol))
        except Exception as e:
            logger.info(f"Failed to establish UDP connection: {e}")

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            try:
                if event.end_stream:
                    logger.info(f"Stream={event.stream_id} closed by client")
                    await self.close_this_stream(event.stream_id)
                elif event.stream_id in self.tcp_connections:
                    writer = self.tcp_connections[event.stream_id][1]
                    writer.write(event.data)
                    await writer.drain()
                elif event.stream_id in self.udp_connections:
                    transport, _ = self.udp_connections[event.stream_id]
                    transport.sendto(event.data)
                    self.udp_last_activity[event.stream_id] = self.loop.time()
                else:
                    socket_type = None
                    socket_port = 0
                    new_req = event.data.split(b",!###!", 1)
                    req_header = new_req[0].decode("utf-8")
                    logger.info(f"New request received: {req_header}")
                    if req_header.startswith(parameters.quic_auth_code + "connect,"):
                        j = len(parameters.quic_auth_code) + 8
                        if req_header[j:j + 3] == "tcp":
                            socket_type = "tcp"
                        elif req_header[j:j + 3] == "udp":
                            socket_type = "udp"
                        socket_port = int(req_header[j + 4:])
                        if socket_port > 0:
                            if socket_type == "tcp":
                                asyncio.create_task(self.connect_tcp(event.stream_id, socket_port))
                            elif socket_type == "udp":
                                asyncio.create_task(self.connect_udp(event.stream_id, socket_port))
                            else:
                                logger.info("Invalid request: Unknown socket type")
                        else:
                            logger.info("Invalid request: Unknown socket port")
                    else:
                        logger.info("Invalid request header")
            except Exception as e:
                logger.info(f"Error processing QUIC event: {e}")
        elif isinstance(event, StreamReset):
            logger.info(f"Stream {event.stream_id} reset by client")
            await self.close_this_stream(event.stream_id)
        elif isinstance(event, ConnectionTerminated):
            logger.info(f"Connection terminated: {event.reason_phrase}")
            self.connection_lost(event.reason_phrase)

async def run_server():
    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(parameters.quic_cert_filepath[0], parameters.quic_cert_filepath[1])
    configuration.max_data = parameters.quic_max_data
    configuration.max_stream_data = parameters.quic_max_stream_data
    configuration.idle_timeout = parameters.quic_idle_timeout
    configuration.max_datagram_size = parameters.quic_mtu
    await serve("0.0.0.0", parameters.quic_server_port, configuration=configuration, create_protocol=TunnelServerProtocol)
    logger.warning(f"Server listening for QUIC on port {parameters.quic_server_port}")
    await asyncio.Future()

def handle_shutdown(signum, frame):
    logger.info("Shutting down server gracefully...")
    for protocol in active_protocols:
        protocol.close_all_tcp_connections()
        protocol.close_all_udp_connections()
        protocol.close()
    logger.info("Server shutdown complete")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    asyncio.run(run_server())
