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
        self.tcp_connections = {}  # Map TCP connections to QUIC streams
        self.udp_connections = {}  # Map UDP connections to QUIC streams
        self.udp_last_activity = {}  # Track last activity time for UDP connections
        active_protocols.append(self)  # Add this protocol instance to the list
        try:
            asyncio.create_task(self.cleanup_stale_udp_connections())
        except Exception as e:
            logger.info(f"Error in cleanup_stale_udp task: {e}")

    def connection_lost(self, exc):
        logger.info("Quic channel lost")
        if self in active_protocols:
            active_protocols.remove(self)
        super().connection_lost(exc)
        self.close_all_tcp_connections()
        self.close_all_udp_connections()

    def close_all_tcp_connections(self):
        logger.info("Closing all TCP connections from server...")
        for stream_id, (reader, writer) in self.tcp_connections.items():
            logger.info(f"Closing TCP connection for stream {stream_id}...")
            writer.close()
        self.tcp_connections.clear()

    def close_all_udp_connections(self):
        logger.info("Closing all UDP connections from server...")
        for stream_id, (transport, _) in self.udp_connections.items():
            logger.info(f"Closing UDP connection for stream {stream_id}...")
            transport.close()
        self.udp_connections.clear()
        self.udp_last_activity.clear()


    def close_this_stream(self, stream_id):
        try:
            logger.info(f"FIN to stream={stream_id} sent")
            self._quic.send_stream_data(stream_id, b"", end_stream=True)  # Send FIN flag
            self.transmit()  # Send the FIN flag over the network
        except Exception as e:
            logger.info(f"Error closing stream at server: {e}")
        
        try:            
            if stream_id in self.tcp_connections:
                writer = self.tcp_connections[stream_id][1]
                writer.close()
                del self.tcp_connections[stream_id]
            if stream_id in self.udp_connections:
                transport, _ = self.udp_connections[stream_id]
                transport.close()
                del self.udp_connections[stream_id]
                del self.udp_last_activity[stream_id]                
        except Exception as e:
            logger.info(f"Error closing socket at server: {e}")




    async def cleanup_stale_udp_connections(self):
        logger.info("UDP cleanup task running!")
        check_time = min(parameters.udp_timeout,60)
        while True:
            await asyncio.sleep(check_time)  # Run cleanup every 60 seconds
            current_time = self.loop.time()
            stale_streams = [
                stream_id for stream_id, last_time in self.udp_last_activity.items()
                if current_time - last_time > parameters.udp_timeout
            ]
            for stream_id in stale_streams:
                logger.info(f"idle UDP stream={stream_id} timeout reached")
                self.close_this_stream(stream_id)



    async def forward_tcp_to_quic(self, stream_id, reader):
        logger.info(f"Task TCP to QUIC started")
        try:
            while True:
                data = await reader.read(4096)  # Read data from TCP socket
                if not data:
                    break
                # logger.info(f"Forwarding data from TCP to QUIC on stream {stream_id}")
                self._quic.send_stream_data(stream_id=stream_id, data=data, end_stream=False)
                self.transmit()  # Flush
        except Exception as e:
            logger.info(f"Error forwarding TCP to QUIC: {e}")
        finally:
            logger.info(f"Task TCP to QUIC Ended")
            self.close_this_stream(stream_id)



    async def connect_tcp(self, stream_id, target_port):
        logger.info(f"Connecting to TCP:{target_port}...")
        try:
            reader, writer = await asyncio.open_connection(parameters.xray_server_ip_address, target_port)
            logger.info(f"TCP connection established for stream {stream_id} to port {target_port}")

            # Start forwarding data from TCP to QUIC
            asyncio.create_task(self.forward_tcp_to_quic(stream_id, reader))

            resp_data = parameters.quic_auth_code + "i am ready,!###!"
            self._quic.send_stream_data(stream_id=stream_id, data=resp_data.encode("utf-8"), end_stream=False)
            self.transmit()  # Flush

            self.tcp_connections[stream_id] = (reader, writer)
        except Exception as e:
            logger.info(f"Failed to establish TCP:{target_port} connection: {e}")
            self.close_this_stream(stream_id)



    async def forward_udp_to_quic(self, stream_id, protocol):
        logger.info(f"Task UDP to QUIC started")
        try:
            while True:
                data, _ = await protocol.queue.get()  # Wait for data from UDP
                if(data == None):
                    break
                # logger.info(f"Forwarding data from UDP to QUIC on stream {stream_id}")
                self._quic.send_stream_data(stream_id, data)
                self.transmit()  # Flush
                self.udp_last_activity[stream_id] = self.loop.time()
        except Exception as e:
            logger.info(f"Error forwarding UDP to QUIC: {e}")
        finally:
            logger.info(f"Task UDP to QUIC Ended")
            self.close_this_stream(stream_id)


    async def connect_udp(self, stream_id, target_port):
        class UdpProtocol:
            def __init__(self):
                self.transport = None
                self.queue = asyncio.Queue()
                self.stream_id = stream_id

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                logger.info(f"put this to queue data={data} addr={addr}")
                self.queue.put_nowait((data, addr))

            def error_received(self, exc):
                logger.info(f"UDP error received: {exc}")
                self.queue.put_nowait((None, None)) # to cancel task
                if(self.transport):
                        self.transport.close()                        
                        logger.info("UDP transport closed")

            def connection_lost(self, exc):
                logger.info("UDP connection lost.")
                self.queue.put_nowait((None, None)) # to cancel task
                if(self.transport):
                        self.transport.close()
                        logger.info("UDP transport closed")

        try:
            # Create a UDP socket
            logger.info(f"Connecting to UDP:{target_port}...")
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                UdpProtocol,
                remote_addr=(parameters.xray_server_ip_address, target_port)
            )
            self.udp_connections[stream_id] = (transport, protocol)
            self.udp_last_activity[stream_id] = self.loop.time()  # Track last activity time
            logger.info(f"UDP connection established for stream {stream_id} to port {target_port}")

            asyncio.create_task(self.forward_udp_to_quic(stream_id, protocol))
        except Exception as e:
            logger.info(f"Failed to establish UDP connection: {e}")




    def quic_event_received(self, event):
        # print("EVENT",event)
        if isinstance(event, StreamDataReceived):
            try:
                # logger.info(f"Server received from QUIC on stream {event.stream_id}")
                # logger.info(f"Server TCP IDs -> {self.tcp_connections.keys()}")
                # logger.info(f"Server UDP IDs -> {self.udp_connections.keys()}")

                if event.end_stream:
                    logger.info(f"Stream={event.stream_id} closed by client.")
                    self.close_this_stream(event.stream_id)

                # Forward data to the corresponding TCP connection
                elif event.stream_id in self.tcp_connections:
                    writer = self.tcp_connections[event.stream_id][1]
                    writer.write(event.data)  # Send data over TCP
                    try:
                        asyncio.create_task(writer.drain())
                    except ConnectionResetError as e42:
                        logger.info(f"ERR in writer drain task : {e42}")
                    except Exception as e43:
                        logger.info(f"ERR in writer drain task : {e43}")

                # Forward data to the corresponding UDP connection
                elif event.stream_id in self.udp_connections:                    
                    transport, _ = self.udp_connections[event.stream_id]
                    transport.sendto(event.data)  # Send data over UDP
                    self.udp_last_activity[event.stream_id] = self.loop.time()  # Update last activity time

                else:
                    socket_type = None
                    socket_port = 0

                    # Assume req is like => auth+"connect,udp,443,!###!"
                    new_req = event.data.split(b",!###!", 1)
                    req_header = ""
                    try:
                        req_header = new_req[0].decode("utf-8")
                    except Exception as e47:
                        logger.info(f"ERR in req decoding : {e47}")
                        req_header=""
                    
                    logger.info("New req comes -> " + req_header)

                    if req_header.startswith(parameters.quic_auth_code + "connect,"):
                        j = len(parameters.quic_auth_code) + 8
                        if req_header[j:j + 3] == "tcp":
                            socket_type = "tcp"
                        elif req_header[j:j + 3] == "udp":
                            socket_type = "udp"

                        try:
                            socket_port = int(req_header[j + 4:])
                        except ValueError:
                            logger.info("Invalid port.")

                        if socket_port > 0:
                            if socket_type == "tcp":
                                # New stream detected, create a TCP connection
                                asyncio.create_task(self.connect_tcp(event.stream_id, socket_port))
                            elif socket_type == "udp":
                                # New stream detected, create a UDP connection
                                asyncio.create_task(self.connect_udp(event.stream_id, socket_port))
                            else:
                                logger.info("Invalid Req: socket type unknown.")
                        else:
                            logger.info("Invalid Req: socket port unknown.")
                    else:
                        logger.info("Invalid Req header")

            except Exception as e:
                logger.info(f"Quic event server error: {e}")

        elif isinstance(event, StreamReset):
            # Handle stream reset (client closed the stream)
            logger.info(f"Stream {event.stream_id} reset by client.")
            self.close_this_stream(event.stream_id)

        elif isinstance(event, ConnectionTerminated):
            logger.info(f"Connection lost: {event.reason_phrase}")
            self.connection_lost(event.reason_phrase)


async def run_server():
    configuration = QuicConfiguration(is_client=False)
    configuration.load_cert_chain(parameters.quic_cert_filepath[0], parameters.quic_cert_filepath[1])
    configuration.max_data = parameters.quic_max_data
    configuration.max_stream_data = parameters.quic_max_stream_data
    configuration.idle_timeout = parameters.quic_idle_timeout
    configuration.max_datagram_size = parameters.quic_mtu

    # Start QUIC server
    await serve("0.0.0.0", parameters.quic_server_port, configuration=configuration, create_protocol=TunnelServerProtocol)
    logger.warning(f"Server listening for QUIC on port {parameters.quic_server_port}")

    # Keep the server running
    await asyncio.Future()  # Run forever


def handle_shutdown(signum, frame):
    logger.info("Shutting down server gracefully...")
    for protocol in active_protocols:
        protocol.close_all_tcp_connections()
        protocol.close_all_udp_connections()
        protocol.close()
    logger.info("Server shutdown complete.")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    asyncio.run(run_server())