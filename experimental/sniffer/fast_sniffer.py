"""
Enhanced Fast Asynchronous Packet Sniffer using pcapy.

This implementation provides a robust, high-performance packet sniffer 
with advanced features including packet filtering, protocol analysis,
and comprehensive statistics collection.
"""

import asyncio
import pcapy
import struct
import logging
import sys
import signal
import time
import socket
import json
import argparse
import os
from datetime import datetime
from collections import defaultdict, deque

# Setup logging configuration with more detailed formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('packet_sniffer.log')
    ]
)
logger = logging.getLogger("EnhancedSniffer")

class ProtocolAnalyzer:
    """Handles protocol-specific packet analysis."""
    
    # Protocol number to name mapping
    PROTOCOLS = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        58: 'ICMPv6',
        89: 'OSPF',
        132: 'SCTP'
    }
    
    @staticmethod
    def analyze_ip(ip_data):
        """
        Analyze IP packet and extract header information.
        
        Args:
            ip_data: Raw IP packet data
            
        Returns:
            dict: Extracted IP header information
        """
        try:
            # Extract IP header
            ip_header = ip_data[:20]  # Basic IP header without options
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            ip_header_length = ihl * 4
            
            ttl = iph[5]
            protocol = iph[6]
            protocol_name = ProtocolAnalyzer.PROTOCOLS.get(protocol, f"Unknown({protocol})")
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            return {
                'version': version,
                'header_length': ip_header_length,
                'ttl': ttl,
                'protocol': protocol,
                'protocol_name': protocol_name,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'data': ip_data[ip_header_length:]  # Payload after IP header
            }
        except Exception as e:
            logger.error(f"Error analyzing IP packet: {e}")
            return None
    
    @staticmethod
    def analyze_tcp(tcp_data):
        """
        Analyze TCP packet and extract header information.
        
        Args:
            tcp_data: Raw TCP packet data
            
        Returns:
            dict: Extracted TCP header information
        """
        try:
            # Extract TCP header - first 20 bytes minimum
            tcp_header = tcp_data[:20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            
            src_port = tcph[0]
            dst_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            
            # Calculate TCP header length
            doff_reserved = tcph[4]
            tcph_length = (doff_reserved >> 4) * 4
            
            # Extract flags
            flags = tcph[5]
            fin = (flags & 1) != 0
            syn = (flags & 2) != 0
            rst = (flags & 4) != 0
            psh = (flags & 8) != 0
            ack = (flags & 16) != 0
            urg = (flags & 32) != 0
            
            window = tcph[6]
            
            return {
                'src_port': src_port,
                'dst_port': dst_port,
                'sequence': sequence,
                'acknowledgement': acknowledgement,
                'header_length': tcph_length,
                'flags': {
                    'fin': fin,
                    'syn': syn,
                    'rst': rst,
                    'psh': psh,
                    'ack': ack,
                    'urg': urg
                },
                'window': window,
                'data': tcp_data[tcph_length:]  # Payload after TCP header
            }
        except Exception as e:
            logger.error(f"Error analyzing TCP packet: {e}")
            return None
    
    @staticmethod
    def analyze_udp(udp_data):
        """
        Analyze UDP packet and extract header information.
        
        Args:
            udp_data: Raw UDP packet data
            
        Returns:
            dict: Extracted UDP header information
        """
        try:
            # Extract UDP header - always 8 bytes
            udp_header = udp_data[:8]
            udph = struct.unpack("!HHHH", udp_header)
            
            src_port = udph[0]
            dst_port = udph[1]
            length = udph[2]
            
            return {
                'src_port': src_port,
                'dst_port': dst_port,
                'length': length,
                'data': udp_data[8:]  # Payload after UDP header
            }
        except Exception as e:
            logger.error(f"Error analyzing UDP packet: {e}")
            return None


class NetworkStatistics:
    """Collects and maintains network traffic statistics."""
    
    def __init__(self, window_size=60):
        """
        Initialize statistics collection.
        
        Args:
            window_size: Time window in seconds for rate calculations
        """
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.window_size = window_size
        
        # Protocol statistics
        self.protocol_counts = defaultdict(int)
        self.ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        
        # For rate calculation
        self.packet_times = deque()
        self.packet_sizes = deque()
    
    def update(self, packet_size, protocol_info=None):
        """
        Update statistics with new packet information.
        
        Args:
            packet_size: Size of the packet in bytes
            protocol_info: Dictionary containing protocol information
        """
        current_time = time.time()
        self.total_packets += 1
        self.total_bytes += packet_size
        
        # Add to sliding window for rate calculation
        self.packet_times.append(current_time)
        self.packet_sizes.append(packet_size)
        
        # Remove outdated entries
        while self.packet_times and current_time - self.packet_times[0] > self.window_size:
            self.packet_times.popleft()
            self.packet_sizes.popleft()
        
        # Update protocol specific statistics
        if protocol_info:
            if 'protocol_name' in protocol_info:
                self.protocol_counts[protocol_info['protocol_name']] += 1
            
            if 'src_ip' in protocol_info:
                self.ip_counts[protocol_info['src_ip']] += 1
            
            if 'dst_ip' in protocol_info:
                self.ip_counts[protocol_info['dst_ip']] += 1
            
            # Port statistics for TCP/UDP
            if 'src_port' in protocol_info:
                port_key = f"{protocol_info.get('protocol_name', 'Unknown')}:{protocol_info['src_port']}"
                self.port_counts[port_key] += 1
            
            if 'dst_port' in protocol_info:
                port_key = f"{protocol_info.get('protocol_name', 'Unknown')}:{protocol_info['dst_port']}"
                self.port_counts[port_key] += 1
    
    def get_packet_rate(self):
        """
        Calculate the current packet rate.
        
        Returns:
            float: Packets per second
        """
        if not self.packet_times:
            return 0.0
        
        time_span = self.packet_times[-1] - self.packet_times[0] if len(self.packet_times) > 1 else 1
        if time_span < 0.001:  # Avoid division by zero
            time_span = 0.001
            
        return len(self.packet_times) / time_span
    
    def get_bandwidth(self):
        """
        Calculate the current bandwidth usage.
        
        Returns:
            float: Bytes per second
        """
        if not self.packet_times:
            return 0.0
            
        time_span = self.packet_times[-1] - self.packet_times[0] if len(self.packet_times) > 1 else 1
        if time_span < 0.001:  # Avoid division by zero
            time_span = 0.001
            
        return sum(self.packet_sizes) / time_span
    
    def get_summary(self):
        """
        Get a summary of collected statistics.
        
        Returns:
            dict: Summary statistics
        """
        runtime = time.time() - self.start_time
        
        # Get top 5 IPs and protocols
        top_protocols = sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ips = sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ports = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'runtime_seconds': runtime,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_per_second': self.get_packet_rate(),
            'bytes_per_second': self.get_bandwidth(),
            'top_protocols': dict(top_protocols),
            'top_ips': dict(top_ips),
            'top_ports': dict(top_ports)
        }


class EnhancedSniffer:
    """
    Enhanced asynchronous packet sniffer with advanced filtering and analysis.
    """
    
    def __init__(self, interface="eth0", bpf_filter="", packet_callback=None, snaplen=65536, 
                 promiscuous=True, timeout_ms=0, stats_interval=10):
        """
        Initialize the enhanced packet sniffer.
        
        Args:
            interface: Network interface to capture packets from
            bpf_filter: BPF filter string (e.g., "tcp port 80")
            packet_callback: Optional callback function to process each packet
            snaplen: Maximum number of bytes to capture from each packet
            promiscuous: Whether to put the interface in promiscuous mode
            timeout_ms: Read timeout in milliseconds (0 for no timeout)
            stats_interval: Interval in seconds for printing statistics
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.timeout_ms = timeout_ms
        self.stats_interval = stats_interval
        
        # Use the provided callback or the default handler
        self.packet_callback = packet_callback if packet_callback is not None else self.default_packet_handler
        
        # Initialize asyncio components
        self.loop = asyncio.get_event_loop()
        self._stop = False
        self._pause = False
        
        # Statistics collection
        self.stats = NetworkStatistics()
        self.last_stats_time = 0
        
        # Initialize pcapy capture
        try:
            logger.info(f"Opening interface {self.interface} for capture...")
            self.cap = pcapy.open_live(
                self.interface, 
                self.snaplen, 
                1 if self.promiscuous else 0, 
                self.timeout_ms
            )
            
            if self.bpf_filter:
                logger.info(f"Setting BPF filter: {self.bpf_filter}")
                self.cap.setfilter(self.bpf_filter)
                
            # Get datalink type
            self.datalink_type = self.cap.datalink()
            logger.info(f"Datalink type: {self.datalink_type}")
            
        except pcapy.PcapError as e:
            logger.error(f"Error opening interface {self.interface}: {e}")
            available_devs = pcapy.findalldevs()
            logger.info(f"Available interfaces: {', '.join(available_devs)}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error initializing sniffer: {e}")
            sys.exit(1)
    
    def default_packet_handler(self, hdr, data):
        """
        Default packet handler with comprehensive protocol analysis.
        
        Args:
            hdr: Packet header information
            data: Raw packet data
        """
        try:
            packet_len = len(data)
            timestamp = hdr.getts()
            formatted_time = datetime.fromtimestamp(timestamp[0]).strftime('%Y-%m-%d %H:%M:%S')
            
            # Update statistics
            self.stats.update(packet_len)
            
            # Extract Ethernet header (first 14 bytes)
            eth_header = data[:14]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = eth[2]
            
            # Decode MAC addresses
            src_mac = ':'.join([f"{b:02x}" for b in eth_header[0:6]])
            dst_mac = ':'.join([f"{b:02x}" for b in eth_header[6:12]])
            
            protocol_info = {}
            
            # Process based on Ethernet type
            if eth_protocol == 0x0800:  # IPv4
                ip_info = ProtocolAnalyzer.analyze_ip(data[14:])
                if ip_info:
                    # Update protocol statistics
                    self.stats.update(packet_len, ip_info)
                    protocol_info = ip_info
                    
                    # Further analyze based on protocol
                    if ip_info['protocol'] == 6:  # TCP
                        tcp_info = ProtocolAnalyzer.analyze_tcp(ip_info['data'])
                        if tcp_info:
                            protocol_info.update(tcp_info)
                            # Combine IP and TCP info for stats update
                            combined_info = {**ip_info, **tcp_info}
                            self.stats.update(packet_len, combined_info)
                            
                            # Log TCP connection information
                            if tcp_info['flags']['syn'] and not tcp_info['flags']['ack']:
                                logger.info(
                                    f"TCP connection initiated: {ip_info['src_ip']}:{tcp_info['src_port']} -> "
                                    f"{ip_info['dst_ip']}:{tcp_info['dst_port']}"
                                )
                            elif tcp_info['flags']['fin']:
                                logger.info(
                                    f"TCP connection closing: {ip_info['src_ip']}:{tcp_info['src_port']} -> "
                                    f"{ip_info['dst_ip']}:{tcp_info['dst_port']}"
                                )
                            elif tcp_info['flags']['rst']:
                                logger.info(
                                    f"TCP connection reset: {ip_info['src_ip']}:{tcp_info['src_port']} -> "
                                    f"{ip_info['dst_ip']}:{tcp_info['dst_port']}"
                                )
                            
                    elif ip_info['protocol'] == 17:  # UDP
                        udp_info = ProtocolAnalyzer.analyze_udp(ip_info['data'])
                        if udp_info:
                            protocol_info.update(udp_info)
                            # Combine IP and UDP info for stats update
                            combined_info = {**ip_info, **udp_info}
                            self.stats.update(packet_len, combined_info)
                            
                            # Log UDP packet information
                            logger.debug(
                                f"UDP packet: {ip_info['src_ip']}:{udp_info['src_port']} -> "
                                f"{ip_info['dst_ip']}:{udp_info['dst_port']} "
                                f"(Length: {udp_info['length']} bytes)"
                            )
                    
                    # Log packet information
                    logger.info(
                        f"{formatted_time} - {ip_info['protocol_name']} packet: "
                        f"{ip_info['src_ip']} -> {ip_info['dst_ip']} "
                        f"(TTL: {ip_info['ttl']}, Length: {packet_len} bytes)"
                    )
                
            elif eth_protocol == 0x0806:  # ARP
                logger.info(f"{formatted_time} - ARP packet: {src_mac} -> {dst_mac}")
                
            elif eth_protocol == 0x86DD:  # IPv6
                logger.info(f"{formatted_time} - IPv6 packet: {src_mac} -> {dst_mac}")
                
            else:
                logger.debug(f"{formatted_time} - Unknown packet type (0x{eth_protocol:04x}): {src_mac} -> {dst_mac}")
        
            # Print statistics periodically
            current_time = time.time()
            if current_time - self.last_stats_time >= self.stats_interval:
                self.print_statistics()
                self.last_stats_time = current_time
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def print_statistics(self):
        """Print current network statistics."""
        stats = self.stats.get_summary()
        
        logger.info("----- Network Statistics -----")
        logger.info(f"Runtime: {stats['runtime_seconds']:.2f} seconds")
        logger.info(f"Total Packets: {stats['total_packets']}")
        logger.info(f"Total Data: {stats['total_bytes'] / 1024:.2f} KB")
        logger.info(f"Current Rate: {stats['packets_per_second']:.2f} packets/sec")
        logger.info(f"Current Bandwidth: {stats['bytes_per_second'] / 1024:.2f} KB/sec")
        
        if stats['top_protocols']:
            logger.info("Top Protocols:")
            for proto, count in stats['top_protocols'].items():
                logger.info(f"  {proto}: {count} packets")
        
        if stats['top_ips']:
            logger.info("Top IPs:")
            for ip, count in stats['top_ips'].items():
                logger.info(f"  {ip}: {count} packets")
        
        logger.info("-----------------------------")
    
    def save_statistics(self, filename="sniffer_stats.json"):
        """
        Save current statistics to a JSON file.
        
        Args:
            filename: Output JSON filename
        """
        try:
            stats = self.stats.get_summary()
            with open(filename, 'w') as f:
                json.dump(stats, f, indent=2)
            logger.info(f"Statistics saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving statistics: {e}")
    
    async def start(self):
        """
        Start the asynchronous sniffer loop.
        Continuously captures packets and processes them using the callback.
        """
        logger.info(f"Enhanced sniffer started on interface {self.interface}")
        if self.bpf_filter:
            logger.info(f"BPF filter: {self.bpf_filter}")
        self.last_stats_time = time.time()
        
        while not self._stop:
            if not self._pause:
                try:
                    header, packet = self.cap.next()
                    if header is not None and packet is not None:
                        # Process packet immediately
                        self.packet_callback(header, packet)
                except pcapy.PcapError as e:
                    if "timeout" not in str(e).lower():
                        logger.error(f"Pcap error: {e}")
                except Exception as e:
                    logger.error(f"Error in packet capture: {e}")
            
            # Yield to event loop to keep it responsive
            await asyncio.sleep(0.001)
    
    def pause(self):
        """Pause packet capture without stopping the sniffer."""
        if not self._pause:
            self._pause = True
            logger.info("Packet capture paused")
    
    def resume(self):
        """Resume packet capture after pausing."""
        if self._pause:
            self._pause = False
            logger.info("Packet capture resumed")
    
    def stop(self):
        """Stop the sniffer loop gracefully."""
        self._stop = True
        logger.info("Enhanced sniffer stopping...")
        
        # Save final statistics
        self.print_statistics()
        self.save_statistics()


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(description="Enhanced Asynchronous Packet Sniffer")
    
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Network interface to capture from (default: eth0)")
    
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter expression (e.g., 'tcp port 80')")
    
    parser.add_argument("-p", "--promiscuous", action="store_true",
                        help="Enable promiscuous mode")
    
    parser.add_argument("-s", "--snaplen", type=int, default=65536,
                        help="Snapshot length in bytes (default: 65536)")
    
    parser.add_argument("-t", "--timeout", type=int, default=0,
                        help="Read timeout in milliseconds (default: 0 = no timeout)")
    
    parser.add_argument("--stats-interval", type=int, default=10,
                        help="Statistics printing interval in seconds (default: 10)")
    
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")
    
    parser.add_argument("-o", "--output", default="packet_sniffer.log",
                        help="Log file path (default: packet_sniffer.log)")
    
    return parser.parse_args()


def setup_logging(args):
    """
    Configure logging based on command line arguments.
    
    Args:
        args: Command line arguments
    """
    log_level = logging.DEBUG if args.verbose else logging.INFO
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)
    
    # Create file handler
    file_handler = logging.FileHandler(args.output)
    file_handler.setLevel(log_level)
    file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)


def main():
    """
    Main entry point for the enhanced packet sniffer.
    Parses arguments, sets up the sniffer and runs it until terminated.
    """
    # Parse command line arguments
    args = parse_arguments()
    
    # Configure logging
    setup_logging(args)
    
    logger.info("Starting Enhanced Packet Sniffer...")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"pcapy version: {pcapy.__version__ if hasattr(pcapy, '__version__') else 'Unknown'}")
    
    # Initialize sniffer with parsed arguments
    sniffer = EnhancedSniffer(
        interface=args.interface,
        bpf_filter=args.filter,
        snaplen=args.snaplen,
        promiscuous=args.promiscuous,
        timeout_ms=args.timeout,
        stats_interval=args.stats_interval
    )
    
    # Define signal handlers for graceful termination
    def signal_handler(sig, frame):
        signal_name = signal.Signals(sig).name if hasattr(signal, 'Signals') else str(sig)
        logger.info(f"Signal {signal_name} received, stopping sniffer...")
        sniffer.stop()
        
        # Sleep briefly to allow the stop method to complete
        time.sleep(0.5)
        
        # Exit with success status
        sys.exit(0)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
    
    # On Windows, register SIGBREAK if available
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, signal_handler)  # Ctrl+Break on Windows
    
    # Run the sniffer
    try:
        if sys.platform == 'win32':
            # Windows compatibility fix
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # Use asyncio.run for Python 3.7+
        asyncio.run(sniffer.start())
    except KeyboardInterrupt:
        logger.info("Sniffer interrupted by keyboard.")
        sniffer.stop()
    except Exception as e:
        logger.error(f"Unexpected error during sniffer execution: {e}", exc_info=True)
        sniffer.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()