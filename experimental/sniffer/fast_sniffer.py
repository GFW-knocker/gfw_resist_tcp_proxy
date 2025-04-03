"""
A faster asynchronous packet sniffer using pcapy.
This implementation is intended as an alternative to Scapy's AsyncSniffer.
"""

import asyncio
import pcapy
import struct
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FastSniffer")

def packet_handler(hdr, data):
    # This function processes raw packet data.
    # For example, we extract the Ethernet header (first 14 bytes)
    eth_header = data[:14]
    eth = struct.unpack("!6s6sH", eth_header)
    eth_protocol = eth[2]
    # Filter only IP packets (0x0800)
    if eth_protocol == 0x0800:
        logger.info("IP packet captured")
    # You can add further parsing here.

async def async_sniffer(loop, interface="eth0", bpf_filter="tcp"):
    # Open live capture on the specified interface
    cap = pcapy.open_live(interface, 65536, 1, 0)
    cap.setfilter(bpf_filter)
    logger.info(f"Fast sniffer started on interface {interface} with filter '{bpf_filter}'")
    while True:
        try:
            header, packet = cap.next()
            if header is not None and packet is not None:
                packet_handler(header, packet)
        except Exception as e:
            logger.error(f"Error in sniffer: {e}")
        await asyncio.sleep(0.001)  # Tiny sleep to yield control to event loop

def main():
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(async_sniffer(loop))
    except KeyboardInterrupt:
        logger.info("Sniffer stopped by user.")

if __name__ == "__main__":
    main()