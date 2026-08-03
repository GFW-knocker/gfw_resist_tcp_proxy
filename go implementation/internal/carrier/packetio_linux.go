//go:build linux

package carrier

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// linuxIO is a cgo-free packet backend:
//   - inject via AF_INET/SOCK_RAW with IP_HDRINCL (kernel routes/ARPs for us)
//   - capture via AF_PACKET/SOCK_DGRAM (link-layer agnostic: works on Ethernet
//     and header-less venet/OpenVZ interfaces alike)
//
// Exact host/port/flag matching is done in the Carrier receive loop, so no
// classic-BPF assembly is needed here; we only drop locally-originated frames.
type linuxIO struct {
	sendFD int
	recvFD int
	buf    []byte
}

func htons16(v uint16) uint16 { return (v << 8) | (v >> 8) }

func newPacketIO(p ioParams) (packetIO, error) {
	iface, err := findInterface(p.ifaceName, p.localIP)
	if err != nil {
		return nil, err
	}

	sendFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("carrier: open raw send socket (need root): %w", err)
	}
	if err := unix.SetsockoptInt(sendFD, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(sendFD)
		return nil, fmt.Errorf("carrier: set IP_HDRINCL: %w", err)
	}

	recvFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons16(unix.ETH_P_IP)))
	if err != nil {
		unix.Close(sendFD)
		return nil, fmt.Errorf("carrier: open packet recv socket (need root): %w", err)
	}
	if err := unix.Bind(recvFD, &unix.SockaddrLinklayer{
		Protocol: htons16(unix.ETH_P_IP),
		Ifindex:  iface.Index,
	}); err != nil {
		unix.Close(sendFD)
		unix.Close(recvFD)
		return nil, fmt.Errorf("carrier: bind packet socket to %s: %w", iface.Name, err)
	}

	return &linuxIO{
		sendFD: sendFD,
		recvFD: recvFD,
		buf:    make([]byte, p.snapLen),
	}, nil
}

func (l *linuxIO) Inject(ipPacket []byte) error {
	if len(ipPacket) < 20 {
		return fmt.Errorf("carrier: short IP packet")
	}
	var dst [4]byte
	copy(dst[:], ipPacket[16:20]) // IPv4 destination address
	return unix.Sendto(l.sendFD, ipPacket, 0, &unix.SockaddrInet4{Addr: dst})
}

func (l *linuxIO) Capture() ([]byte, error) {
	for {
		n, from, err := unix.Recvfrom(l.recvFD, l.buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, err
		}
		// Ignore packets we ourselves transmitted on this interface.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		return l.buf[:n], nil
	}
}

func (l *linuxIO) Close() error {
	unix.Close(l.sendFD)
	unix.Close(l.recvFD)
	return nil
}
