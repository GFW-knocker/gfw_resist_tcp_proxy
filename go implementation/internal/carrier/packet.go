// Package carrier implements the "TCP violation" transport: a connectionless
// bidirectional datagram pipe built by crafting and sniffing TCP ACK+PSH
// packets that carry arbitrary payloads, with no SYN handshake. It is exposed
// as a net.PacketConn so reliability layers (KCP, QUIC) can run on top of it.
//
// The GFW enforces its IP blocklist only on TCP SYN packets; by never sending
// a SYN and only emitting mid-stream-looking ACK+PSH segments, traffic to and
// from a blocked VPS IP passes uninspected.
package carrier

import (
	"net"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Addr is a carrier peer address (the other end of the fake-TCP link).
// It implements net.Addr so KCP/QUIC can key sessions on it.
type Addr struct {
	IP   net.IP
	Port uint16
}

// Network returns the pseudo-network name.
func (a *Addr) Network() string { return "gfk" }

// String returns "ip:port".
func (a *Addr) String() string {
	return net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port)))
}

// addrFromNet coerces any net.Addr (our *Addr, or a *net.UDPAddr handed to us
// by kcp-go's string-resolving constructors) into IP+port.
func addrFromNet(a net.Addr) (net.IP, uint16, bool) {
	switch v := a.(type) {
	case *Addr:
		return v.IP, v.Port, true
	case *net.UDPAddr:
		return v.IP, uint16(v.Port), true
	case *net.TCPAddr:
		return v.IP, uint16(v.Port), true
	default:
		if host, port, err := net.SplitHostPort(a.String()); err == nil {
			ip := net.ParseIP(host)
			p, perr := strconv.Atoi(port)
			if ip != nil && perr == nil {
				return ip, uint16(p), true
			}
		}
	}
	return nil, 0, false
}

// Our receiver matches carrier packets by port and reads the payload; it never
// inspects TCP seq/ack. We therefore keep seq and ack CONSTANT and low, so that
// stateful conntrack/NAT on the path (home router, ISP) always sees in-window
// packets. A climbing seq would eventually exceed the peer's ~64 KB window (the
// ack never advances, since there is no real handshake), and the middlebox would
// start dropping that direction — observed as the return path dying at ~24s.
const (
	carrierSeq = 1
	carrierAck = 1
)

// craftSegment serializes a full IPv4 packet carrying a TCP ACK(+PSH) segment
// with the given payload. It returns the raw IP bytes (no Ethernet header).
func craftSegment(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, payload []byte) ([]byte, error) {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP.To4(),
		DstIP:    dstIP.To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		ACK:     true,
		PSH:     len(payload) > 0,
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// segment is a parsed inbound carrier packet.
type segment struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	synOnly bool // true if SYN set (we ignore these — they are not carrier data)
	payload []byte
}

// parseIPv4 parses raw IPv4 bytes into a TCP segment. ok is false if the packet
// is not IPv4+TCP or has no payload we care about.
func parseIPv4(data []byte) (segment, bool) {
	var seg segment
	pkt := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ipl := pkt.Layer(layers.LayerTypeIPv4)
	if ipl == nil {
		return seg, false
	}
	ip, _ := ipl.(*layers.IPv4)
	tcl := pkt.Layer(layers.LayerTypeTCP)
	if tcl == nil {
		return seg, false
	}
	tcp, _ := tcl.(*layers.TCP)
	seg.srcIP = ip.SrcIP
	seg.dstIP = ip.DstIP
	seg.srcPort = uint16(tcp.SrcPort)
	seg.dstPort = uint16(tcp.DstPort)
	seg.synOnly = tcp.SYN
	seg.payload = tcp.Payload
	return seg, true
}

// localIPToward returns the source IP the OS would use to reach dst. The UDP
// "dial" only connect()s (a route lookup) and sends nothing, so it is cheap and
// side-effect-free. The destination port is arbitrary — 53 by convention, since
// no packet is ever emitted to it; the kernel picks the local source port.
func localIPToward(dst net.IP) (net.IP, error) {
	c, err := net.Dial("udp", net.JoinHostPort(dst.String(), "53"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP, nil
}
