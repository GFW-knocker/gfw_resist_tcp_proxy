package carrier

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Role selects client (single fixed peer) or server (many peers) behaviour.
type Role int

const (
	RoleClient Role = iota
	RoleServer
)

// Options configures a Carrier.
type Options struct {
	Role       Role
	VPSIP      net.IP // client: server's filtered public IP (required); server: optional reply source, auto-derived per client if nil
	ServerPort uint16 // carrier TCP port the server "listens" on
	ClientPort uint16 // carrier TCP source port the client uses (base of the rotation range)
	// ClientPortSpan is how many source ports the client rotates through on
	// reconnect, starting at ClientPort. 1 (or 0) disables rotation.
	ClientPortSpan int
	// ServerPortSpan is how many carrier ports the server accepts (starting at
	// ServerPort) and the client rotates the destination across on reconnect, to
	// escape a middlebox blocking one port. Must match on both ends. 1 disables.
	ServerPortSpan int
	Interface      string // NIC name; empty = auto-detect toward VPSIP
	SnapLen        int    // capture length; defaults applied if 0
}

// rxPacket is one received carrier payload plus its source peer.
type rxPacket struct {
	data []byte
	addr *Addr
}

// replySrc is the (IP, port) the server crafts replies from for a given client:
// the exact destination that client addressed it at. Learned per client so the
// client's ingress filter matches and a server port span works.
type replySrc struct {
	ip   net.IP
	port uint16
}

// Carrier is a net.PacketConn over the fake-TCP link.
type Carrier struct {
	opts    Options
	pio     packetIO
	localIP net.IP
	peer    *Addr // client mode: the single server peer

	// curClientPort is the client's current carrier source port, rotated across
	// [ClientPort, ClientPort+ClientPortSpan) on reconnect to dodge a KCP session
	// collision with the server's not-yet-expired old session.
	curClientPort atomic.Uint32
	// curServerPort is the server port the client currently targets, rotated
	// across [ServerPort, ServerPort+ServerPortSpan) on reconnect to escape a
	// middlebox that has started dropping a specific port.
	curServerPort atomic.Uint32

	// learnedSrc maps a client addr string -> replySrc (the exact IP+port the
	// client addressed us at), so the server replies from that address.
	learnedSrc sync.Map

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	rx        chan rxPacket
	closed    chan struct{}
	closeOnce sync.Once

	rdMu         sync.Mutex
	readDeadline time.Time
}

// packetIO is the platform-specific raw capture/inject backend.
type packetIO interface {
	// Inject sends one fully-formed IPv4 packet (IP header first).
	Inject(ipPacket []byte) error
	// Capture returns the next captured IPv4 packet (IP header first). The
	// returned slice is only valid until the next Capture call.
	Capture() ([]byte, error)
	Close() error
}

// Open constructs a Carrier, brings up the packet backend, and starts the
// receive loop.
func Open(opts Options) (*Carrier, error) {
	if opts.SnapLen == 0 {
		opts.SnapLen = 2048
	}
	if opts.Role == RoleClient && opts.VPSIP == nil {
		return nil, fmt.Errorf("carrier: VPSIP is required for client role")
	}

	// localIP selects the NIC to bind capture/inject to; on the client it is also
	// the crafted source IP. On the server the reply source is VPSIP (override) or
	// auto-derived per client, so localIP here only steers interface selection.
	var localIP net.IP
	var err error
	switch {
	case opts.Role == RoleClient:
		localIP, err = localIPToward(opts.VPSIP)
		if err != nil {
			return nil, fmt.Errorf("carrier: resolve local IP toward %s: %w", opts.VPSIP, err)
		}
	case opts.VPSIP != nil:
		localIP = opts.VPSIP // server, explicit source IP: its NIC owns it
	case opts.Interface != "":
		localIP = nil // server: NIC chosen by name; source IP derived per client
	default:
		// server, no VPSIP and no interface: find the primary egress NIC. Try the
		// default-route source first — connect() to a globally-routable address
		// resolves via the default gateway and sends NO packet, so we just read
		// back the source IP the kernel would use. (A bogon/reserved probe like
		// TEST-NET can fail next-hop resolution on some hosts, e.g. OVH.) If even
		// that fails, fall back to the first up, non-loopback IPv4 interface.
		localIP, err = localIPToward(net.IPv4(8, 8, 8, 8))
		if err != nil || localIP == nil {
			localIP, err = firstGlobalUnicastIPv4()
		}
		if err != nil {
			return nil, fmt.Errorf("carrier: auto-detect default interface (set carrier.interface): %w", err)
		}
	}

	pio, err := newPacketIO(ioParams{
		role:       opts.Role,
		ifaceName:  opts.Interface,
		localIP:    localIP,
		vpsIP:      opts.VPSIP,
		serverPort: opts.ServerPort,
		clientPort: opts.ClientPort,
		snapLen:    opts.SnapLen,
	})
	if err != nil {
		return nil, err
	}

	c := &Carrier{
		opts:    opts,
		pio:     pio,
		localIP: localIP,
		rx:      make(chan rxPacket, 1024),
		closed:  make(chan struct{}),
	}
	c.curClientPort.Store(uint32(opts.ClientPort))
	c.curServerPort.Store(uint32(opts.ServerPort))
	if opts.Role == RoleClient {
		c.peer = &Addr{IP: opts.VPSIP, Port: opts.ServerPort}
	}
	go c.recvLoop()
	return c, nil
}

// LocalIP reports the source IP used for crafted packets.
func (c *Carrier) LocalIP() net.IP { return c.localIP }

// RotateClientPort advances the client's carrier source port within its span so
// the next reconnect looks like a fresh flow to the server, avoiding a stall
// while the server's previous session for the old port times out. No-op on the
// server or when span<=1. Returns the new port. Only the reconnect loop calls
// this (single writer); recvLoop/WriteTo read the value atomically.
func (c *Carrier) RotateClientPort() uint16 {
	if c.opts.Role != RoleClient || c.opts.ClientPortSpan <= 1 {
		return uint16(c.curClientPort.Load())
	}
	base := uint32(c.opts.ClientPort)
	next := base + (c.curClientPort.Load()-base+1)%uint32(c.opts.ClientPortSpan)
	c.curClientPort.Store(next)
	return uint16(next)
}

// RotateServerPort advances the server port the client targets within its span,
// so a reconnect tries a different carrier port — escaping a middlebox that has
// started dropping the current one. The server accepts the whole span, so no
// coordination is needed. No-op on the server or when span<=1.
func (c *Carrier) RotateServerPort() uint16 {
	if c.opts.Role != RoleClient || c.opts.ServerPortSpan <= 1 {
		return uint16(c.curServerPort.Load())
	}
	base := uint32(c.opts.ServerPort)
	next := base + (c.curServerPort.Load()-base+1)%uint32(c.opts.ServerPortSpan)
	c.curServerPort.Store(next)
	return uint16(next)
}

// usableSrcIP reports whether ip is a sane reply source address.
func usableSrcIP(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
}

// firstGlobalUnicastIPv4 returns the IPv4 of the first up, non-loopback
// interface — a dial-free fallback for egress-NIC detection when a route lookup
// is unavailable (e.g. no route to the probe address on the VPS).
func firstGlobalUnicastIPv4() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && ip.IsGlobalUnicast() {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no up, non-loopback IPv4 interface found")
}

func (c *Carrier) recvLoop() {
	for {
		raw, err := c.pio.Capture()
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
				// Transient capture error; keep going.
				continue
			}
		}
		seg, ok := parseIPv4(raw)
		if !ok || seg.synOnly || len(seg.payload) == 0 {
			continue
		}

		var addr *Addr
		if c.opts.Role == RoleClient {
			if !seg.srcIP.Equal(c.opts.VPSIP) || seg.srcPort != uint16(c.curServerPort.Load()) || seg.dstPort != uint16(c.curClientPort.Load()) {
				continue
			}
			addr = c.peer
		} else {
			// Accept any dst port in the server span; the client rotates within it.
			span := c.opts.ServerPortSpan
			if span < 1 {
				span = 1
			}
			if int(seg.dstPort) < int(c.opts.ServerPort) || int(seg.dstPort) >= int(c.opts.ServerPort)+span {
				continue
			}
			ipCopy := make(net.IP, len(seg.srcIP))
			copy(ipCopy, seg.srcIP)
			addr = &Addr{IP: ipCopy, Port: seg.srcPort}
			// Remember the exact address the client reached us at (IP + port) so we
			// reply from it. Stored before the packet reaches the transport, so a
			// later WriteTo always finds it. The port makes the server span work;
			// the IP is used as the reply source unless VPSIP overrides it.
			if usableSrcIP(seg.dstIP) {
				dstCopy := make(net.IP, len(seg.dstIP))
				copy(dstCopy, seg.dstIP)
				c.learnedSrc.Store(addr.String(), replySrc{ip: dstCopy, port: seg.dstPort})
			}
		}

		payload := make([]byte, len(seg.payload))
		copy(payload, seg.payload)
		c.bytesIn.Add(uint64(len(payload)))

		select {
		case c.rx <- rxPacket{data: payload, addr: addr}:
		case <-c.closed:
			return
		}
	}
}

// ReadFrom implements net.PacketConn.
func (c *Carrier) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rdMu.Lock()
	dl := c.readDeadline
	c.rdMu.Unlock()

	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, timeoutError{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case pk := <-c.rx:
		n := copy(p, pk.data)
		return n, pk.addr, nil
	case <-timeout:
		return 0, nil, timeoutError{}
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo implements net.PacketConn.
func (c *Carrier) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	if c.opts.Role == RoleClient {
		srcIP, srcPort = c.localIP, uint16(c.curClientPort.Load())
		dstIP, dstPort = c.opts.VPSIP, uint16(c.curServerPort.Load())
	} else {
		ip, port, ok := addrFromNet(addr)
		if !ok {
			return 0, fmt.Errorf("carrier: bad destination addr %v", addr)
		}
		key := (&Addr{IP: ip, Port: port}).String()
		replyIP := c.opts.VPSIP        // IP override, if configured
		replyPort := c.opts.ServerPort // fallback until we've learned the client's port
		if v, found := c.learnedSrc.Load(key); found {
			ls := v.(replySrc)
			if replyIP == nil {
				replyIP = ls.ip
			}
			replyPort = ls.port // reply from the exact port the client used (server span)
		}
		if replyIP == nil {
			return 0, fmt.Errorf("carrier: no reply source for %s yet (no inbound packet seen)", key)
		}
		srcIP, srcPort = replyIP, replyPort
		dstIP, dstPort = ip, port
	}

	ipPkt, err := craftSegment(srcIP, dstIP, srcPort, dstPort, carrierSeq, carrierAck, p)
	if err != nil {
		return 0, err
	}
	if err := c.pio.Inject(ipPkt); err != nil {
		return 0, err
	}
	c.bytesOut.Add(uint64(len(p)))
	return len(p), nil
}

// Stats returns cumulative carrier bytes received and sent.
func (c *Carrier) Stats() (in, out uint64) {
	return c.bytesIn.Load(), c.bytesOut.Load()
}

// LocalAddr implements net.PacketConn.
func (c *Carrier) LocalAddr() net.Addr {
	if c.opts.Role == RoleClient {
		return &Addr{IP: c.localIP, Port: uint16(c.curClientPort.Load())}
	}
	ip := c.opts.VPSIP
	if ip == nil {
		ip = net.IPv4zero
	}
	return &Addr{IP: ip, Port: c.opts.ServerPort}
}

// SetDeadline implements net.PacketConn.
func (c *Carrier) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (c *Carrier) SetReadDeadline(t time.Time) error {
	c.rdMu.Lock()
	c.readDeadline = t
	c.rdMu.Unlock()
	return nil
}

// SetWriteDeadline implements net.PacketConn. Writes never block, so this is a
// no-op that only reports closure.
func (c *Carrier) SetWriteDeadline(time.Time) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
		return nil
	}
}

// Close implements net.PacketConn.
func (c *Carrier) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		err = c.pio.Close()
	})
	return err
}

// timeoutError satisfies net.Error with Timeout()==true so KCP/QUIC treat
// ReadFrom deadline expiries correctly.
type timeoutError struct{}

func (timeoutError) Error() string   { return "carrier: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
