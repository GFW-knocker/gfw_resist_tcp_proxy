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
	Interface      string // NIC name; empty = auto-detect toward VPSIP
	SnapLen        int    // capture length; defaults applied if 0
}

// rxPacket is one received carrier payload plus its source peer.
type rxPacket struct {
	data []byte
	addr *Addr
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

	// learnedSrc maps a client addr string -> the reply source IP (the dst IP the
	// client addressed us at). Server auto-derive mode only (VPSIP nil).
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
		// server, no VPSIP and no interface: bind the default-route NIC.
		localIP, err = localIPToward(net.IPv4(192, 0, 2, 1)) // TEST-NET-1: route lookup only, no packet sent
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

// usableSrcIP reports whether ip is a sane reply source address.
func usableSrcIP(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
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
			if !seg.srcIP.Equal(c.opts.VPSIP) || seg.srcPort != c.opts.ServerPort || seg.dstPort != uint16(c.curClientPort.Load()) {
				continue
			}
			addr = c.peer
		} else {
			if seg.dstPort != c.opts.ServerPort {
				continue
			}
			ipCopy := make(net.IP, len(seg.srcIP))
			copy(ipCopy, seg.srcIP)
			addr = &Addr{IP: ipCopy, Port: seg.srcPort}
			// Auto-derive: remember the IP the client addressed us at, to use as the
			// reply source. Stored before the packet reaches the transport, so a
			// later WriteTo always finds it. Skipped when VPSIP overrides.
			if c.opts.VPSIP == nil && usableSrcIP(seg.dstIP) {
				dstCopy := make(net.IP, len(seg.dstIP))
				copy(dstCopy, seg.dstIP)
				c.learnedSrc.Store(addr.String(), dstCopy)
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
		dstIP, dstPort = c.opts.VPSIP, c.opts.ServerPort
	} else {
		ip, port, ok := addrFromNet(addr)
		if !ok {
			return 0, fmt.Errorf("carrier: bad destination addr %v", addr)
		}
		src := c.opts.VPSIP // configured override, if any
		if src == nil {
			if v, found := c.learnedSrc.Load((&Addr{IP: ip, Port: port}).String()); found {
				src = v.(net.IP)
			}
		}
		if src == nil {
			return 0, fmt.Errorf("carrier: no reply source IP for %s yet (no inbound packet seen)", (&Addr{IP: ip, Port: port}).String())
		}
		srcIP, srcPort = src, c.opts.ServerPort
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
