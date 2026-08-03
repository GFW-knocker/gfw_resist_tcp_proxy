package carrier

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeIO is an in-memory packetIO: Capture yields queued inbound packets,
// Inject records outbound ones. Capture unblocks when Close is called.
type fakeIO struct {
	inbound chan []byte
	sent    chan []byte
	stop    chan struct{}
}

func newFakeIO() *fakeIO {
	return &fakeIO{
		inbound: make(chan []byte, 8),
		sent:    make(chan []byte, 8),
		stop:    make(chan struct{}),
	}
}

func (f *fakeIO) Inject(p []byte) error {
	cp := append([]byte(nil), p...)
	f.sent <- cp
	return nil
}

func (f *fakeIO) Capture() ([]byte, error) {
	select {
	case b := <-f.inbound:
		return b, nil
	case <-f.stop:
		return nil, net.ErrClosed
	}
}

func (f *fakeIO) Close() error {
	close(f.stop)
	return nil
}

// newTestServer builds a server Carrier around a fake backend, bypassing the
// real socket/interface setup in Open.
func newTestServer(vpsIP net.IP, pio packetIO) *Carrier {
	c := &Carrier{
		opts:   Options{Role: RoleServer, VPSIP: vpsIP, ServerPort: 45000, ClientPort: 40000},
		pio:    pio,
		rx:     make(chan rxPacket, 16),
		closed: make(chan struct{}),
	}
	go c.recvLoop()
	return c
}

// feedInbound injects a client->server carrier packet and returns the peer addr
// the transport would see from ReadFrom.
func feedInbound(t *testing.T, c *Carrier, f *fakeIO, clientIP, addressedIP net.IP, payload string) net.Addr {
	t.Helper()
	pkt, err := craftSegment(clientIP, addressedIP, 40000, 45000, 1, 1, []byte(payload))
	if err != nil {
		t.Fatalf("craftSegment: %v", err)
	}
	f.inbound <- pkt

	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("payload = %q, want %q", buf[:n], payload)
	}
	return addr
}

// TestServerAutoDerivesReplySource: with no VPSIP, the server must reply from
// the exact IP the client addressed it at (learned from the inbound packet).
func TestServerAutoDerivesReplySource(t *testing.T) {
	f := newFakeIO()
	c := newTestServer(nil, f) // auto-derive mode
	defer c.Close()

	client := net.IPv4(198, 51, 100, 7)
	addressed := net.IPv4(203, 0, 113, 9) // e.g. a private/DNAT'd IP in real life
	addr := feedInbound(t, c, f, client, addressed, "hello")

	if _, err := c.WriteTo([]byte("reply"), addr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	seg, ok := parseIPv4(<-f.sent)
	if !ok {
		t.Fatal("could not parse injected reply")
	}
	if !seg.srcIP.Equal(addressed) {
		t.Errorf("reply srcIP = %v, want auto-derived %v", seg.srcIP, addressed)
	}
	if !seg.dstIP.Equal(client) {
		t.Errorf("reply dstIP = %v, want %v", seg.dstIP, client)
	}
	if seg.srcPort != 45000 || seg.dstPort != 40000 {
		t.Errorf("reply ports = %d->%d, want 45000->40000", seg.srcPort, seg.dstPort)
	}
}

// TestCarrierConstantSeq: crafted packets must keep a constant, low TCP seq
// regardless of payload size, so stateful NAT/conntrack never window-drops the
// flow (the ~24s return-path death seen in the field).
func TestCarrierConstantSeq(t *testing.T) {
	f := newFakeIO()
	c := newTestServer(nil, f)
	defer c.Close()

	addr := feedInbound(t, c, f, net.IPv4(198, 51, 100, 7), net.IPv4(203, 0, 113, 9), "x")

	seqOf := func(ipPkt []byte) uint32 {
		ihl := int(ipPkt[0]&0x0f) * 4
		return binary.BigEndian.Uint32(ipPkt[ihl+4 : ihl+8])
	}
	if _, err := c.WriteTo([]byte("aaaa"), addr); err != nil {
		t.Fatal(err)
	}
	s1 := seqOf(<-f.sent)
	if _, err := c.WriteTo([]byte("bbbbbbbbbbbbbbbb"), addr); err != nil {
		t.Fatal(err)
	}
	s2 := seqOf(<-f.sent)
	if s1 != carrierSeq || s2 != carrierSeq {
		t.Fatalf("seq should stay constant %d, got %d then %d", carrierSeq, s1, s2)
	}
}

// TestServerExplicitVPSIPOverrides: when VPSIP is set, replies use it regardless
// of what the client addressed.
func TestServerExplicitVPSIPOverrides(t *testing.T) {
	f := newFakeIO()
	override := net.IPv4(203, 0, 113, 10)
	c := newTestServer(override, f)
	defer c.Close()

	client := net.IPv4(198, 51, 100, 7)
	addressed := net.IPv4(10, 0, 0, 5) // different from override
	addr := feedInbound(t, c, f, client, addressed, "hi")

	if _, err := c.WriteTo([]byte("reply"), addr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	seg, ok := parseIPv4(<-f.sent)
	if !ok {
		t.Fatal("could not parse injected reply")
	}
	if !seg.srcIP.Equal(override) {
		t.Errorf("reply srcIP = %v, want override %v", seg.srcIP, override)
	}
}
