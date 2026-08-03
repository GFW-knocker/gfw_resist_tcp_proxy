package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
)

// Client exposes local listeners (port-forwards + optional SOCKS5) and relays
// each accepted connection over a transport stream to the server.
type Client struct {
	cfg    config.ClientConfig
	psk    string
	dialer Dialer
	log    *slog.Logger
}

// NewClient builds a client.
func NewClient(cfg config.ClientConfig, psk string, d Dialer, log *slog.Logger) *Client {
	return &Client{cfg: cfg, psk: psk, dialer: d, log: log}
}

// helloTimeout bounds the connectivity-check round-trip when a session is
// established, so a one-way-broken carrier fails fast and the supervisor retries.
const helloTimeout = 8 * time.Second

// Verify confirms a freshly dialed session is actually bidirectional by doing a
// small authenticated hello round-trip. It returns nil only if the server
// answered OK within helloTimeout. This makes "tunnel established" trustworthy
// even for KCP, whose Dial completes locally without any round-trip.
func Verify(sess transport.Session, psk string) error {
	done := make(chan error, 1)
	go func() { done <- hello(sess, psk) }()
	select {
	case err := <-done:
		return err
	case <-time.After(helloTimeout):
		return fmt.Errorf("tunnel verify timed out after %s (no reply from server)", helloTimeout)
	}
}

func hello(sess transport.Session, psk string) error {
	st, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := writeConnectReq(st, psk, connectReq{Cmd: cmdHello}); err != nil {
		return err
	}
	status, err := readStatus(st)
	if err != nil {
		return err
	}
	if status != statusOK {
		return fmt.Errorf("server refused hello (status %d)", status)
	}
	return nil
}

// Run starts all listeners and blocks until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	for _, f := range c.cfg.Forwards {
		f := f
		switch f.Proto {
		case "tcp":
			go c.serveTCPForward(ctx, f)
		case "udp":
			go c.serveUDPForward(ctx, f)
		}
	}
	if c.cfg.Socks5Listen != "" {
		go c.serveSocks5(ctx)
	}
	<-ctx.Done()
	return ctx.Err()
}

// openStream opens a transport stream and completes the connect handshake.
func (c *Client) openStream(ctx context.Context, req connectReq) (transport.Stream, error) {
	sess, err := c.dialer.Session(ctx)
	if err != nil {
		return nil, err
	}
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := writeConnectReq(st, c.psk, req); err != nil {
		_ = st.Close()
		return nil, err
	}
	status, err := readStatus(st)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	if status != statusOK {
		_ = st.Close()
		return nil, fmt.Errorf("server refused connect (status %d)", status)
	}
	return st, nil
}

func (c *Client) serveTCPForward(ctx context.Context, f config.Forward) {
	ln, err := net.Listen("tcp", f.Listen)
	if err != nil {
		c.log.Error("tcp forward listen failed", "listen", f.Listen, "err", err)
		return
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	c.log.Info("tcp forward listening", "listen", f.Listen, "target_port", f.TargetPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go func() {
			defer conn.Close()
			st, err := c.openStream(ctx, connectReq{Cmd: cmdConnectTCP, Atyp: atypBackendPort, Port: f.TargetPort})
			if err != nil {
				c.log.Warn("open stream failed", "err", err)
				return
			}
			pipe(conn, st)
		}()
	}
}

func (c *Client) serveUDPForward(ctx context.Context, f config.Forward) {
	addr, err := net.ResolveUDPAddr("udp", f.Listen)
	if err != nil {
		c.log.Error("udp forward bad listen addr", "listen", f.Listen, "err", err)
		return
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		c.log.Error("udp forward listen failed", "listen", f.Listen, "err", err)
		return
	}
	defer pc.Close()
	go func() { <-ctx.Done(); pc.Close() }()
	c.log.Info("udp forward listening", "listen", f.Listen, "target_port", f.TargetPort)

	m := &udpForward{
		client: c,
		ctx:    ctx,
		pc:     pc,
		target: f.TargetPort,
		flows:  make(map[string]*udpFlow),
	}
	m.run()
}

// udpForward multiplexes local UDP senders onto per-source transport streams.
type udpForward struct {
	client *Client
	ctx    context.Context
	pc     *net.UDPConn
	target uint16
	mu     sync.Mutex
	flows  map[string]*udpFlow
}

type udpFlow struct {
	st   transport.Stream
	dst  *net.UDPAddr
	last time.Time
}

func (m *udpForward) run() {
	buf := make([]byte, 65535)
	for {
		n, src, err := m.pc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-m.ctx.Done():
				return
			default:
				return
			}
		}
		fl := m.getFlow(src)
		if fl == nil {
			continue
		}
		if err := writeDatagram(fl.st, buf[:n]); err != nil {
			m.dropFlow(src.String())
		}
	}
}

func (m *udpForward) getFlow(src *net.UDPAddr) *udpFlow {
	key := src.String()
	m.mu.Lock()
	defer m.mu.Unlock()
	if fl, ok := m.flows[key]; ok {
		fl.last = time.Now()
		return fl
	}
	st, err := m.client.openStream(m.ctx, connectReq{Cmd: cmdConnectUDP, Atyp: atypBackendPort, Port: m.target})
	if err != nil {
		m.client.log.Warn("udp open stream failed", "err", err)
		return nil
	}
	fl := &udpFlow{st: st, dst: src, last: time.Now()}
	m.flows[key] = fl
	go m.readBack(key, fl)
	return fl
}

func (m *udpForward) readBack(key string, fl *udpFlow) {
	buf := make([]byte, 65535)
	for {
		n, err := readDatagram(fl.st, buf)
		if err != nil {
			m.dropFlow(key)
			return
		}
		if _, err := m.pc.WriteToUDP(buf[:n], fl.dst); err != nil {
			m.dropFlow(key)
			return
		}
	}
}

func (m *udpForward) dropFlow(key string) {
	m.mu.Lock()
	if fl, ok := m.flows[key]; ok {
		_ = fl.st.Close()
		delete(m.flows, key)
	}
	m.mu.Unlock()
}
