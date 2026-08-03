package tunnel

import (
	"bufio"
	"context"
	"io"
	"net"
)

// serveSocks5 runs a minimal SOCKS5 proxy (no auth, CONNECT/TCP only). Targets
// are forwarded to the server, which dials them directly (requires the server's
// allow_socks5 to be true).
func (c *Client) serveSocks5(ctx context.Context) {
	ln, err := net.Listen("tcp", c.cfg.Socks5Listen)
	if err != nil {
		c.log.Error("socks5 listen failed", "listen", c.cfg.Socks5Listen, "err", err)
		return
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	c.log.Info("socks5 listening", "listen", c.cfg.Socks5Listen)

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
		go c.handleSocks(ctx, conn)
	}
}

// bufConn overrides Read to drain a bufio.Reader while keeping the underlying
// connection's Write/Close.
type bufConn struct {
	net.Conn
	r io.Reader
}

func (b bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func socksReply(rep byte) []byte {
	// VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
	return []byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0}
}

func (c *Client) handleSocks(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	// Greeting: VER, NMETHODS, METHODS...
	ver, err := br.ReadByte()
	if err != nil || ver != 5 {
		return
	}
	nm, err := br.ReadByte()
	if err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(nm)); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil { // no auth
		return
	}

	// Request: VER, CMD, RSV, ATYP, ADDR, PORT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != 5 || hdr[1] != 1 { // only CONNECT
		_, _ = conn.Write(socksReply(7))
		return
	}

	req := connectReq{Cmd: cmdConnectTCP}
	switch hdr[3] {
	case 1: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		req.Atyp = atypIPv4
		req.Host = net.IP(ip).String()
	case 4: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		req.Atyp = atypIPv6
		req.Host = net.IP(ip).String()
	case 3: // domain
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		d := make([]byte, l)
		if _, err := io.ReadFull(br, d); err != nil {
			return
		}
		req.Atyp = atypDomain
		req.Host = string(d)
	default:
		_, _ = conn.Write(socksReply(8))
		return
	}
	var p [2]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		return
	}
	req.Port = be.Uint16(p[:])

	st, err := c.openStream(ctx, req)
	if err != nil {
		c.log.Warn("socks open stream failed", "target", req.Host, "port", req.Port, "err", err)
		_, _ = conn.Write(socksReply(1))
		return
	}
	if _, err := conn.Write(socksReply(0)); err != nil {
		_ = st.Close()
		return
	}
	pipe(bufConn{Conn: conn, r: br}, st)
}
