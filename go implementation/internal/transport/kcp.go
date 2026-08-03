package transport

import (
	"net"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// kcpSession wraps a smux session running over one KCP flow.
type kcpSession struct {
	sess   *smux.Session
	raw    net.Conn
	remote net.Addr
}

func (s *kcpSession) OpenStream() (Stream, error) {
	st, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *kcpSession) AcceptStream() (Stream, error) {
	st, err := s.sess.AcceptStream()
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *kcpSession) RemoteAddr() net.Addr { return s.remote }
func (s *kcpSession) IsClosed() bool        { return s.sess.IsClosed() }

func (s *kcpSession) Close() error {
	err := s.sess.Close()
	_ = s.raw.Close()
	return err
}

// kcpListener accepts KCP flows and wraps each in a smux server session.
type kcpListener struct {
	lis *kcp.Listener
	p   Params
}

func (l *kcpListener) Accept() (Session, error) {
	conn, err := l.lis.AcceptKCP()
	if err != nil {
		return nil, err
	}
	tuneKCP(conn, l.p)
	sess, err := smux.Server(conn, smuxConfig(l.p))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &kcpSession{sess: sess, raw: conn, remote: conn.RemoteAddr()}, nil
}

func (l *kcpListener) Close() error { return l.lis.Close() }

func dialKCP(pc net.PacketConn, remote net.Addr, p Params) (Session, error) {
	block, err := kcp.NewAESBlockCrypt(deriveKey(p.Key))
	if err != nil {
		return nil, err
	}
	conn, err := kcp.NewConn2(remote, block, p.KCP.FECData, p.KCP.FECParity, pc)
	if err != nil {
		return nil, err
	}
	tuneKCP(conn, p)
	sess, err := smux.Client(conn, smuxConfig(p))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &kcpSession{sess: sess, raw: conn, remote: remote}, nil
}

func listenKCP(pc net.PacketConn, p Params) (Listener, error) {
	block, err := kcp.NewAESBlockCrypt(deriveKey(p.Key))
	if err != nil {
		return nil, err
	}
	lis, err := kcp.ServeConn(block, p.KCP.FECData, p.KCP.FECParity, pc)
	if err != nil {
		return nil, err
	}
	return &kcpListener{lis: lis, p: p}, nil
}

func tuneKCP(conn *kcp.UDPSession, p Params) {
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(p.KCP.NoDelay, p.KCP.Interval, p.KCP.Resend, p.KCP.NC)
	conn.SetWindowSize(p.KCP.SndWnd, p.KCP.RcvWnd)
	conn.SetMtu(p.MTU)
	conn.SetACKNoDelay(true)
}

func smuxConfig(p Params) *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	interval := p.KeepAliveSeconds
	if interval <= 0 {
		interval = 4
	}
	// Dead-peer detection ~= KeepAliveTimeout. interval*2 gives ~8s at the default
	// 4s heartbeat, so both ends notice a drop quickly instead of after ~24s.
	c.KeepAliveInterval = time.Duration(interval) * time.Second
	c.KeepAliveTimeout = time.Duration(interval*2) * time.Second
	// Flow-control windows (bytes). smux's 64KB per-stream default throttles a
	// single download to ~buffer/RTT (~1.7 Mbps at 300ms RTT). We instead size the
	// smux window from the KCP window: big enough to fill the pipe, but not so big
	// that the sender can queue far beyond the KCP window and cause bufferbloat.
	// Outstanding data is bounded by the smux window, so keeping it ≈ 2× the KCP
	// window (≈2× BDP) fills the link without the multi-second queues a fixed 4 MB
	// buffer caused on slow links.
	stream := p.KCP.StreamBuffer
	if stream <= 0 {
		win := p.KCP.RcvWnd
		if p.KCP.SndWnd > win {
			win = p.KCP.SndWnd
		}
		if win <= 0 {
			win = 128
		}
		mtu := p.MTU
		if mtu <= 0 {
			mtu = 1400
		}
		stream = win * mtu * 2
		if stream < 64<<10 { // smux needs at least a couple of frames
			stream = 64 << 10
		}
	}
	session := p.KCP.SessionBuffer
	if session <= 0 {
		session = stream * 4 // headroom for a few concurrent streams
	}
	if session < stream {
		session = stream
	}
	c.MaxStreamBuffer = stream
	c.MaxReceiveBuffer = session
	return c
}
