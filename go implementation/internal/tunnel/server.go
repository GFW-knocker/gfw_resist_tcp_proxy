package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
)

// Server accepts transport sessions/streams and relays each to the requested
// target: a fixed backend port (port-forward) or an arbitrary host (SOCKS mode,
// gated by allow_socks5).
type Server struct {
	cfg config.ServerConfig
	psk string
	log *slog.Logger
}

// NewServer builds a server.
func NewServer(cfg config.ServerConfig, psk string, log *slog.Logger) *Server {
	return &Server{cfg: cfg, psk: psk, log: log}
}

// Serve accepts sessions from lis until ctx is cancelled or lis is closed.
func (s *Server) Serve(ctx context.Context, lis transport.Listener) error {
	go func() { <-ctx.Done(); lis.Close() }()
	for {
		sess, err := lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handleSession(ctx, sess)
	}
}

func (s *Server) handleSession(ctx context.Context, sess transport.Session) {
	peer := sess.RemoteAddr()
	s.log.Debug("client session up", "peer", peer)
	var verified atomic.Bool // set once the client passes the authenticated hello
	defer func() {
		_ = sess.Close() // closes all streams; their goroutines and backend conns unwind
		if verified.Load() {
			s.log.Info("client disconnected", "peer", peer)
		} else {
			s.log.Debug("client session down", "peer", peer)
		}
	}()
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go s.handleStream(ctx, st, peer, &verified)
	}
}

func (s *Server) handleStream(ctx context.Context, st transport.Stream, peer net.Addr, verified *atomic.Bool) {
	defer st.Close()
	req, err := readConnectReq(st, s.psk)
	if err != nil {
		if errors.Is(err, errAuth) {
			_ = writeStatus(st, statusAuthFail)
		} else {
			_ = writeStatus(st, statusBadReq)
		}
		return
	}

	// A hello stream is an authenticated connectivity check with no target: ack it
	// and report the now-verified client.
	if req.Cmd == cmdHello {
		if verified.CompareAndSwap(false, true) {
			s.log.Info("new client connected", "peer", peer)
		}
		_ = writeStatus(st, statusOK)
		return
	}

	target, ok := s.resolveTarget(req)
	if !ok {
		s.log.Warn("refused target", "atyp", req.Atyp, "host", req.Host, "port", req.Port)
		_ = writeStatus(st, statusBadReq)
		return
	}

	switch req.Cmd {
	case cmdConnectTCP:
		s.handleTCP(st, target)
	case cmdConnectUDP:
		s.handleUDP(st, target)
	default:
		_ = writeStatus(st, statusBadReq)
	}
}

// resolveTarget maps a request to a "host:port" string, or returns ok=false if
// the request is not permitted.
func (s *Server) resolveTarget(req connectReq) (string, bool) {
	if !s.portAllowed(req.Port) {
		return "", false
	}
	port := strconv.Itoa(int(req.Port))
	if req.Atyp == atypBackendPort {
		return net.JoinHostPort(s.cfg.BackendIP, port), true
	}
	if !s.cfg.AllowSocks5 {
		return "", false
	}
	if req.Host == "" {
		return "", false
	}
	return net.JoinHostPort(req.Host, port), true
}

// portAllowed enforces the optional server-side destination-port allowlist.
// An empty allowlist means no restriction.
func (s *Server) portAllowed(port uint16) bool {
	if len(s.cfg.AllowedPorts) == 0 {
		return true
	}
	for _, p := range s.cfg.AllowedPorts {
		if p == int(port) {
			return true
		}
	}
	return false
}

func (s *Server) handleTCP(st transport.Stream, target string) {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		s.log.Warn("dial tcp failed", "target", target, "err", err)
		_ = writeStatus(st, statusDialFail)
		return
	}
	defer conn.Close()
	if err := writeStatus(st, statusOK); err != nil {
		return
	}
	pipe(st, conn)
}

func (s *Server) handleUDP(st transport.Stream, target string) {
	conn, err := net.DialTimeout("udp", target, 10*time.Second)
	if err != nil {
		s.log.Warn("dial udp failed", "target", target, "err", err)
		_ = writeStatus(st, statusDialFail)
		return
	}
	defer conn.Close()
	if err := writeStatus(st, statusOK); err != nil {
		return
	}

	// stream -> udp backend
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := readDatagram(st, buf)
			if err != nil {
				conn.Close()
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				conn.Close()
				return
			}
		}
	}()

	// udp backend -> stream
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if err := writeDatagram(st, buf[:n]); err != nil {
			return
		}
	}
}
