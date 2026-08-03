// Package transport is the pluggable reliability+multiplexing layer that runs
// on top of the carrier's net.PacketConn. Two implementations are provided:
// KCP+smux (default; aggressive ARQ + FEC, best on lossy links) and QUIC.
// Both expose the same Session/Listener abstraction of multiplexed streams.
package transport

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
)

// Stream is one multiplexed bidirectional stream.
type Stream = io.ReadWriteCloser

// Session is a multiplexed connection to a single peer.
type Session interface {
	// OpenStream opens a new outbound stream.
	OpenStream() (Stream, error)
	// AcceptStream blocks for the next inbound stream.
	AcceptStream() (Stream, error)
	// RemoteAddr is the peer's carrier address.
	RemoteAddr() net.Addr
	// IsClosed reports whether the session is dead.
	IsClosed() bool
	// Close tears the session down.
	Close() error
}

// Listener accepts inbound sessions (one per client) over a PacketConn.
type Listener interface {
	// Accept blocks for the next client session.
	Accept() (Session, error)
	// Close stops accepting.
	Close() error
}

// Params configures the transport.
type Params struct {
	Transport        config.Transport
	Key              string
	MTU              int
	KeepAliveSeconds int // smux/QUIC heartbeat period; keeps the NAT pinhole warm
	KCP              config.KCPConfig
	QUIC             config.QUICConfig
}

// Dial establishes a client session to remote over pc.
func Dial(ctx context.Context, pc net.PacketConn, remote net.Addr, p Params) (Session, error) {
	switch p.Transport {
	case config.TransportKCP:
		return dialKCP(pc, remote, p)
	case config.TransportQUIC:
		return dialQUIC(ctx, pc, remote, p)
	default:
		return nil, fmt.Errorf("transport: unknown transport %q", p.Transport)
	}
}

// Listen accepts client sessions over pc.
func Listen(pc net.PacketConn, p Params) (Listener, error) {
	switch p.Transport {
	case config.TransportKCP:
		return listenKCP(pc, p)
	case config.TransportQUIC:
		return listenQUIC(pc, p)
	default:
		return nil, fmt.Errorf("transport: unknown transport %q", p.Transport)
	}
}

// deriveKey stretches the pre-shared key to 32 bytes for AES-256.
func deriveKey(key string) []byte {
	sum := sha256.Sum256([]byte("gfk-carrier-v1:" + key))
	return sum[:]
}
