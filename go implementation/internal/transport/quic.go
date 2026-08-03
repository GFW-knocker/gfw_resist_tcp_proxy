package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const quicALPN = "gfk"

// quicSession adapts a QUIC connection to the transport.Session interface.
type quicSession struct {
	conn *quic.Conn
}

func (s *quicSession) OpenStream() (Stream, error) {
	st, err := s.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *quicSession) AcceptStream() (Stream, error) {
	st, err := s.conn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *quicSession) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

func (s *quicSession) IsClosed() bool { return s.conn.Context().Err() != nil }

func (s *quicSession) Close() error { return s.conn.CloseWithError(0, "bye") }

// quicListener accepts QUIC connections.
type quicListener struct {
	lis *quic.Listener
}

func (l *quicListener) Accept() (Session, error) {
	conn, err := l.lis.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	return &quicSession{conn: conn}, nil
}

func (l *quicListener) Close() error { return l.lis.Close() }

func dialQUIC(ctx context.Context, pc net.PacketConn, remote net.Addr, p Params) (Session, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{quicALPN},
	}
	conn, err := quic.Dial(ctx, pc, remote, tlsConf, quicConfig(p))
	if err != nil {
		return nil, err
	}
	return &quicSession{conn: conn}, nil
}

func listenQUIC(pc net.PacketConn, p Params) (Listener, error) {
	tlsConf, err := selfSignedTLS()
	if err != nil {
		return nil, err
	}
	lis, err := quic.Listen(pc, tlsConf, quicConfig(p))
	if err != nil {
		return nil, err
	}
	return &quicListener{lis: lis}, nil
}

func quicConfig(p Params) *quic.Config {
	c := &quic.Config{
		DisablePathMTUDiscovery: true,
		EnableDatagrams:         false,
	}
	if p.MTU >= 1200 {
		c.InitialPacketSize = uint16(p.MTU)
	}
	// Default keepalive/idle from the shared heartbeat so QUIC also detects a
	// dead peer in ~2×heartbeat (~8s), not after a long idle timeout.
	ka := p.KeepAliveSeconds
	if ka <= 0 {
		ka = 4
	}
	c.KeepAlivePeriod = time.Duration(ka) * time.Second
	c.MaxIdleTimeout = time.Duration(ka*2) * time.Second
	if p.QUIC.KeepAlivePeriod > 0 {
		c.KeepAlivePeriod = time.Duration(p.QUIC.KeepAlivePeriod) * time.Second
	}
	if p.QUIC.MaxIdleTimeout > 0 {
		c.MaxIdleTimeout = time.Duration(p.QUIC.MaxIdleTimeout) * time.Second
	}
	return c
}

// selfSignedTLS builds an in-memory self-signed certificate. The inner traffic
// is already end-to-end encrypted and streams are authenticated with the PSK,
// so QUIC's TLS here provides transport encryption, not peer identity.
func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gfk"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
	}, nil
}
