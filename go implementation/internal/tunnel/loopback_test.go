package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
)

// staticDialer hands out one pre-established session (no supervisor needed).
type staticDialer struct{ sess transport.Session }

func (s staticDialer) Session(context.Context) (transport.Session, error) { return s.sess, nil }

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startEcho starts a TCP echo server standing in for the "backend" (xray).
func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return ln
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func testParams(tr config.Transport) transport.Params {
	d := config.Default()
	return transport.Params{
		Transport:        tr,
		Key:              "loopback-test-key",
		MTU:              1350,
		KeepAliveSeconds: 2,
		KCP:              d.KCP,
		QUIC:             d.QUIC,
	}
}

// bringUp wires a server and a client over a pair of loopback UDP PacketConns
// and returns the client session plus a cleanup func.
func bringUp(t *testing.T, tr config.Transport, backendPort int, allowSocks bool) (context.Context, *Client) {
	t.Helper()
	params := testParams(tr)

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	lis, err := transport.Listen(serverPC, params)
	if err != nil {
		t.Fatalf("transport.Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		lis.Close()
		serverPC.Close()
		clientPC.Close()
	})

	srv := NewServer(config.ServerConfig{BackendIP: "127.0.0.1", AllowSocks5: allowSocks}, params.Key, quietLogger())
	go srv.Serve(ctx, lis)

	sess, err := transport.Dial(ctx, clientPC, serverPC.LocalAddr(), params)
	if err != nil {
		t.Fatalf("transport.Dial: %v", err)
	}

	cl := NewClient(config.ClientConfig{}, params.Key, staticDialer{sess}, quietLogger())
	return ctx, cl
}

func TestLoopbackTCPForward(t *testing.T) {
	for _, tr := range []config.Transport{config.TransportKCP, config.TransportQUIC} {
		tr := tr
		t.Run(string(tr), func(t *testing.T) {
			echo := startEcho(t)
			defer echo.Close()
			backendPort := echo.Addr().(*net.TCPAddr).Port

			ctx, cl := bringUp(t, tr, backendPort, false)
			localPort := freePort(t)
			cl.cfg.Forwards = []config.Forward{{
				Proto:      "tcp",
				Listen:     net.JoinHostPort("127.0.0.1", itoa(localPort)),
				TargetPort: uint16(backendPort),
			}}
			go cl.Run(ctx)

			roundTrip(t, localPort, "hello over "+string(tr))
		})
	}
}

func TestLoopbackSocks5(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	backendPort := echo.Addr().(*net.TCPAddr).Port

	ctx, cl := bringUp(t, config.TransportKCP, backendPort, true)
	socksPort := freePort(t)
	cl.cfg.Socks5Listen = net.JoinHostPort("127.0.0.1", itoa(socksPort))
	go cl.Run(ctx)

	// Connect through SOCKS5 to the echo server (arbitrary target).
	waitDial(t, socksPort)
	c, err := net.Dial("tcp", cl.cfg.Socks5Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	// greeting
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil || resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("socks greeting failed: %v %v", resp, err)
	}
	// CONNECT 127.0.0.1:backendPort (IPv4)
	req := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(backendPort >> 8), byte(backendPort)}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0 {
		t.Fatalf("socks connect failed: %v %v", rep, err)
	}
	// echo test
	msg := []byte("socks hello")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("socks echo mismatch: got %q", got)
	}
}

// TestLoopbackHelloVerify checks the connectivity round-trip: Verify succeeds
// with the right key and fails with a wrong one.
func TestLoopbackHelloVerify(t *testing.T) {
	for _, tr := range []config.Transport{config.TransportKCP, config.TransportQUIC} {
		tr := tr
		t.Run(string(tr), func(t *testing.T) {
			params := testParams(tr)
			serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			lis, err := transport.Listen(serverPC, params)
			if err != nil {
				t.Fatalf("transport.Listen: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(func() {
				cancel()
				lis.Close()
				serverPC.Close()
				clientPC.Close()
			})
			srv := NewServer(config.ServerConfig{BackendIP: "127.0.0.1"}, params.Key, quietLogger())
			go srv.Serve(ctx, lis)

			sess, err := transport.Dial(ctx, clientPC, serverPC.LocalAddr(), params)
			if err != nil {
				t.Fatalf("transport.Dial: %v", err)
			}
			if err := Verify(sess, params.Key); err != nil {
				t.Fatalf("Verify with correct key failed: %v", err)
			}
			if err := Verify(sess, "wrong-key"); err == nil {
				t.Fatalf("Verify with wrong key should have failed")
			}
		})
	}
}

func roundTrip(t *testing.T, localPort int, msg string) {
	t.Helper()
	waitDial(t, localPort)
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(localPort)))
	if err != nil {
		t.Fatalf("dial local forward: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
}

// waitDial retries until the local listener is accepting.
func waitDial(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("listener on %s never came up", addr)
}

func itoa(i int) string { return strconv.Itoa(i) }
