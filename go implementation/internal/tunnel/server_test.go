package tunnel

import (
	"io"
	"log/slog"
	"testing"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
)

// TestResolveTargetPortAllowlist verifies the server-side destination-port
// allowlist: only listed ports are reachable when set; empty = unrestricted.
func TestResolveTargetPortAllowlist(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	restricted := NewServer(config.ServerConfig{
		BackendIP:    "127.0.0.1",
		AllowedPorts: []int{443, 2096, 2052},
	}, "psk", log)

	if _, ok := restricted.resolveTarget(connectReq{Cmd: cmdConnectTCP, Atyp: atypBackendPort, Port: 443}); !ok {
		t.Error("port 443 should be allowed")
	}
	if _, ok := restricted.resolveTarget(connectReq{Cmd: cmdConnectTCP, Atyp: atypBackendPort, Port: 22}); ok {
		t.Error("port 22 must be refused by the allowlist")
	}

	// Allowlist also applies to SOCKS targets.
	socks := NewServer(config.ServerConfig{
		BackendIP:    "127.0.0.1",
		AllowSocks5:  true,
		AllowedPorts: []int{443},
	}, "psk", log)
	if _, ok := socks.resolveTarget(connectReq{Cmd: cmdConnectTCP, Atyp: atypIPv4, Host: "1.2.3.4", Port: 80}); ok {
		t.Error("SOCKS target on port 80 must be refused by the allowlist")
	}
	if _, ok := socks.resolveTarget(connectReq{Cmd: cmdConnectTCP, Atyp: atypIPv4, Host: "1.2.3.4", Port: 443}); !ok {
		t.Error("SOCKS target on port 443 should be allowed")
	}

	open := NewServer(config.ServerConfig{BackendIP: "127.0.0.1"}, "psk", log)
	if _, ok := open.resolveTarget(connectReq{Cmd: cmdConnectTCP, Atyp: atypBackendPort, Port: 9999}); !ok {
		t.Error("empty allowlist should allow any port")
	}
}
