// Package config defines the on-disk YAML configuration for gfk and the
// runtime defaults. One struct serves both client and server; the `mode`
// field selects which half of the config is active.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode is client or server.
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

// Transport selects the reliability layer that runs on top of the carrier.
type Transport string

const (
	TransportKCP  Transport = "kcp"
	TransportQUIC Transport = "quic"
)

// FirewallPolicy controls whether gfk touches the OS firewall to suppress
// kernel RSTs for the carrier port.
type FirewallPolicy string

const (
	// FirewallAsk prompts the user once at startup (interactive TTY only).
	FirewallAsk FirewallPolicy = "ask"
	// FirewallYes applies the rules without prompting (use for services).
	FirewallYes FirewallPolicy = "yes"
	// FirewallNo never touches the firewall; the user manages RST suppression.
	FirewallNo FirewallPolicy = "no"
)

// Config is the whole file.
type Config struct {
	Mode      Mode      `yaml:"mode"`
	Transport Transport `yaml:"transport"`

	Carrier  CarrierConfig  `yaml:"carrier"`
	Firewall FirewallConfig `yaml:"firewall"`
	Auth     AuthConfig     `yaml:"auth"`
	KCP      KCPConfig      `yaml:"kcp"`
	QUIC     QUICConfig     `yaml:"quic"`

	Client ClientConfig `yaml:"client"`
	Server ServerConfig `yaml:"server"`

	LogLevel string `yaml:"log_level"`
}

// CarrierConfig describes the fake-TCP link.
type CarrierConfig struct {
	// VPSIP is the server's (filtered) public IP.
	//   - client: REQUIRED — the address to send to and to accept replies from.
	//   - server: OPTIONAL — reply source IP. If empty, it is auto-derived per
	//     client from the destination IP of inbound packets (recommended; also
	//     correct behind 1:1-NAT clouds). Set it only to force a specific source.
	VPSIP string `yaml:"vps_ip"`
	// ServerPort is the carrier TCP port the server "listens" on (vio_tcp_server_port).
	ServerPort uint16 `yaml:"server_port"`
	// ClientPort is the carrier TCP source port the client uses (vio_tcp_client_port);
	// the base of the reconnect rotation range.
	ClientPort uint16 `yaml:"client_port"`
	// ClientPortSpan rotates the client source port across this many ports (from
	// ClientPort) on each reconnect, so a new session doesn't collide with the
	// server's not-yet-expired old one. 1 = disable. The firewall covers the range.
	ClientPortSpan int `yaml:"client_port_span"`
	// Interface is the NIC to capture/inject on. Empty = auto-detect the
	// interface used to reach VPSIP.
	Interface string `yaml:"interface"`
	// MTU is the maximum carrier payload (bytes placed in one TCP segment).
	// The transport layer is told to stay under this to avoid IP fragmentation.
	MTU int `yaml:"mtu"`
}

// FirewallConfig controls RST suppression.
type FirewallConfig struct {
	Manage FirewallPolicy `yaml:"manage"`
}

// AuthConfig holds the pre-shared secret used for carrier crypto and the
// per-stream connect handshake.
type AuthConfig struct {
	Key string `yaml:"key"`
}

// KCPConfig mirrors kcp-go's tunables plus the smux flow-control windows.
// See the profiles in config/*.example.yaml and GO.md for per-line-speed values.
type KCPConfig struct {
	NoDelay   int `yaml:"nodelay"`   // 1 = low-latency mode (fast flush/ACK); 0 = normal
	Interval  int `yaml:"interval"`  // internal update period, ms (10 responsive .. 40 low-CPU)
	Resend    int `yaml:"resend"`    // fast-retransmit after N duplicate ACKs (0 = off)
	NC        int `yaml:"nc"`        // 0 = congestion control ON (adaptive); 1 = OFF (aggressive)
	SndWnd    int `yaml:"sndwnd"`    // send window, packets (max in-flight sent)
	RcvWnd    int `yaml:"rcvwnd"`    // receive window, packets. Throughput ~= window*mtu/RTT
	FECData   int `yaml:"fec_data"`  // Reed-Solomon data shards; 0 = FEC off
	FECParity int `yaml:"fec_parity"`// parity shards recovered per group (must match both ends)
	// StreamBuffer / SessionBuffer are the smux flow-control windows in BYTES:
	// per-connection and whole-tunnel. Single-connection throughput is capped at
	// StreamBuffer/RTT. 0 = defaults (4 MB / 16 MB). Raise both for >100 Mbps links.
	StreamBuffer  int `yaml:"stream_buffer"`
	SessionBuffer int `yaml:"session_buffer"`
}

// QUICConfig holds QUIC-specific knobs.
type QUICConfig struct {
	// KeepAlivePeriod in seconds (0 = library default).
	KeepAlivePeriod int `yaml:"keepalive_period"`
	// MaxIdleTimeout in seconds.
	MaxIdleTimeout int `yaml:"max_idle_timeout"`
}

// Forward is a single client-side listener that maps to a server backend port.
type Forward struct {
	Proto      string `yaml:"proto"` // "tcp" or "udp"
	Listen     string `yaml:"listen"`
	TargetPort uint16 `yaml:"target_port"`
}

// ClientConfig is the client half.
type ClientConfig struct {
	// Socks5Listen, if non-empty, exposes a SOCKS5 proxy (server dials arbitrary targets).
	Socks5Listen string `yaml:"socks5_listen"`
	// Forwards are fixed local:remote-port maps (server dials backend_ip:target_port).
	Forwards []Forward `yaml:"forwards"`
	// KeepAliveSeconds is the carrier/session heartbeat period (keeps NAT pinhole open).
	KeepAliveSeconds int `yaml:"keepalive_seconds"`
	// ReconnectSeconds is the delay between reconnection attempts.
	ReconnectSeconds int `yaml:"reconnect_seconds"`
}

// ServerConfig is the server half.
type ServerConfig struct {
	// BackendIP is where forwarded connections are dialed (xray_server_ip_address).
	BackendIP string `yaml:"backend_ip"`
	// AllowSocks5, when true, lets clients request arbitrary targets (SOCKS mode).
	AllowSocks5 bool `yaml:"allow_socks5"`
	// AllowedPorts restricts which destination ports a client may reach (applies
	// to both port-forward and SOCKS targets). Empty = no restriction (any port).
	// e.g. [443, 2096, 2052] lets clients reach only those ports.
	AllowedPorts []int `yaml:"allowed_ports"`
}

// Default returns a Config populated with sensible defaults, matching the
// port numbers used by the reference Python implementation where relevant.
func Default() Config {
	return Config{
		Mode:      ModeClient,
		Transport: TransportKCP,
		Carrier: CarrierConfig{
			ServerPort:     45000,
			ClientPort:     40000,
			ClientPortSpan: 8,
			MTU:            1400,
		},
		Firewall: FirewallConfig{Manage: FirewallAsk},
		Auth:     AuthConfig{Key: "change-me"},
		KCP: KCPConfig{
			NoDelay:   1,
			Interval:  10,
			Resend:    2,
			NC:        1, // no congestion control = KCP's normal mode (nc=0/CC underperforms on this carrier)
			SndWnd:    128, // ~BDP for a slow link; bounds bufferbloat. Raise for faster links (see profiles)
			RcvWnd:    128,
			FECData:   0, // FEC off by default (saves ~30% bandwidth); enable on lossy links
			FECParity: 0,
			StreamBuffer:  0, // 0 = auto-size smux buffers from the KCP window
			SessionBuffer: 0,
		},
		QUIC: QUICConfig{KeepAlivePeriod: 4, MaxIdleTimeout: 8},
		Client: ClientConfig{
			KeepAliveSeconds: 4,
			ReconnectSeconds: 2,
		},
		Server: ServerConfig{BackendIP: "127.0.0.1"},
		LogLevel: "info",
	}
}

// Load reads a YAML file over the defaults and validates it.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate checks required fields for the selected mode.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeClient, ModeServer:
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeClient, ModeServer, c.Mode)
	}
	switch c.Transport {
	case TransportKCP, TransportQUIC:
	default:
		return fmt.Errorf("transport must be %q or %q, got %q", TransportKCP, TransportQUIC, c.Transport)
	}
	switch c.Firewall.Manage {
	case FirewallAsk, FirewallYes, FirewallNo:
	default:
		return fmt.Errorf("firewall.manage must be ask|yes|no, got %q", c.Firewall.Manage)
	}
	if c.Mode == ModeClient && c.Carrier.VPSIP == "" {
		return fmt.Errorf("carrier.vps_ip is required for client mode")
	}
	if c.Carrier.ServerPort == 0 || c.Carrier.ClientPort == 0 {
		return fmt.Errorf("carrier.server_port and carrier.client_port are required")
	}
	if c.Carrier.ClientPortSpan < 0 || int(c.Carrier.ClientPort)+c.Carrier.ClientPortSpan-1 > 65535 {
		return fmt.Errorf("carrier.client_port_span invalid: client_port + span - 1 exceeds 65535")
	}
	if c.Carrier.MTU < 576 || c.Carrier.MTU > 1500 {
		return fmt.Errorf("carrier.mtu must be between 576 and 1500, got %d", c.Carrier.MTU)
	}
	if strings.TrimSpace(c.Auth.Key) == "" {
		return fmt.Errorf("auth.key is required")
	}
	if c.Mode == ModeClient {
		if c.Client.Socks5Listen == "" && len(c.Client.Forwards) == 0 {
			return fmt.Errorf("client needs at least a socks5_listen or one forward")
		}
		for i, f := range c.Client.Forwards {
			if f.Proto != "tcp" && f.Proto != "udp" {
				return fmt.Errorf("client.forwards[%d].proto must be tcp|udp", i)
			}
			if f.Listen == "" || f.TargetPort == 0 {
				return fmt.Errorf("client.forwards[%d] needs listen and target_port", i)
			}
		}
	}
	if c.Mode == ModeServer {
		for i, p := range c.Server.AllowedPorts {
			if p < 1 || p > 65535 {
				return fmt.Errorf("server.allowed_ports[%d]=%d is out of range 1-65535", i, p)
			}
		}
	}
	return nil
}
