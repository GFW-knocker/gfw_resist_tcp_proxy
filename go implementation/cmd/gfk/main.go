// Command gfk is the client/server for the GFW-Knocker TCP-violation tunnel.
// It reads a YAML config (mode selects client or server), optionally installs
// firewall RST-suppression rules, brings up the fake-TCP carrier, and runs the
// selected role.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/carrier"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/firewall"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/supervisor"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/tunnel"
)

func main() {
	cfgPath := flag.String("config", "", "path to YAML config file")
	dropRST := flag.Bool("dropRST", false, "apply firewall RST-suppression rules without prompting")
	dropRSTlc := flag.Bool("droprst", false, "alias for -dropRST")
	flag.Parse()

	if *cfgPath == "" {
		*cfgPath = defaultConfigPath() // look for a config next to the binary
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "usage: gfk -config <file.yaml> [-dropRST]")
		fmt.Fprintln(os.Stderr, "  (or place server.yaml / client.yaml next to the gfk binary)")
		os.Exit(2)
	}
	forceFirewall := *dropRST || *dropRSTlc

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	logger.Info("config loaded", "path", *cfgPath)

	// vps_ip is required on the client; optional on the server (auto-derived).
	var vpsIP net.IP
	if cfg.Carrier.VPSIP != "" {
		if vpsIP = net.ParseIP(cfg.Carrier.VPSIP); vpsIP == nil {
			logger.Error("carrier.vps_ip is set but not a valid IP", "value", cfg.Carrier.VPSIP)
			os.Exit(1)
		}
	}
	if cfg.Mode == config.ModeClient && vpsIP == nil {
		logger.Error("carrier.vps_ip is required for client mode")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Firewall (RST suppression) --- covers the client's port-rotation range.
	fwRules := firewall.Rules{PortStart: cfg.Carrier.ServerPort, PortEnd: cfg.Carrier.ServerPort}
	if cfg.Mode == config.ModeClient {
		span := cfg.Carrier.ClientPortSpan
		if span < 1 {
			span = 1
		}
		fwRules = firewall.Rules{PortStart: cfg.Carrier.ClientPort, PortEnd: cfg.Carrier.ClientPort + uint16(span) - 1}
	}
	portDesc := fmt.Sprintf("%d-%d", fwRules.PortStart, fwRules.PortEnd)
	if decideFirewall(cfg.Firewall.Manage, forceFirewall) {
		remove, err := firewall.Install(fwRules)
		if err != nil {
			logger.Error("failed to apply firewall rules", "err", err)
			logger.Error("without RST suppression the OS will reset the carrier; aborting")
			os.Exit(1)
		}
		logger.Info("firewall RST-suppression rules applied", "ports", portDesc)
		defer func() {
			if err := remove(); err != nil {
				logger.Warn("failed to remove firewall rules", "err", err)
			} else {
				logger.Info("firewall rules removed")
			}
		}()
	} else {
		logger.Warn("firewall rules NOT managed by gfk; ensure kernel RSTs are suppressed on the carrier port(s) yourself", "ports", portDesc)
	}

	// --- Carrier ---
	role := carrier.RoleServer
	if cfg.Mode == config.ModeClient {
		role = carrier.RoleClient
	}
	car, err := carrier.Open(carrier.Options{
		Role:           role,
		VPSIP:          vpsIP,
		ServerPort:     cfg.Carrier.ServerPort,
		ClientPort:     cfg.Carrier.ClientPort,
		ClientPortSpan: cfg.Carrier.ClientPortSpan,
		Interface:      cfg.Carrier.Interface,
	})
	if err != nil {
		logger.Error("failed to open carrier", "err", err)
		os.Exit(1)
	}
	defer car.Close()
	logger.Info("carrier bound", "local_ip", car.LocalIP(), "interface", cfg.Carrier.Interface)

	params := transport.Params{
		Transport:        cfg.Transport,
		Key:              cfg.Auth.Key,
		MTU:              cfg.Carrier.MTU,
		KeepAliveSeconds: cfg.Client.KeepAliveSeconds,
		KCP:              cfg.KCP,
		QUIC:             cfg.QUIC,
	}

	switch cfg.Mode {
	case config.ModeClient:
		runClient(ctx, cfg, car, params, logger)
	case config.ModeServer:
		runServer(ctx, cfg, car, params, logger)
	}

	logger.Info("shutdown complete")
}

func runClient(ctx context.Context, cfg config.Config, car *carrier.Carrier, params transport.Params, logger *slog.Logger) {
	remote := &carrier.Addr{IP: net.ParseIP(cfg.Carrier.VPSIP), Port: cfg.Carrier.ServerPort}
	delay := time.Duration(cfg.Client.ReconnectSeconds) * time.Second
	if delay <= 0 {
		delay = 3 * time.Second
	}
	dialCount := 0
	sup := supervisor.New(func(dctx context.Context) (transport.Session, error) {
		if dialCount > 0 {
			// Reconnect: use a fresh source port so the server sees a new flow
			// instead of colliding with its previous (still-expiring) session.
			if p := car.RotateClientPort(); p != 0 {
				logger.Debug("rotated carrier source port for reconnect", "port", p)
			}
		}
		dialCount++
		sess, err := transport.Dial(dctx, car, remote, params)
		if err != nil {
			return nil, err
		}
		if err := tunnel.Verify(sess, cfg.Auth.Key); err != nil {
			_ = sess.Close()
			return nil, err
		}
		logger.Info(string(cfg.Transport)+" tunnel established to server", "peer", remote)
		return sess, nil
	}, delay, logger)
	go sup.Run(ctx)

	logger.Info("client starting", "transport", cfg.Transport, "vps", cfg.Carrier.VPSIP)
	cl := tunnel.NewClient(cfg.Client, cfg.Auth.Key, sup, logger)
	_ = cl.Run(ctx)
}

func runServer(ctx context.Context, cfg config.Config, car *carrier.Carrier, params transport.Params, logger *slog.Logger) {
	lis, err := transport.Listen(car, params)
	if err != nil {
		logger.Error("failed to start transport listener", "err", err)
		os.Exit(1)
	}
	logger.Info("server starting", "transport", cfg.Transport, "backend", cfg.Server.BackendIP, "allow_socks5", cfg.Server.AllowSocks5)
	srv := tunnel.NewServer(cfg.Server, cfg.Auth.Key, logger)
	if err := srv.Serve(ctx, lis); err != nil {
		logger.Error("server stopped", "err", err)
	}
}

// decideFirewall resolves the effective firewall policy.
func decideFirewall(policy config.FirewallPolicy, forceYes bool) bool {
	if forceYes {
		return true
	}
	switch policy {
	case config.FirewallYes:
		return true
	case config.FirewallNo:
		return false
	case config.FirewallAsk:
		return promptYesNo("Apply firewall rules to suppress kernel RSTs on the carrier port? [Y/n]: ")
	}
	return false
}

func promptYesNo(prompt string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Non-interactive (e.g. systemd): default to not touching the firewall.
		fmt.Fprintln(os.Stderr, "firewall.manage=ask but no terminal; skipping firewall changes (set manage: yes or pass -yes)")
		return false
	}
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "" || line == "y" || line == "yes"
}

// defaultConfigPath returns a config file sitting next to the executable when
// -config is omitted, so a gfk binary placed alongside server.yaml (e.g. in
// /root/gfk) runs with no flags.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	for _, name := range []string{"server.yaml", "client.yaml", "gfk.yaml"} {
		p := filepath.Join(dir, name)
		if fi, statErr := os.Stat(p); statErr == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
