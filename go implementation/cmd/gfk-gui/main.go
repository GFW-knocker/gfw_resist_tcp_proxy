//go:build gui

// Command gfk-gui is the Windows desktop client (Fyne). It wraps the same
// client engine as the CLI: fake-TCP carrier -> KCP/QUIC transport -> port
// forwards + SOCKS5. Built separately from the cgo-free CLI via `-tags gui`.
package main

import (
	"context"
	"fmt"
	"image/color"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"gopkg.in/yaml.v3"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/carrier"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/firewall"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/supervisor"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/tunnel"
)

var (
	colGreen = color.NRGBA{R: 0x2e, G: 0xcc, B: 0x71, A: 0xff}
	colAmber = color.NRGBA{R: 0xf3, G: 0x9c, B: 0x12, A: 0xff}
	colGrey  = color.NRGBA{R: 0x95, G: 0xa5, B: 0xa6, A: 0xff}
	colRed   = color.NRGBA{R: 0xe7, G: 0x4c, B: 0x3c, A: 0xff}
)

type ui struct {
	win fyne.Window

	cfgPath  *widget.Entry
	vps      *widget.Entry
	key      *widget.Entry
	trans    *widget.Select
	srvPort  *widget.Entry
	cliPort  *widget.Entry
	mtu      *widget.Entry
	socks    *widget.Entry
	forwards *widget.Entry
	firewall *widget.Check

	connectBtn *widget.Button
	status     *canvas.Text
	rate       *canvas.Text
	logEntry   *widget.Entry
	logScroll  *container.Scroll

	logger *slog.Logger
	logh   *uiLogHandler

	mu     sync.Mutex
	eng    *engine
	ticker chan struct{}
}

func main() {
	a := app.NewWithID("org.gfwknocker.gfk")
	w := a.NewWindow("gfk — GFW Knocker")
	u := newUI(w)
	w.SetContent(u.build())
	w.Resize(fyne.NewSize(660, 720))

	if !isElevated() {
		u.logger.Warn("not running as Administrator — raw sockets, Npcap and firewall changes will fail; restart elevated")
	} else {
		u.logger.Info("gfk client ready")
	}
	w.SetCloseIntercept(func() {
		u.disconnect()
		w.Close()
	})
	w.ShowAndRun()
}

func newUI(w fyne.Window) *ui {
	d := config.Default()
	u := &ui{win: w}
	u.cfgPath = entry("client.yaml")
	u.vps = entry("")
	u.key = widget.NewPasswordEntry()
	u.trans = widget.NewSelect([]string{string(config.TransportKCP), string(config.TransportQUIC)}, nil)
	u.trans.SetSelected(string(d.Transport))
	u.srvPort = entry(strconv.Itoa(int(d.Carrier.ServerPort)))
	u.cliPort = entry(strconv.Itoa(int(d.Carrier.ClientPort)))
	u.mtu = entry(strconv.Itoa(d.Carrier.MTU))
	u.socks = entry("127.0.0.1:1080")
	u.forwards = widget.NewMultiLineEntry()
	u.forwards.SetPlaceHolder("one per line:  tcp 127.0.0.1:14000 443")
	u.firewall = widget.NewCheck("Manage firewall RST rules (recommended)", nil)
	u.firewall.SetChecked(true)

	u.status = canvas.NewText("○ disconnected", colGrey)
	u.status.TextStyle = fyne.TextStyle{Bold: true}
	u.rate = canvas.NewText("↓ 0 B/s   ↑ 0 B/s", colGrey)

	u.logEntry = widget.NewMultiLineEntry()
	u.logEntry.Wrapping = fyne.TextWrapWord
	u.logScroll = container.NewScroll(u.logEntry)
	u.logh = &uiLogHandler{level: slog.LevelInfo, set: func(s string) {
		u.logEntry.SetText(s)
		u.logScroll.ScrollToBottom()
	}}
	u.logger = slog.New(u.logh)
	return u
}

func (u *ui) build() fyne.CanvasObject {
	form := widget.NewForm(
		widget.NewFormItem("Config file", container.NewBorder(nil, nil, nil,
			container.NewHBox(
				widget.NewButton("Load", u.loadConfig),
				widget.NewButton("Save", u.saveConfig),
			), u.cfgPath)),
		widget.NewFormItem("VPS IP", u.vps),
		widget.NewFormItem("Shared key", u.key),
		widget.NewFormItem("Transport", u.trans),
		widget.NewFormItem("Server port", u.srvPort),
		widget.NewFormItem("Client port", u.cliPort),
		widget.NewFormItem("MTU", u.mtu),
		widget.NewFormItem("SOCKS5 listen", u.socks),
		widget.NewFormItem("Forwards", u.forwards),
	)

	u.connectBtn = widget.NewButton("Connect", u.toggle)
	u.connectBtn.Importance = widget.HighImportance

	statusBar := container.NewHBox(u.status, widget.NewLabel("   "), u.rate)
	top := container.NewVBox(form, u.firewall, u.connectBtn, widget.NewSeparator(), statusBar, widget.NewSeparator())

	return container.NewBorder(top, nil, nil, nil, u.logScroll)
}

func (u *ui) toggle() {
	u.mu.Lock()
	running := u.eng != nil
	u.mu.Unlock()
	if running {
		u.disconnect()
	} else {
		u.connect()
	}
}

func (u *ui) connect() {
	cfg, err := u.buildConfig()
	if err != nil {
		u.logger.Error("invalid config", "err", err)
		return
	}
	u.setInputs(false)
	u.connectBtn.SetText("Disconnect")
	u.setStatus(supervisor.StateConnecting)

	go func() {
		eng, err := startEngine(cfg, u.firewall.Checked, u.setStatus, u.logger)
		if err != nil {
			u.logger.Error("failed to start", "err", err)
			fyne.Do(func() {
				u.setInputs(true)
				u.connectBtn.SetText("Connect")
				u.setStatusText("○ start failed", colRed)
			})
			return
		}
		u.mu.Lock()
		u.eng = eng
		u.ticker = make(chan struct{})
		stop := u.ticker
		u.mu.Unlock()
		go u.pollRate(eng.car, stop)
	}()
}

func (u *ui) disconnect() {
	u.mu.Lock()
	eng := u.eng
	u.eng = nil
	if u.ticker != nil {
		close(u.ticker)
		u.ticker = nil
	}
	u.mu.Unlock()
	if eng != nil {
		eng.stop()
		u.logger.Info("disconnected")
	}
	fyne.Do(func() {
		u.setInputs(true)
		u.connectBtn.SetText("Connect")
		u.setStatusText("○ disconnected", colGrey)
		u.rate.Text = "↓ 0 B/s   ↑ 0 B/s"
		u.rate.Color = colGrey
		u.rate.Refresh()
	})
}

func (u *ui) pollRate(car *carrier.Carrier, stop chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	lastIn, lastOut := car.Stats()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			in, out := car.Stats()
			di, do := in-lastIn, out-lastOut
			lastIn, lastOut = in, out
			txt := fmt.Sprintf("↓ %s/s   ↑ %s/s", humanBytes(di), humanBytes(do))
			fyne.Do(func() {
				u.rate.Text = txt
				u.rate.Color = colGreen
				u.rate.Refresh()
			})
		}
	}
}

func (u *ui) setStatus(st supervisor.State) {
	switch st {
	case supervisor.StateUp:
		u.setStatusText("● connected", colGreen)
	case supervisor.StateConnecting:
		u.setStatusText("● connecting…", colAmber)
	case supervisor.StateDown:
		u.setStatusText("● reconnecting…", colAmber)
	}
}

func (u *ui) setStatusText(s string, c color.Color) {
	fyne.Do(func() {
		u.status.Text = s
		u.status.Color = c
		u.status.Refresh()
	})
}

func (u *ui) setInputs(enabled bool) {
	widgets := []fyne.Disableable{u.vps, u.key, u.trans, u.srvPort, u.cliPort, u.mtu, u.socks, u.forwards, u.firewall, u.cfgPath}
	for _, wdg := range widgets {
		if enabled {
			wdg.Enable()
		} else {
			wdg.Disable()
		}
	}
}

// buildConfig assembles and validates a client config from the form fields.
func (u *ui) buildConfig() (config.Config, error) {
	cfg := config.Default()
	cfg.Mode = config.ModeClient
	cfg.Transport = config.Transport(u.trans.Selected)
	cfg.Carrier.VPSIP = strings.TrimSpace(u.vps.Text)
	cfg.Carrier.ServerPort = atou16(u.srvPort.Text, cfg.Carrier.ServerPort)
	cfg.Carrier.ClientPort = atou16(u.cliPort.Text, cfg.Carrier.ClientPort)
	if m, err := strconv.Atoi(strings.TrimSpace(u.mtu.Text)); err == nil {
		cfg.Carrier.MTU = m
	}
	cfg.Auth.Key = u.key.Text
	cfg.Client.Socks5Listen = strings.TrimSpace(u.socks.Text)
	fws, err := parseForwards(u.forwards.Text)
	if err != nil {
		return cfg, err
	}
	cfg.Client.Forwards = fws
	if u.firewall.Checked {
		cfg.Firewall.Manage = config.FirewallYes
	} else {
		cfg.Firewall.Manage = config.FirewallNo
	}
	return cfg, cfg.Validate()
}

func (u *ui) applyConfig(cfg config.Config) {
	u.vps.SetText(cfg.Carrier.VPSIP)
	u.key.SetText(cfg.Auth.Key)
	u.trans.SetSelected(string(cfg.Transport))
	u.srvPort.SetText(strconv.Itoa(int(cfg.Carrier.ServerPort)))
	u.cliPort.SetText(strconv.Itoa(int(cfg.Carrier.ClientPort)))
	u.mtu.SetText(strconv.Itoa(cfg.Carrier.MTU))
	u.socks.SetText(cfg.Client.Socks5Listen)
	u.forwards.SetText(forwardsToText(cfg.Client.Forwards))
	u.firewall.SetChecked(cfg.Firewall.Manage != config.FirewallNo)
}

func (u *ui) loadConfig() {
	cfg, err := config.Load(strings.TrimSpace(u.cfgPath.Text))
	if err != nil {
		u.logger.Error("load config failed", "err", err)
		return
	}
	u.applyConfig(cfg)
	u.logger.Info("config loaded", "path", u.cfgPath.Text)
}

func (u *ui) saveConfig() {
	cfg, err := u.buildConfig()
	if err != nil {
		u.logger.Error("cannot save invalid config", "err", err)
		return
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		u.logger.Error("marshal failed", "err", err)
		return
	}
	if err := os.WriteFile(strings.TrimSpace(u.cfgPath.Text), out, 0o644); err != nil {
		u.logger.Error("write config failed", "err", err)
		return
	}
	u.logger.Info("config saved", "path", u.cfgPath.Text)
}

// ---- engine ----

type engine struct {
	cancel   context.CancelFunc
	car      *carrier.Carrier
	fwRemove func() error
}

func startEngine(cfg config.Config, applyFW bool, onState func(supervisor.State), logger *slog.Logger) (*engine, error) {
	vpsIP := net.ParseIP(cfg.Carrier.VPSIP)
	if vpsIP == nil {
		return nil, fmt.Errorf("invalid VPS IP %q", cfg.Carrier.VPSIP)
	}
	ctx, cancel := context.WithCancel(context.Background())

	span := cfg.Carrier.ClientPortSpan
	if span < 1 {
		span = 1
	}
	portEnd := cfg.Carrier.ClientPort + uint16(span) - 1

	var fwRemove func() error
	if applyFW {
		rm, err := firewall.Install(firewall.Rules{PortStart: cfg.Carrier.ClientPort, PortEnd: portEnd})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("firewall: %w", err)
		}
		fwRemove = rm
		logger.Info("firewall RST-suppression applied", "ports", fmt.Sprintf("%d-%d", cfg.Carrier.ClientPort, portEnd))
	}

	car, err := carrier.Open(carrier.Options{
		Role:           carrier.RoleClient,
		VPSIP:          vpsIP,
		ServerPort:     cfg.Carrier.ServerPort,
		ClientPort:     cfg.Carrier.ClientPort,
		ClientPortSpan: cfg.Carrier.ClientPortSpan,
		Interface:      cfg.Carrier.Interface,
	})
	if err != nil {
		cancel()
		if fwRemove != nil {
			_ = fwRemove()
		}
		return nil, fmt.Errorf("carrier: %w", err)
	}

	params := transport.Params{
		Transport:        cfg.Transport,
		Key:              cfg.Auth.Key,
		MTU:              cfg.Carrier.MTU,
		KeepAliveSeconds: cfg.Client.KeepAliveSeconds,
		KCP:              cfg.KCP,
		QUIC:             cfg.QUIC,
	}
	remote := &carrier.Addr{IP: vpsIP, Port: cfg.Carrier.ServerPort}
	delay := time.Duration(cfg.Client.ReconnectSeconds) * time.Second
	if delay <= 0 {
		delay = 3 * time.Second
	}
	dialCount := 0
	sup := supervisor.New(func(dctx context.Context) (transport.Session, error) {
		if dialCount > 0 {
			car.RotateClientPort() // fresh source port on reconnect
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
	sup.SetStateHook(onState)
	go sup.Run(ctx)

	cl := tunnel.NewClient(cfg.Client, cfg.Auth.Key, sup, logger)
	go cl.Run(ctx)

	return &engine{cancel: cancel, car: car, fwRemove: fwRemove}, nil
}

func (e *engine) stop() {
	e.cancel()
	_ = e.car.Close()
	if e.fwRemove != nil {
		_ = e.fwRemove()
	}
}

// ---- helpers ----

func entry(text string) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(text)
	return e
}

func atou16(s string, def uint16) uint16 {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v > 0 && v <= 65535 {
		return uint16(v)
	}
	return def
}

func parseForwards(s string) ([]config.Forward, error) {
	var fs []config.Forward
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.Fields(ln)
		if len(parts) != 3 {
			return nil, fmt.Errorf("bad forward %q (want: proto listen targetport)", ln)
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("bad target port in %q", ln)
		}
		fs = append(fs, config.Forward{Proto: parts[0], Listen: parts[1], TargetPort: uint16(port)})
	}
	return fs, nil
}

func forwardsToText(fs []config.Forward) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "%s %s %d\n", f.Proto, f.Listen, f.TargetPort)
	}
	return b.String()
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// uiLogHandler is an slog.Handler that renders records into the log pane.
type uiLogHandler struct {
	level slog.Level
	set   func(string)
	mu    sync.Mutex
	lines []string
}

func (h *uiLogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *uiLogHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %-5s %s", r.Time.Format("15:04:05"), r.Level.String(), r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&sb, "  %s=%v", a.Key, a.Value.Any())
		return true
	})
	h.mu.Lock()
	h.lines = append(h.lines, sb.String())
	if len(h.lines) > 400 {
		h.lines = h.lines[len(h.lines)-400:]
	}
	text := strings.Join(h.lines, "\n")
	h.mu.Unlock()
	fyne.Do(func() { h.set(text) })
	return nil
}

func (h *uiLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *uiLogHandler) WithGroup(string) slog.Handler      { return h }
