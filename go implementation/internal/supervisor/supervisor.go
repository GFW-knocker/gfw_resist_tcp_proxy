// Package supervisor keeps a single client-side transport session alive. It
// (re)dials on demand, holds the session open so the transport's keepalive
// traffic keeps the NAT pinhole warm, and hands the current live session to
// callers, blocking while a reconnect is in progress.
package supervisor

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
)

// Factory establishes a new session (typically transport.Dial over the carrier).
type Factory func(ctx context.Context) (transport.Session, error)

// State is the current connection state, for UIs.
type State int32

const (
	StateConnecting State = iota
	StateUp
	StateDown
)

// String renders the state for display.
func (s State) String() string {
	switch s {
	case StateUp:
		return "connected"
	case StateDown:
		return "disconnected"
	default:
		return "connecting"
	}
}

// Supervisor maintains one live session with automatic reconnection.
type Supervisor struct {
	factory Factory
	delay   time.Duration
	log     *slog.Logger

	mu      sync.Mutex
	cond    *sync.Cond
	cur     transport.Session
	stopped bool

	state   atomic.Int32
	onState func(State)
}

// New builds a Supervisor. delay is the pause between reconnection attempts.
func New(f Factory, delay time.Duration, log *slog.Logger) *Supervisor {
	s := &Supervisor{factory: f, delay: delay, log: log}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// SetStateHook registers a callback invoked on every connection-state change.
// Call it before Run.
func (s *Supervisor) SetStateHook(f func(State)) { s.onState = f }

// State reports the current connection state.
func (s *Supervisor) State() State { return State(s.state.Load()) }

func (s *Supervisor) setState(st State) {
	if s.state.Swap(int32(st)) == int32(st) {
		return
	}
	if s.onState != nil {
		s.onState(st)
	}
}

// Run maintains the session until ctx is cancelled.
func (s *Supervisor) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		s.stopped = true
		s.cond.Broadcast()
		s.mu.Unlock()
	}()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.setState(StateConnecting)
		sess, err := s.factory(ctx)
		if err != nil {
			s.log.Warn("tunnel connect failed", "err", err)
			if !sleepCtx(ctx, s.delay) {
				return ctx.Err()
			}
			continue
		}

		s.mu.Lock()
		s.cur = sess
		s.cond.Broadcast()
		s.mu.Unlock()
		s.setState(StateUp)
		s.log.Debug("session up", "peer", sess.RemoteAddr())

		s.waitDead(ctx, sess)

		s.mu.Lock()
		if s.cur == sess {
			s.cur = nil
		}
		s.mu.Unlock()
		_ = sess.Close()
		s.setState(StateDown)

		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.log.Warn("tunnel down; reconnecting")
		if !sleepCtx(ctx, s.delay) {
			return ctx.Err()
		}
	}
}

// waitDead returns when the session closes or ctx is cancelled.
func (s *Supervisor) waitDead(ctx context.Context, sess transport.Session) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		if sess.IsClosed() {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Session returns the current live session, blocking while reconnecting. It
// satisfies tunnel.Dialer.
func (s *Supervisor) Session(ctx context.Context) (transport.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if s.stopped {
			return nil, context.Canceled
		}
		if s.cur != nil && !s.cur.IsClosed() {
			return s.cur, nil
		}
		s.cond.Wait()
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
