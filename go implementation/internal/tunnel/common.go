package tunnel

import (
	"context"
	"io"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
)

// Dialer supplies the current live transport session, reconnecting as needed.
// The supervisor implements it.
type Dialer interface {
	Session(ctx context.Context) (transport.Session, error)
}

// pipe copies bytes in both directions until either side ends, then closes both.
func pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	cp := func(dst, src io.ReadWriteCloser) {
		_, _ = io.Copy(dst, src)
		_ = dst.Close()
		_ = src.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
