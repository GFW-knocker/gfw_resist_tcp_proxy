//go:build !linux && !windows

package carrier

import (
	"fmt"
	"runtime"
)

// newPacketIO has no raw-packet backend on this OS. Raw capture/injection is
// implemented only for linux (AF_PACKET + AF_INET raw) and windows (Npcap); on
// other platforms gfk still builds and links, but Open fails cleanly at startup
// with this message instead of not compiling at all.
func newPacketIO(ioParams) (packetIO, error) {
	return nil, fmt.Errorf("carrier: raw packet backend not implemented on %s/%s (supported: linux, windows)", runtime.GOOS, runtime.GOARCH)
}
