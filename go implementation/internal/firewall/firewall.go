// Package firewall installs and removes the OS rules that stop the kernel from
// resetting the fake-TCP carrier. Because gfk fabricates TCP packets that the
// kernel has no socket for, the OS would otherwise reply with RST and also let
// conntrack interfere. On Linux we NOTRACK the carrier port and drop kernel
// RSTs; on Windows we block the stack from seeing the carrier port (Npcap still
// captures below the firewall).
package firewall

// Rules describes what to protect.
type Rules struct {
	// LocalPort is the carrier TCP port this side owns (server_port on the
	// server, client_port on the client). Kernel RSTs originate from it.
	LocalPort uint16
}

// Install applies the rules and returns a function that removes them. The
// implementation is platform-specific; on unsupported platforms it is a no-op.
func Install(r Rules) (remove func() error, err error) {
	return install(r)
}
