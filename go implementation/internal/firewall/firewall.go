// Package firewall installs and removes the OS rules that stop the kernel from
// resetting the fake-TCP carrier. Because gfk fabricates TCP packets that the
// kernel has no socket for, the OS would otherwise reply with RST and also let
// conntrack interfere. On Linux we NOTRACK the carrier port(s) and drop kernel
// RSTs; on Windows we block the stack from seeing them (Npcap still captures
// below the firewall).
package firewall

// Rules describes the carrier TCP port range to protect from the kernel.
type Rules struct {
	// PortStart..PortEnd (inclusive) is the carrier port range this side owns:
	// a single port on the server (server_port), or the client_port rotation
	// range on the client. Kernel RSTs originate from these ports; we suppress
	// them and NOTRACK the range. If PortEnd < PortStart it means a single port.
	PortStart uint16
	PortEnd   uint16
}

// ports returns the normalized inclusive [start, end] range.
func (r Rules) ports() (start, end uint16) {
	end = r.PortEnd
	if end < r.PortStart {
		end = r.PortStart
	}
	return r.PortStart, end
}

// Install applies the rules and returns a function that removes them. The
// implementation is platform-specific; on unsupported platforms it is a no-op.
func Install(r Rules) (remove func() error, err error) {
	return install(r)
}
