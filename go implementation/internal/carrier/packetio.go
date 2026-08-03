package carrier

import (
	"fmt"
	"net"
)

// ioParams carries everything a platform backend needs to open its sockets.
type ioParams struct {
	role       Role
	ifaceName  string
	localIP    net.IP
	vpsIP      net.IP
	serverPort uint16
	clientPort uint16
	snapLen    int
}

// bpfFilter returns a libpcap-style filter selecting inbound carrier packets.
// (Windows/libpcap uses it directly; Linux applies exact matching in userspace.)
func (p ioParams) bpfFilter() string {
	if p.role == RoleClient {
		return fmt.Sprintf("tcp and src host %s and src port %d and dst port %d",
			p.vpsIP, p.serverPort, p.clientPort)
	}
	// Server matches by destination port only: with 1:1-NAT the destination IP is
	// a private address, and vps_ip is optional on the server.
	return fmt.Sprintf("tcp and dst port %d", p.serverPort)
}

// findInterface resolves the NIC to use: by name if given, else the interface
// that owns localIP.
func findInterface(name string, localIP net.IP) (*net.Interface, error) {
	if name != "" {
		return net.InterfaceByName(name)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localIP) {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("carrier: no interface owns local IP %s (set carrier.interface explicitly)", localIP)
}
