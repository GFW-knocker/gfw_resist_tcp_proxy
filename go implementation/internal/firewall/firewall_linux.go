//go:build linux

package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// install adds iptables rules:
//   - raw/PREROUTING + raw/OUTPUT NOTRACK for the carrier port, so conntrack
//     does not create phantom state for our handshake-less flow;
//   - mangle/OUTPUT drop of any kernel-generated RST from the carrier port.
func install(r Rules) (func() error, error) {
	start, end := r.ports()
	port := strconv.Itoa(int(start))
	if end != start {
		port = fmt.Sprintf("%d:%d", start, end) // iptables inclusive port range
	}
	// Each entry: table, then the rule spec (without -A/-D).
	specs := [][]string{
		{"raw", "PREROUTING", "-p", "tcp", "--dport", port, "-j", "NOTRACK"},
		{"raw", "OUTPUT", "-p", "tcp", "--sport", port, "-j", "NOTRACK"},
		{"mangle", "OUTPUT", "-p", "tcp", "--sport", port, "--tcp-flags", "RST", "RST", "-j", "DROP"},
	}

	var added [][]string
	remove := func() error {
		var errs []string
		// Remove in reverse order.
		for i := len(added) - 1; i >= 0; i-- {
			s := added[i]
			args := append([]string{"-t", s[0], "-D", s[1]}, s[2:]...)
			if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
				errs = append(errs, fmt.Sprintf("iptables -D %v: %v (%s)", s, err, strings.TrimSpace(string(out))))
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("firewall cleanup: %s", strings.Join(errs, "; "))
		}
		return nil
	}

	for _, s := range specs {
		args := append([]string{"-t", s[0], "-A", s[1]}, s[2:]...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			_ = remove()
			return nil, fmt.Errorf("iptables -A %v: %w (%s)", s, err, strings.TrimSpace(string(out)))
		}
		added = append(added, s)
	}
	return remove, nil
}
