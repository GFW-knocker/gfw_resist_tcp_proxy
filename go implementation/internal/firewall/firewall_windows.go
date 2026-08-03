//go:build windows

package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// install adds Windows Firewall rules that stop the TCP/IP stack from seeing
// the carrier port (so it never emits a RST). Npcap captures below WFP, so
// inbound carrier packets are still delivered to gfk. We block both directions
// on the port for good measure.
func install(r Rules) (func() error, error) {
	port := strconv.Itoa(int(r.LocalPort))
	nameIn := "gfk-carrier-in-" + port
	nameOut := "gfk-carrier-out-" + port

	rules := []struct {
		name string
		dir  string
	}{
		{nameIn, "in"},
		{nameOut, "out"},
	}

	var added []string
	remove := func() error {
		var errs []string
		for _, name := range added {
			out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
				"name="+name).CombinedOutput()
			if err != nil {
				errs = append(errs, fmt.Sprintf("delete %s: %v (%s)", name, err, strings.TrimSpace(string(out))))
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("firewall cleanup: %s", strings.Join(errs, "; "))
		}
		return nil
	}

	for _, ru := range rules {
		out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ru.name,
			"dir="+ru.dir,
			"action=block",
			"protocol=TCP",
			"localport="+port,
		).CombinedOutput()
		if err != nil {
			_ = remove()
			return nil, fmt.Errorf("netsh add rule %s: %w (%s)", ru.name, err, strings.TrimSpace(string(out)))
		}
		added = append(added, ru.name)
	}
	return remove, nil
}
