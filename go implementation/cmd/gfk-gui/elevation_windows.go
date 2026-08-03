//go:build gui && windows

package main

import "golang.org/x/sys/windows"

// isElevated reports whether the process runs with Administrator rights, which
// are required for raw sockets, Npcap and firewall changes.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
