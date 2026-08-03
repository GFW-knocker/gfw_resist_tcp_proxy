//go:build !linux && !windows

package firewall

// install is a no-op on platforms without a supported firewall integration.
func install(r Rules) (func() error, error) {
	return func() error { return nil }, nil
}
