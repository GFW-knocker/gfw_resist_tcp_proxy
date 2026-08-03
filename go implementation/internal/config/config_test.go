package config

import (
	"path/filepath"
	"testing"
)

// TestExampleConfigsValidate ensures the shipped example configs load and pass
// validation — in particular that the server example (empty vps_ip) is accepted
// while the client example (vps_ip set) is too.
func TestExampleConfigsValidate(t *testing.T) {
	for _, name := range []string{"server.example.yaml", "client.example.yaml"} {
		p := filepath.Join("..", "..", "config", name)
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("%s: load: %v", name, err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: validate: %v", name, err)
		}
	}
}

// TestServerAllowsEmptyVPSIP / client requires it.
func TestVPSIPRequirement(t *testing.T) {
	base := Default()
	base.Auth.Key = "k"
	base.Carrier.ServerPort, base.Carrier.ClientPort, base.Carrier.MTU = 45000, 40000, 1400

	srv := base
	srv.Mode = ModeServer
	srv.Server.BackendIP = "127.0.0.1"
	srv.Carrier.VPSIP = ""
	if err := srv.Validate(); err != nil {
		t.Errorf("server with empty vps_ip should validate, got: %v", err)
	}
	srv.Carrier.ClientPort = 0 // server ignores client_port; must not be required
	if err := srv.Validate(); err != nil {
		t.Errorf("server should not require client_port, got: %v", err)
	}

	cli := base
	cli.Mode = ModeClient
	cli.Client.Forwards = []Forward{{Proto: "tcp", Listen: "127.0.0.1:14000", TargetPort: 443}}
	cli.Carrier.VPSIP = ""
	if err := cli.Validate(); err == nil {
		t.Errorf("client with empty vps_ip should fail validation")
	}
}
