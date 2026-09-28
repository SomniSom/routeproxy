package config_test

import (
	"testing"

	"routeproxy/internal/config"
)

func TestLoadExample(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:1080" {
		t.Fatal(cfg.Listen)
	}
	if !cfg.HasPurpose("ru") || !cfg.HasPurpose("auto") {
		t.Fatal("purposes")
	}
	var socksURL bool
	for _, p := range cfg.Proxies {
		if p.Name == "socks-example" {
			if p.Server != "203.0.113.20" || p.Port != 1080 {
				t.Fatalf("%+v", p)
			}
			socksURL = true
		}
	}
	if !socksURL {
		t.Fatal("url-imported socks")
	}
	if cfg.TelegramMTProto[0].Secret[:2] != "ee" {
		t.Fatal(cfg.TelegramMTProto[0])
	}
	if cfg.Alerts.ForbidDirect {
		t.Fatal("example should leave forbid_direct off")
	}
}

func TestValidateDuplicateName(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies = append(cfg.Proxies, cfg.Proxies[0])
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected duplicate name")
	}
}

func TestValidateBadListen(t *testing.T) {
	cfg := &config.Config{Listen: "not-a-port"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected listen error")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/out.yaml"
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen != cfg.Listen || len(got.Proxies) != len(cfg.Proxies) {
		t.Fatalf("roundtrip %+v", got.Listen)
	}
}

func TestExceptionForceWins(t *testing.T) {
	e := config.Exception{Outbound: "auto", Force: "direct"}
	if e.Target() != "direct" {
		t.Fatal(e.Target())
	}
}

func TestHasWireGuardAndHostPort(t *testing.T) {
	en := true
	cfg := &config.Config{
		Listen:  "0.0.0.0:8079",
		Proxies: []config.Proxy{{Name: "wg", Type: "wireguard", Enabled: &en}},
	}
	if !cfg.HasWireGuard() {
		t.Fatal("expected wg")
	}
	h, p, err := cfg.ListenHostPort()
	if err != nil || h != "0.0.0.0" || p != 8079 {
		t.Fatalf("%s %d %v", h, p, err)
	}
}

func TestDisabledProxy(t *testing.T) {
	f := false
	p := config.Proxy{Enabled: &f}
	if p.IsEnabled() {
		t.Fatal("disabled")
	}
}
