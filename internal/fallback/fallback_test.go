package fallback_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"routeproxy/internal/alert"
	"routeproxy/internal/config"
	"routeproxy/internal/fallback"
	"routeproxy/internal/mtproxy"
)

func TestWriteInitialMTProtoEnv(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.BotAPI.EnvFile = filepath.Join(dir, "bot.env")
	cfg.BotAPI.CheckerHost = "127.0.0.1"
	reg, err := mtproxy.BuildRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := fallback.New(cfg, reg, alert.New(cfg))
	if err := c.WriteInitial(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(cfg.BotAPI.EnvFile)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"TDLIB_PROXY_TYPE=mtproto", "PROXY_PORT=1443", "PROXY_SECRET=ee"} {
		if !strings.Contains(s, want) {
			t.Fatalf("env missing %q:\n%s", want, s)
		}
	}
}

func TestTickFallbackWritesSOCKSEnv(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.BotAPI.EnvFile = filepath.Join(dir, "bot.env")
	cfg.Alerts.MTProtoDeadFor = "0s"
	cfg.Alerts.WarnWhenHealthyLeft = 1
	reg := &mtproxy.Registry{
		Probe: func(mtproxy.ProbeTarget, time.Duration) (bool, string) { return false, "down" },
	}
	p := &mtproxy.Proxy{Name: "tg", Server: "203.0.113.30", Port: 443, Secret: "dd00", Kind: "mtproto", Enabled: true}
	reg.Proxies = []*mtproxy.Proxy{p}
	reg.Groups = []*mtproxy.Group{{
		Key: "mtproto:dd00", Kind: "mtproto", Secret: "dd00",
		ListenHost: "127.0.0.1", ListenPort: 1443, Proxies: []*mtproxy.Proxy{p},
	}}
	c := fallback.New(cfg, reg, alert.New(cfg))
	if err := c.WriteInitial(); err != nil {
		t.Fatal(err)
	}
	cfg.Checker.Health.FailThreshold = 1
	cfg.Checker.Health.OKThreshold = 1
	cfg.Checker.Health.TimeoutSec = 1
	cfg.Checker.Health.Concurrency = 1
	reg.CheckAll(cfg)
	c.Tick()
	b, err := os.ReadFile(cfg.BotAPI.EnvFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "TDLIB_PROXY_TYPE=socks5") {
		t.Fatalf("expected socks fallback:\n%s", b)
	}
}
