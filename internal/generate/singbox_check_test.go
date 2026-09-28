package generate_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"routeproxy/internal/config"
	"routeproxy/internal/generate"
)

func TestSingBoxCheck(t *testing.T) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("sing-box not installed")
	}
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.GeneratedPath = filepath.Join(dir, "config.json")
	cfg.CacheDir = filepath.Join(dir, "cache")
	if _, err := generate.Write(cfg); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "check", "-c", cfg.GeneratedPath)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check: %v\n%s", err, out)
	}
}

func TestSingBoxCheckSFA(t *testing.T) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("sing-box not installed")
	}
	cfg, err := config.Load("testdata/vless-grpc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sfa.json")
	if _, err := generate.WriteSFA(cfg, path); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "check", "-c", path)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check sfa: %v\n%s", err, out)
	}
}
