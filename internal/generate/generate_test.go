package generate_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"routeproxy/internal/config"
	"routeproxy/internal/generate"
)

func TestBuildSnapshot(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := generate.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(res.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	route := doc["route"].(map[string]any)
	if route["final"] != "auto" {
		t.Fatalf("final %v", route["final"])
	}
	sets := route["rule_set"].([]any)
	var tags []string
	for _, s := range sets {
		m := s.(map[string]any)
		tags = append(tags, m["tag"].(string))
		if m["tag"] == "geosite-category-ru" && m["download_detour"] == "direct" {
			t.Fatal("github rule-sets should download via auto, not broken host IPv6")
		}
	}
	want := []string{"geosite-category-ru", "geoip-ru", "geosite-telegram", "geosite-google", "geosite-youtube"}
	joined := strings.Join(tags, ",")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Fatalf("missing rule-set %s in %s", w, joined)
		}
	}
	raw := string(res.JSON)
	for _, s := range []string{".ru", ".xn--p1ai", ".su", ".рф", "geosite-instagram"} {
		if !strings.Contains(raw, s) {
			t.Fatalf("generated JSON missing %q", s)
		}
	}
	if !strings.Contains(raw, `"action": "sniff"`) {
		t.Fatal("missing sniff")
	}
	obs := doc["outbounds"].([]any)
	found := map[string]bool{}
	for _, o := range obs {
		m := o.(map[string]any)
		found[m["tag"].(string)] = true
		if m["tag"] == "auto" && m["type"] != "urltest" {
			t.Fatal("auto should be urltest")
		}
	}
	for _, tag := range []string{"direct", "auto", "telegram", "ru", "vless-example"} {
		if !found[tag] {
			t.Fatalf("missing outbound %s", tag)
		}
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("example has no wireguard, unexpected warnings %v", res.Warnings)
	}
	if strings.Contains(raw, "geoip-telegram") || strings.Contains(raw, "geosite-ru-available-only-inside") {
		t.Fatal("removed 404 rule-sets should not be generated")
	}
}

func TestVLESSGRPCReality(t *testing.T) {
	cfg, err := config.Load("testdata/vless-grpc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := generate.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(res.JSON)
	for _, s := range []string{
		`"type": "grpc"`,
		`"service_name": "livestreamcontent"`,
		`"fingerprint": "firefox"`,
		`"packet_encoding": "xudp"`,
		`"example.com"`,
	} {
		if !strings.Contains(raw, s) {
			t.Fatalf("generated JSON missing %s", s)
		}
	}
	if strings.Contains(raw, `"flow"`) {
		t.Fatal("grpc vless should not set flow")
	}
}

func TestSkipMissingWireGuard(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies = append(cfg.Proxies, config.Proxy{
		Name:       "wg-missing",
		Purpose:    []string{"auto"},
		Type:       "wireguard",
		ConfigFile: filepath.Join(t.TempDir(), "nope.conf"),
	})
	res, err := generate.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "wg-missing") {
		t.Fatalf("warnings %v", res.Warnings)
	}
	if strings.Contains(string(res.JSON), "wg-missing") {
		t.Fatal("missing wg file should not appear in JSON")
	}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.GeneratedPath = filepath.Join(dir, "config.json")
	cfg.CacheDir = filepath.Join(dir, "cache")
	if _, err := generate.Write(cfg); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(cfg.GeneratedPath)
	if err != nil || st.Size() == 0 {
		t.Fatal(err)
	}
}

func TestBuildSFA(t *testing.T) {
	cfg, err := config.Load("testdata/vless-grpc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := generate.BuildSFA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(res.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	raw := string(res.JSON)
	if strings.Contains(raw, "mixed-in") || strings.Contains(raw, `"type": "mixed"`) {
		t.Fatal("SFA profile must not use mixed inbound")
	}
	if !strings.Contains(raw, `"tag": "tun-in"`) || !strings.Contains(raw, `"type": "tun"`) {
		t.Fatal("SFA profile needs tun inbound")
	}
	if !strings.Contains(raw, `"auto_route": true`) || !strings.Contains(raw, `"stack": "mixed"`) {
		t.Fatal("SFA tun missing auto_route/stack")
	}
	if strings.Contains(raw, "private_key_path") {
		t.Fatal("SFA JSON must not keep host private_key_path")
	}
	cache := doc["experimental"].(map[string]any)["cache_file"].(map[string]any)
	if cache["path"] != "cache.db" {
		t.Fatalf("SFA cache path %v", cache["path"])
	}
	if strings.Contains(raw, "listen_port") {
		t.Fatal("SFA tun should not listen on a SOCKS port")
	}
}

func TestBuildSFAInlinesSSH(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_rsa")
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-key\n-----END OPENSSH PRIVATE KEY-----"
	if err := os.WriteFile(keyPath, []byte(pem+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load("testdata/vless-grpc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies = append(cfg.Proxies, config.Proxy{
		Name:           "node-c",
		Purpose:        []string{"auto"},
		Type:           "ssh",
		Server:         "203.0.113.10",
		Port:           22,
		User:           "root",
		PrivateKeyPath: keyPath,
	})
	res, err := generate.BuildSFA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(res.JSON)
	if !strings.Contains(raw, `"private_key": "-----BEGIN OPENSSH PRIVATE KEY-----`) {
		t.Fatal("expected inlined ssh private_key")
	}
	if strings.Contains(raw, keyPath) || strings.Contains(raw, "private_key_path") {
		t.Fatal("host key path leaked into SFA JSON")
	}
}

func TestBuildSFASkipsMissingSSH(t *testing.T) {
	cfg, err := config.Load("testdata/vless-grpc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies = append(cfg.Proxies, config.Proxy{
		Name:           "node-c",
		Purpose:        []string{"auto"},
		Type:           "ssh",
		Server:         "203.0.113.10",
		PrivateKeyPath: filepath.Join(t.TempDir(), "missing"),
	})
	res, err := generate.BuildSFA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "node-c") {
		t.Fatalf("warnings %v", res.Warnings)
	}
	if strings.Contains(string(res.JSON), "node-c") {
		t.Fatal("unreadable ssh key should skip the outbound")
	}
}

func TestWriteSFA(t *testing.T) {
	cfg, err := config.Load("testdata/vless-grpc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sfa.json")
	res, err := generate.WriteSFA(cfg, path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 || int(st.Size()) != len(res.JSON) {
		t.Fatalf("write %v size %v", err, st)
	}
}

func TestBuildRUDirectHasNoRUGroup(t *testing.T) {
	cfg, err := config.Load("testdata/vless-grpc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := generate.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.RUTag != "direct" {
		t.Fatalf("ru tag %s", res.RUTag)
	}
	var doc map[string]any
	if err := json.Unmarshal(res.JSON, &doc); err != nil {
		t.Fatal(err)
	}
	for _, o := range doc["outbounds"].([]any) {
		if o.(map[string]any)["tag"] == "ru" {
			t.Fatal("routing.ru: direct must not emit ru urltest")
		}
	}
}

func TestBuildHTTPAndWireGuardInline(t *testing.T) {
	cfg, err := config.Load("testdata/vless-grpc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies = append(cfg.Proxies,
		config.Proxy{
			Name: "http-up", Purpose: []string{"auto"}, Type: "http",
			Server: "203.0.113.9", Port: 8080, Username: "u", Password: "p",
		},
		config.Proxy{
			Name: "wg-inline", Purpose: []string{"auto"}, Type: "wireguard",
			PrivateKey:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
			PeerPublicKey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=",
			Endpoint:      "wg.example.com:51820",
			LocalAddress:  []string{"10.8.0.2/32"},
			MTU:           1280,
		},
	)
	res, err := generate.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(res.JSON)
	if !strings.Contains(raw, `"type": "http"`) || !strings.Contains(raw, `"tag": "http-up"`) {
		t.Fatal("missing http outbound")
	}
	if !strings.Contains(raw, `"type": "wireguard"`) || !strings.Contains(raw, `"tag": "wg-inline"`) {
		t.Fatal("missing wg endpoint")
	}
	if !strings.Contains(raw, "wg.example.com") {
		t.Fatal("missing wg endpoint host")
	}
}
