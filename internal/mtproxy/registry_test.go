package mtproxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"routeproxy/internal/config"
	"routeproxy/internal/mtproxy"
)

func TestBuildRegistryFromExample(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := mtproxy.BuildRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Groups) != 1 || reg.Groups[0].ListenPort != 1443 {
		t.Fatalf("groups %+v", reg.Groups)
	}
	if reg.MTProtoGroups() != 1 || reg.FirstMTProtoGroup() == nil {
		t.Fatal("mtproto group")
	}
	if reg.AnyUp() {
		t.Fatal("nothing probed yet")
	}
}

func TestBuildRegistrySOCKSReserve(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies = append(cfg.Proxies, config.Proxy{
		Name: "reserve-socks", Type: "socks", Server: "127.0.0.1", Port: 1080,
		Username: "u", Password: "p", Reserve: true,
	})
	reg, err := mtproxy.BuildRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Groups) != 2 {
		t.Fatalf("want mtproto+socks groups, got %d", len(reg.Groups))
	}
}

func TestStatusServerHealthAndMetrics(t *testing.T) {
	p := &mtproxy.Proxy{Name: "p1", Server: "127.0.0.1", Port: 9, Secret: "dd00", Kind: "mtproto", Enabled: true, OK: true}
	reg := &mtproxy.Registry{
		Proxies: []*mtproxy.Proxy{p},
		Groups: []*mtproxy.Group{{
			Key: "mtproto:dd00", Kind: "mtproto", Secret: "dd00",
			ListenHost: "127.0.0.1", ListenPort: 1443,
			Proxies: []*mtproxy.Proxy{p}, Current: p,
		}},
		Probe: func(mtproxy.ProbeTarget, time.Duration) (bool, string) { return true, "ok" },
	}
	srv := httptest.NewServer(mtproxy.StatusServer{Reg: reg})
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	m := string(raw)
	if !strings.Contains(m, "routeproxy_checker_any_up 1") || !strings.Contains(m, "routeproxy_proxy_up") {
		t.Fatal(m)
	}

	resp, err = http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var snap map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	if snap["any_up"] != true {
		t.Fatalf("%v", snap["any_up"])
	}
}

func TestHealthzDown(t *testing.T) {
	reg := &mtproxy.Registry{}
	h := mtproxy.StatusServer{Reg: reg}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestCheckOneEmptySecret(t *testing.T) {
	p := &mtproxy.Proxy{Name: "x", Kind: "mtproto", Enabled: true}
	reg := &mtproxy.Registry{Proxies: []*mtproxy.Proxy{p}}
	reg.CheckOne(p, time.Second, 1, 1)
	if p.OK || p.LastError != "empty-secret" {
		t.Fatalf("%+v", p)
	}
}
