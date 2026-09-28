package route_test

import (
	"strings"
	"testing"

	"routeproxy/internal/config"
	"routeproxy/internal/route"
)

func testCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestWhyTable(t *testing.T) {
	cfg := testCfg(t)
	cases := []struct {
		host     string
		out      string
		rulePart string
	}{
		{"10.0.0.1", "direct", "ip_is_private"},
		{"127.0.0.1", "direct", "ip_is_private"},
		{"nalog.ru", "direct", "exception"},
		{"www.gosuslugi.ru", "direct", "exception"},
		{"ya.ru", "ru", "domain_suffix"},
		{"пример.рф", "ru", "domain_suffix"},
		{"xn--e1afmkfd.xn--p1ai", "ru", "domain_suffix"},
		{"example.su", "ru", "domain_suffix"},
		{"telegram.org", "telegram", "telegram"},
		{"web.telegram.org", "telegram", "telegram"},
		{"google.com", "auto", "force-auto"},
		{"www.youtube.com", "auto", "force-auto"},
		{"vk.com", "ru", "geosite"},
		{"shop.example.ru", "ru", "domain_suffix"},
	}
	for _, tc := range cases {
		d := route.Why(cfg, tc.host)
		if d.Outbound != tc.out {
			t.Errorf("%s: outbound %s want %s (%s)", tc.host, d.Outbound, tc.out, d.Rule)
		}
		if !strings.Contains(d.Rule, tc.rulePart) {
			t.Errorf("%s: rule %q want contain %q", tc.host, d.Rule, tc.rulePart)
		}
	}
}

func TestRUFallbackDirectWhenNoRUProxies(t *testing.T) {
	cfg := testCfg(t)
	var kept []config.Proxy
	for _, p := range cfg.Proxies {
		if !p.HasPurpose("ru") {
			kept = append(kept, p)
		}
	}
	cfg.Proxies = kept
	d := route.Why(cfg, "ya.ru")
	if d.Outbound != "direct" {
		t.Fatalf("got %s (%s)", d.Outbound, d.Rule)
	}
}

func TestWhyCIDRAndNamedOutbound(t *testing.T) {
	cfg := testCfg(t)
	cfg.Routing.Exceptions = append([]config.Exception{
		{MatchCIDR: "203.0.113.0/24", Outbound: "direct"},
		{MatchDomain: "rotator.test", Outbound: "ru-rotate"},
	}, cfg.Routing.Exceptions...)
	d := route.Why(cfg, "203.0.113.50")
	if d.Outbound != "direct" || !strings.Contains(d.Rule, "cidr") {
		t.Fatalf("%+v", d)
	}
	d = route.Why(cfg, "rotator.test")
	if d.Outbound != "ru-rotate" || !strings.Contains(d.Rule, "exception domain") {
		t.Fatalf("%+v", d)
	}
	if !strings.Contains(d.String(), "rotator.test") {
		t.Fatal(d.String())
	}
}

func TestWhyErrorOnBadConfig(t *testing.T) {
	d := route.Why(&config.Config{Listen: "bad"}, "ya.ru")
	if d.Outbound != "error" {
		t.Fatalf("%+v", d)
	}
}
