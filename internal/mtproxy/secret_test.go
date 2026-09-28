package mtproxy_test

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"routeproxy/internal/config"
	"routeproxy/internal/mtproxy"
)

func TestSecretEE(t *testing.T) {
	// telegram.org in hex after 32-byte key
	sec := "ee" + "00" + "000000000000000000000000000000" + "74656c656772616d2e6f7267"
	// simpler: ee + 32 hex chars of zeros is 2+32=34, rest is domain
	sec = "ee" + "00000000000000000000000000000000" + "74656c656772616d2e6f7267"
	m := mtproxy.SecretMetaFrom(sec)
	if m.Kind != mtproxy.SecretEE {
		t.Fatalf("kind %s", m.Kind)
	}
	if m.SNI != "telegram.org" {
		t.Fatalf("sni %q", m.SNI)
	}
}

func TestSecretDD(t *testing.T) {
	m := mtproxy.SecretMetaFrom("ddaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if m.Kind != mtproxy.SecretDD {
		t.Fatal(m.Kind)
	}
}

func TestProbeTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	ok, detail := mtproxy.Probe(mtproxy.ProbeTarget{Kind: "mtproto", Server: "127.0.0.1", Port: p, Secret: "aabbcc"}, time.Second)
	if !ok {
		t.Fatal(detail)
	}
}

func TestProbeFakeTLSAlertIsAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}) // TLS alert
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	sec := "ee" + "00000000000000000000000000000000" + "74656c656772616d2e6f7267"
	ok, detail := mtproxy.Probe(mtproxy.ProbeTarget{Kind: "mtproto", Server: "127.0.0.1", Port: p, Secret: sec}, 2*time.Second)
	if !ok {
		t.Fatal(detail)
	}
}

func TestProbeSOCKS5(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveMockSOCKS(t, ln)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	ok, detail := mtproxy.Probe(mtproxy.ProbeTarget{
		Kind: "socks5", Server: "127.0.0.1", Port: p, Username: "u", Password: "p",
	}, 2*time.Second)
	if !ok {
		t.Fatal(detail)
	}
}

func serveMockSOCKS(t *testing.T, ln net.Listener) {
	t.Helper()
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	buf := make([]byte, 3)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 2})
	auth := make([]byte, 2)
	if _, err := io.ReadFull(c, auth); err != nil {
		return
	}
	u := make([]byte, int(auth[1]))
	if _, err := io.ReadFull(c, u); err != nil {
		return
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return
	}
	pw := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(c, pw); err != nil {
		return
	}
	_, _ = c.Write([]byte{1, 0})
	req := make([]byte, 4)
	_, _ = io.ReadFull(c, req)
	dlen := make([]byte, 1)
	_, _ = io.ReadFull(c, dlen)
	_, _ = io.ReadFull(c, make([]byte, int(dlen[0])+2))
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
}

func TestRegistryFailover(t *testing.T) {
	reg := &mtproxy.Registry{
		Probe: func(tgt mtproxy.ProbeTarget, timeout time.Duration) (bool, string) {
			return tgt.Server == "good.example", "mock"
		},
	}
	bad := &mtproxy.Proxy{Name: "bad", Server: "bad.example", Port: 443, Secret: "dd00", Kind: "mtproto", Enabled: true}
	good := &mtproxy.Proxy{Name: "good", Server: "good.example", Port: 443, Secret: "dd00", Kind: "mtproto", Enabled: true}
	reg.Proxies = []*mtproxy.Proxy{bad, good}
	reg.Groups = []*mtproxy.Group{{
		Key: "mtproto:dd00", Kind: "mtproto", Secret: "dd00",
		ListenHost: "127.0.0.1", ListenPort: 1443,
		Proxies: []*mtproxy.Proxy{bad, good},
	}}
	cfg := &config.Config{}
	cfg.Checker.Health.FailThreshold = 1
	cfg.Checker.Health.OKThreshold = 1
	cfg.Checker.Health.TimeoutSec = 1
	cfg.Checker.Health.Concurrency = 2
	reg.CheckAll(cfg)
	if reg.Groups[0].Current == nil || reg.Groups[0].Current.Name != "good" {
		t.Fatalf("current %+v", reg.Groups[0].Current)
	}
}
