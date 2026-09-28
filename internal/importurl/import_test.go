package importurl_test

import (
	"net/url"
	"testing"

	"routeproxy/internal/importurl"
)

func TestParseSOCKS(t *testing.T) {
	p, err := importurl.Parse("tg://socks?server=1.2.3.4&port=1080&user=u&pass=p")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != importurl.KindSOCKS || p.Server != "1.2.3.4" || p.Port != 1080 || p.Username != "u" || p.Password != "p" {
		t.Fatalf("%+v", p)
	}
}

func TestParseTMeSOCKS(t *testing.T) {
	p, err := importurl.Parse("https://t.me/socks?server=1.2.3.4&port=9050&user=n%40me&pass=s%20ec")
	if err != nil {
		t.Fatal(err)
	}
	if p.Username != "n@me" || p.Password != "s ec" || p.Port != 9050 {
		t.Fatalf("%+v", p)
	}
}

func TestParseMTProto(t *testing.T) {
	raw := "https://t.me/proxy?server=8.8.8.8&port=443&secret=ee0000000000000000000000000000000074656c656772616d2e6f7267"
	p, err := importurl.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != importurl.KindMTProto || p.Secret[:2] != "ee" || p.Port != 443 {
		t.Fatalf("%+v", p)
	}
	u := importurl.MTProtoURL(p.Server, p.Port, p.Secret)
	if _, err := url.Parse(u); err != nil {
		t.Fatal(err)
	}
}

func TestParseVLESS(t *testing.T) {
	p, err := importurl.Parse("vless://11111111-1111-1111-1111-111111111111@ex.com:443?security=reality&pbk=abc&sid=dd&sni=ex.com&flow=xtls-rprx-vision")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != importurl.KindVLESS || p.UUID == "" || !p.TLS.Reality || p.TLS.PublicKey != "abc" {
		t.Fatalf("%+v", p)
	}
}

func TestLocalSOCKS(t *testing.T) {
	u := importurl.LocalSOCKSURL("0.0.0.0:1080")
	if u != "tg://socks?server=127.0.0.1&port=1080" {
		t.Fatal(u)
	}
}

func TestParseSOCKS5URL(t *testing.T) {
	p, err := importurl.Parse("socks5://u:p@1.2.3.4:1080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != importurl.KindSOCKS || p.Username != "u" || p.Password != "p" || p.Port != 1080 {
		t.Fatalf("%+v", p)
	}
}

func TestParseTrojan(t *testing.T) {
	p, err := importurl.Parse("trojan://secret@ex.com:443?sni=ex.com")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != importurl.KindTrojan || p.Password != "secret" || p.TLS.ServerName != "ex.com" {
		t.Fatalf("%+v", p)
	}
}

func TestParseEmptyAndUnknown(t *testing.T) {
	if _, err := importurl.Parse(""); err == nil {
		t.Fatal("empty")
	}
	if _, err := importurl.Parse("http://example.com"); err == nil {
		t.Fatal("unknown scheme")
	}
}

func TestParseTGProxy(t *testing.T) {
	p, err := importurl.Parse("tg://proxy?server=9.9.9.9&port=443&secret=dd00")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != importurl.KindMTProto || p.Server != "9.9.9.9" {
		t.Fatalf("%+v", p)
	}
}
