package mtproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type ProbeTarget struct {
	Kind     string // mtproto | socks5
	Server   string
	Port     int
	Secret   string
	Username string
	Password string
}

type ProbeFunc func(t ProbeTarget, timeout time.Duration) (ok bool, detail string)

func Probe(t ProbeTarget, timeout time.Duration) (bool, string) {
	if t.Kind == "socks5" {
		return probeSOCKS5(t, timeout)
	}
	meta := SecretMetaFrom(t.Secret)
	if meta.Kind == SecretEE || meta.Kind == SecretDD {
		return probeFakeTLS(t.Server, t.Port, timeout, meta.SNI)
	}
	return probeTCP(t.Server, t.Port, timeout)
}

func probeTCP(host string, port int, timeout time.Duration) (bool, string) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		return false, "tcp:" + err.Error()
	}
	if err := c.Close(); err != nil {
		return false, "close:" + err.Error()
	}
	return true, "tcp"
}

func closeResult(c io.Closer, ok bool, detail string) (bool, string) {
	if err := c.Close(); err != nil {
		if !ok {
			return false, detail + "; close:" + err.Error()
		}
		return false, "close:" + err.Error()
	}
	return ok, detail
}

func probeFakeTLS(host string, port int, timeout time.Duration, sni string) (ok bool, detail string) {
	d := net.Dialer{Timeout: timeout}
	raw, err := d.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return false, "tcp:" + err.Error()
	}
	defer func() { ok, detail = closeResult(raw, ok, detail) }()
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, "deadline:" + err.Error()
	}
	if sni == "" {
		sni = "telegram.org"
	}
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	conn := tls.Client(raw, cfg)
	err = conn.Handshake()
	if err == nil {
		if err := conn.Close(); err != nil {
			return false, "close:" + err.Error()
		}
		return true, "tls-complete"
	}
	if _, ok := errors.AsType[tls.RecordHeaderError](err); ok {
		return true, "tls-alert:" + err.Error()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false, "tls:" + err.Error()
	}
	return true, "tls-alert:" + err.Error()
}

func probeSOCKS5(t ProbeTarget, timeout time.Duration) (ok bool, detail string) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(t.Server, fmt.Sprint(t.Port)), timeout)
	if err != nil {
		return false, "tcp:" + err.Error()
	}
	defer func() { ok, detail = closeResult(c, ok, detail) }()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, "deadline:" + err.Error()
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return false, "socks:" + err.Error()
	}
	hello := make([]byte, 2)
	if _, err := io.ReadFull(c, hello); err != nil {
		return false, "socks:" + err.Error()
	}
	if hello[0] != 5 || hello[1] != 2 {
		return false, fmt.Sprintf("socks-method:%x", hello)
	}
	user := []byte(t.Username)
	pass := []byte(t.Password)
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := c.Write(auth); err != nil {
		return false, "socks:" + err.Error()
	}
	arep := make([]byte, 2)
	if _, err := io.ReadFull(c, arep); err != nil {
		return false, "socks:" + err.Error()
	}
	if arep[0] != 1 || arep[1] != 0 {
		return false, "socks-auth-fail"
	}
	dest := []byte("api.telegram.org")
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(dest))}
	req = append(req, dest...)
	req = append(req, 0x01, 0xbb) // 443
	if _, err := c.Write(req); err != nil {
		return false, "socks:" + err.Error()
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return false, "socks:" + err.Error()
	}
	if hdr[0] != 5 || hdr[1] != 0 {
		return false, fmt.Sprintf("socks-connect:%d", hdr[1])
	}
	switch hdr[3] {
	case 1:
		if _, err := io.ReadFull(c, make([]byte, 6)); err != nil {
			return false, "socks:" + err.Error()
		}
	case 3:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			return false, "socks:" + err.Error()
		}
		if _, err := io.ReadFull(c, make([]byte, int(ln[0])+2)); err != nil {
			return false, "socks:" + err.Error()
		}
	case 4:
		if _, err := io.ReadFull(c, make([]byte, 18)); err != nil {
			return false, "socks:" + err.Error()
		}
	}
	return true, "socks5-telegram"
}
