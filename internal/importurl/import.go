package importurl

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Kind string

const (
	KindSOCKS   Kind = "socks"
	KindMTProto Kind = "mtproto"
	KindVLESS   Kind = "vless"
	KindTrojan  Kind = "trojan"
)

type Parsed struct {
	Kind     Kind
	Type     string
	Server   string
	Port     int
	Username string
	Password string
	Secret   string
	UUID     string
	Flow     string
	TLS      *TLS
	Raw      string
}

type TLS struct {
	ServerName string
	Reality    bool
	PublicKey  string
	ShortID    string
}

func Parse(raw string) (*Parsed, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty url")
	}
	switch {
	case strings.HasPrefix(raw, "tg://socks"), strings.Contains(raw, "t.me/socks"):
		return parseTelegramQuery(raw, KindSOCKS)
	case strings.HasPrefix(raw, "tg://proxy"), strings.Contains(raw, "t.me/proxy"):
		return parseTelegramQuery(raw, KindMTProto)
	case strings.HasPrefix(raw, "vless://"):
		return parseVLESS(raw)
	case strings.HasPrefix(raw, "trojan://"):
		return parseTrojan(raw)
	case strings.HasPrefix(raw, "socks5://"), strings.HasPrefix(raw, "socks://"):
		return parseSOCKS(raw)
	default:
		return nil, fmt.Errorf("unsupported url scheme")
	}
}

func parseTelegramQuery(raw string, kind Kind) (*Parsed, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if u.Host == "socks" || u.Host == "proxy" {
		// tg://socks?server= already in RawQuery
	}
	server := first(q, "server", "address")
	portStr := first(q, "port")
	if server == "" {
		return nil, fmt.Errorf("missing server")
	}
	port := 443
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("port: %w", err)
		}
	}
	out := &Parsed{
		Kind:     kind,
		Server:   server,
		Port:     port,
		Username: first(q, "user", "username"),
		Password: first(q, "pass", "password"),
		Secret:   strings.ToLower(strings.TrimSpace(first(q, "secret"))),
		Raw:      raw,
	}
	if kind == KindSOCKS {
		out.Type = "socks"
		if out.Port == 443 && portStr == "" {
			out.Port = 1080
		}
	} else {
		out.Type = "mtproto"
	}
	return out, nil
}

func parseVLESS(raw string) (*Parsed, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host, portStr, err := splitHostPort(u.Host, "443")
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	q := u.Query()
	p := &Parsed{
		Kind:   KindVLESS,
		Type:   "vless",
		Server: host,
		Port:   port,
		UUID:   u.User.Username(),
		Flow:   q.Get("flow"),
		Raw:    raw,
		TLS:    &TLS{ServerName: first(q, "sni", "serverName", "host")},
	}
	if q.Get("security") == "reality" || q.Get("pbk") != "" {
		p.TLS.Reality = true
		p.TLS.PublicKey = first(q, "pbk", "publicKey")
		p.TLS.ShortID = first(q, "sid", "shortId")
	}
	if p.TLS.ServerName == "" {
		p.TLS.ServerName = host
	}
	return p, nil
}

func parseTrojan(raw string) (*Parsed, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host, portStr, err := splitHostPort(u.Host, "443")
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	pass, _ := u.User.Password()
	if pass == "" {
		pass = u.User.Username()
	}
	q := u.Query()
	return &Parsed{
		Kind:     KindTrojan,
		Type:     "trojan",
		Server:   host,
		Port:     port,
		Password: pass,
		Raw:      raw,
		TLS:      &TLS{ServerName: first(q, "sni", "peer")},
	}, nil
}

func parseSOCKS(raw string) (*Parsed, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host, portStr, err := splitHostPort(u.Host, "1080")
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	pass, _ := u.User.Password()
	return &Parsed{
		Kind:     KindSOCKS,
		Type:     "socks",
		Server:   host,
		Port:     port,
		Username: u.User.Username(),
		Password: pass,
		Raw:      raw,
	}, nil
}

func splitHostPort(host, defPort string) (string, string, error) {
	if host == "" {
		return "", "", fmt.Errorf("missing host")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return host, defPort, nil
	}
	return net.SplitHostPort(host)
}

func first(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func LocalSOCKSURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "tg://socks?server=127.0.0.1&port=1080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("tg://socks?server=%s&port=%s", host, port)
}

func MTProtoURL(server string, port int, secret string) string {
	return fmt.Sprintf("https://t.me/proxy?server=%s&port=%d&secret=%s", url.QueryEscape(server), port, url.QueryEscape(secret))
}
