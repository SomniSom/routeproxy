package generate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"routeproxy/internal/config"
	"routeproxy/internal/hostcheck"
)

const (
	geositeBase = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/"
	geoipBase   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/"
)

var ruSuffixes = []string{".ru", ".xn--p1ai", ".рф", ".su"}

var forceAutoSites = []string{
	"geosite-google",
	"geosite-youtube",
	"geosite-instagram",
	"geosite-twitter",
	"geosite-facebook",
	"geosite-discord",
}

type Result struct {
	Config   map[string]any
	JSON     []byte
	AutoTag  string
	RUTag    string
	TGTag    string
	Warnings []string
}

const DefaultSFAPath = "generated/sfa.json"

func Build(cfg *config.Config) (*Result, error) {
	return build(cfg, false)
}

func BuildSFA(cfg *config.Config) (*Result, error) {
	return build(cfg, true)
}

func build(cfg *config.Config, sfa bool) (*Result, error) {
	usable, skipWarn := usableProxies(cfg)
	if sfa {
		var extra []string
		usable, extra = prepareSFAProxies(usable)
		skipWarn = append(skipWarn, extra...)
	}
	work := *cfg
	work.Proxies = usable

	autoMembers := namesWithPurpose(&work, "auto")
	tgMembers := namesWithPurpose(&work, "telegram")
	ruMembers := namesWithPurpose(&work, "ru")

	autoTag := "auto"
	if len(autoMembers) == 0 {
		autoTag = "direct"
	}
	ruTag := "direct"
	if cfg.Routing.RU == "direct" {
		ruTag = "direct"
	} else if len(ruMembers) > 0 {
		ruTag = "ru"
	}
	tgTag := autoTag
	if len(tgMembers) > 0 {
		tgTag = "telegram"
	}

	outbounds := []any{
		map[string]any{
			"type":            "direct",
			"tag":             "direct",
			"domain_resolver": resolverIPv4(),
		},
	}
	endpoints := []any{}

	for _, p := range work.Proxies {
		if !p.IsEnabled() {
			continue
		}
		ob, ep, err := proxyOutbound(p)
		if err != nil {
			return nil, err
		}
		if ep != nil {
			endpoints = append(endpoints, ep)
			continue
		}
		if ob != nil {
			outbounds = append(outbounds, ob)
		}
	}

	if len(autoMembers) > 0 {
		outbounds = append(outbounds, urltest("auto", autoMembers, "https://www.gstatic.com/generate_204"))
	}
	if len(tgMembers) > 0 {
		outbounds = append(outbounds, urltest("telegram", tgMembers, "https://www.gstatic.com/generate_204"))
	}
	if len(ruMembers) > 0 && cfg.Routing.RU != "direct" {
		outbounds = append(outbounds, urltest("ru", ruMembers, "https://ya.ru"))
	}

	var listenHost string
	var listenPort int
	if !sfa {
		var err error
		listenHost, listenPort, err = cfg.ListenHostPort()
		if err != nil {
			return nil, err
		}
	}

	ruleSets := remoteRuleSets(autoTag)
	rules := routeRules(cfg, ruTag, tgTag, autoTag)

	dns := map[string]any{
		"servers": []any{
			map[string]any{"type": "udp", "tag": "dns-ru", "server": "77.88.8.8"},
			map[string]any{"type": "udp", "tag": "dns-bootstrap", "server": "1.1.1.1"},
			map[string]any{
				"type":            "https",
				"tag":             "dns-remote",
				"server":          "1.1.1.1",
				"detour":          autoTag,
				"domain_resolver": resolverIPv4(),
			},
		},
		"rules": dnsRules(&work),
		"final": "dns-remote",
	}

	inbounds := []any{mixedInbound(listenHost, listenPort, cfg.SetSystemProxy)}
	cachePath := filepath.ToSlash(filepath.Join(cfg.CacheDir, "cache.db"))
	if sfa {
		inbounds = []any{sfaTunInbound()}
		cachePath = "cache.db"
	}

	doc := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules":                   rules,
			"rule_set":                ruleSets,
			"final":                   autoTag,
			"default_domain_resolver": resolverIPv4(),
			"auto_detect_interface":   true,
		},
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled": true,
				"path":    cachePath,
			},
		},
	}
	if len(endpoints) > 0 {
		doc["endpoints"] = endpoints
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	warnings := skipWarn
	if !sfa {
		warnings = append(warnings, hostcheck.WireGuardWarnings(&work)...)
	}
	return &Result{
		Config:   doc,
		JSON:     raw,
		AutoTag:  autoTag,
		RUTag:    ruTag,
		TGTag:    tgTag,
		Warnings: warnings,
	}, nil
}

func mixedInbound(host string, port int, setSystemProxy bool) map[string]any {
	return map[string]any{
		"type":             "mixed",
		"tag":              "mixed-in",
		"listen":           host,
		"listen_port":      port,
		"set_system_proxy": setSystemProxy,
		"tcp_fast_open":    true,
		"udp_fragment":     true,
	}
}

func sfaTunInbound() map[string]any {
	return map[string]any{
		"type":       "tun",
		"tag":        "tun-in",
		"address":    []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
		"mtu":        9000,
		"auto_route": true,
		"stack":      "mixed",
		"exclude_package": []string{
			"com.android.captiveportallogin",
		},
	}
}

func prepareSFAProxies(in []config.Proxy) ([]config.Proxy, []string) {
	var out []config.Proxy
	var warns []string
	for _, p := range in {
		if p.Type != "ssh" {
			out = append(out, p)
			continue
		}
		if p.PrivateKeyPath != "" {
			raw, err := os.ReadFile(p.PrivateKeyPath)
			if err != nil {
				warns = append(warns, fmt.Sprintf("skip ssh %s: cannot read private_key_path: %v", p.Name, err))
				continue
			}
			p.PrivateKey = strings.TrimSpace(string(raw))
			p.PrivateKeyPath = ""
		}
		if p.PrivateKey == "" && p.Password == "" {
			warns = append(warns, fmt.Sprintf("skip ssh %s: SFA needs an inlined private_key or password", p.Name))
			continue
		}
		out = append(out, p)
	}
	return out, warns
}

func resolverIPv4() map[string]any {
	return map[string]any{"server": "dns-bootstrap", "strategy": "ipv4_only"}
}

func usableProxies(cfg *config.Config) ([]config.Proxy, []string) {
	var out []config.Proxy
	var warns []string
	for _, p := range cfg.Proxies {
		if !p.IsEnabled() {
			continue
		}
		if p.Type == "wireguard" && p.ConfigFile != "" {
			if _, err := os.Stat(p.ConfigFile); err != nil {
				warns = append(warns, fmt.Sprintf("skip wireguard %s: %v", p.Name, err))
				continue
			}
		}
		out = append(out, p)
	}
	return out, warns
}

func dnsRules(cfg *config.Config) []any {
	rules := []any{}
	if names := cfg.DNS.DirectNames; len(names) > 0 {
		rules = append(rules, map[string]any{"domain": names, "server": "dns-bootstrap"})
	}
	rules = append(rules,
		map[string]any{"domain_suffix": ruSuffixes, "server": "dns-ru"},
		map[string]any{"rule_set": []string{"geosite-category-ru"}, "server": "dns-ru"},
	)
	return rules
}

func Write(cfg *config.Config) (*Result, error) {
	res, err := Build(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.GeneratedPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.GeneratedPath, res.JSON, 0o644); err != nil {
		return nil, err
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warn:", w)
	}
	return res, nil
}

func WriteSFA(cfg *config.Config, path string) (*Result, error) {
	if path == "" {
		path = DefaultSFAPath
	}
	res, err := BuildSFA(cfg)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(path, res.JSON, 0o600); err != nil {
		return nil, err
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warn:", w)
	}
	return res, nil
}

func namesWithPurpose(cfg *config.Config, purpose string) []string {
	var out []string
	for _, p := range cfg.Proxies {
		if p.IsEnabled() && p.HasPurpose(purpose) {
			out = append(out, p.Name)
		}
	}
	return out
}

func urltest(tag string, members []string, testURL string) map[string]any {
	return map[string]any{
		"type":      "urltest",
		"tag":       tag,
		"outbounds": members,
		"url":       testURL,
		"interval":  "3m",
		"tolerance": 50,
	}
}

func proxyOutbound(p config.Proxy) (ob map[string]any, ep map[string]any, err error) {
	switch p.Type {
	case "vless":
		m := map[string]any{
			"type":            "vless",
			"tag":             p.Name,
			"server":          p.Server,
			"server_port":     p.Port,
			"uuid":            p.UUID,
			"packet_encoding": "xudp",
			"domain_resolver": resolverIPv4(),
		}
		if p.Flow != "" {
			m["flow"] = p.Flow
		}
		if tls := tlsObject(p); tls != nil {
			m["tls"] = tls
		}
		if tr := transportObject(p); tr != nil {
			m["transport"] = tr
		}
		return m, nil, nil
	case "trojan":
		m := map[string]any{
			"type":            "trojan",
			"tag":             p.Name,
			"server":          p.Server,
			"server_port":     p.Port,
			"password":        p.Password,
			"domain_resolver": resolverIPv4(),
		}
		if tls := tlsObject(p); tls != nil {
			m["tls"] = tls
		}
		if tr := transportObject(p); tr != nil {
			m["transport"] = tr
		}
		return m, nil, nil
	case "socks":
		port := p.Port
		if port == 0 {
			port = 1080
		}
		m := map[string]any{
			"type":            "socks",
			"tag":             p.Name,
			"server":          p.Server,
			"server_port":     port,
			"version":         "5",
			"domain_resolver": resolverIPv4(),
		}
		if p.Username != "" {
			m["username"] = p.Username
			m["password"] = p.Password
		}
		return m, nil, nil
	case "http":
		m := map[string]any{
			"type":            "http",
			"tag":             p.Name,
			"server":          p.Server,
			"server_port":     p.Port,
			"domain_resolver": resolverIPv4(),
		}
		if p.Username != "" {
			m["username"] = p.Username
			m["password"] = p.Password
		}
		return m, nil, nil
	case "ssh":
		port := p.Port
		if port == 0 {
			port = 22
		}
		m := map[string]any{
			"type":            "ssh",
			"tag":             p.Name,
			"server":          p.Server,
			"server_port":     port,
			"user":            p.User,
			"domain_resolver": resolverIPv4(),
		}
		if p.PrivateKey != "" {
			m["private_key"] = p.PrivateKey
		}
		if p.PrivateKeyPath != "" {
			m["private_key_path"] = p.PrivateKeyPath
		}
		if p.Password != "" {
			m["password"] = p.Password
		}
		return m, nil, nil
	case "wireguard":
		ep, err := wireguardEndpoint(p)
		return nil, ep, err
	default:
		return nil, nil, fmt.Errorf("unsupported type %s", p.Type)
	}
}

func tlsObject(p config.Proxy) map[string]any {
	if p.TLS == nil {
		return map[string]any{"enabled": true, "server_name": p.Server}
	}
	tls := map[string]any{
		"enabled":     true,
		"server_name": p.TLS.ServerName,
		"insecure":    p.TLS.Insecure,
	}
	if p.TLS.ServerName == "" {
		tls["server_name"] = p.Server
	}
	fp := p.TLS.UTLS
	if fp == "" {
		fp = "chrome"
	}
	tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	if p.TLS.Reality {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": p.TLS.PublicKey,
			"short_id":   p.TLS.ShortID,
		}
	}
	return tls
}

func transportObject(p config.Proxy) map[string]any {
	if p.Transport == nil || p.Transport.Type == "" {
		return nil
	}
	tr := map[string]any{"type": p.Transport.Type}
	if p.Transport.ServiceName != "" {
		tr["service_name"] = p.Transport.ServiceName
	}
	if p.Transport.Type == "grpc" {
		tr["idle_timeout"] = "60s"
	}
	return tr
}

func wireguardEndpoint(p config.Proxy) (map[string]any, error) {
	iface := p.Interface
	if iface == "" {
		iface = p.Name
	}
	priv, pub, psk, endpoint, addrs, mtu := p.PrivateKey, p.PeerPublicKey, p.PreSharedKey, p.Endpoint, p.LocalAddress, p.MTU
	if p.ConfigFile != "" {
		parsed, err := ParseWGQuick(p.ConfigFile)
		if err != nil {
			return nil, err
		}
		if priv == "" {
			priv = parsed.PrivateKey
		}
		if pub == "" {
			pub = parsed.PublicKey
		}
		if psk == "" {
			psk = parsed.PresharedKey
		}
		if endpoint == "" {
			endpoint = parsed.Endpoint
		}
		if len(addrs) == 0 {
			addrs = parsed.Address
		}
		if mtu == 0 {
			mtu = parsed.MTU
		}
		if parsed.Interface != "" && p.Interface == "" {
			iface = parsed.Interface
		}
	}
	host, port := splitEndpoint(endpoint)
	peer := map[string]any{
		"address":     host,
		"port":        port,
		"public_key":  pub,
		"allowed_ips": []string{"0.0.0.0/0", "::/0"},
	}
	if psk != "" {
		peer["pre_shared_key"] = psk
	}
	ep := map[string]any{
		"type":        "wireguard",
		"tag":         p.Name,
		"system":      false,
		"name":        iface,
		"address":     addrs,
		"private_key": priv,
		"peers":       []any{peer},
	}
	if mtu > 0 {
		ep["mtu"] = mtu
	}
	return ep, nil
}

func splitEndpoint(ep string) (string, int) {
	parts := strings.Split(ep, ":")
	if len(parts) != 2 {
		return ep, 51820
	}
	var port int
	fmt.Sscanf(parts[1], "%d", &port)
	if port == 0 {
		port = 51820
	}
	return parts[0], port
}

func routeRules(cfg *config.Config, ruTag, tgTag, autoTag string) []any {
	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	}
	for _, ex := range cfg.Routing.Exceptions {
		target := resolveGroup(cfg, ex.Target(), ruTag, tgTag, autoTag)
		r := map[string]any{"outbound": target}
		if ex.MatchDomainSuffix != "" {
			r["domain_suffix"] = ex.MatchDomainSuffix
		}
		if ex.MatchDomain != "" {
			r["domain"] = ex.MatchDomain
		}
		if ex.MatchCIDR != "" {
			r["ip_cidr"] = ex.MatchCIDR
		}
		rules = append(rules, r)
	}
	rules = append(rules,
		map[string]any{"ip_is_private": true, "outbound": "direct"},
		map[string]any{"rule_set": forceAutoSites, "outbound": autoTag},
		map[string]any{"rule_set": []string{"geosite-telegram"}, "outbound": tgTag},
		map[string]any{"domain_suffix": ruSuffixes, "outbound": ruTag},
		map[string]any{"rule_set": []string{"geosite-category-ru", "geoip-ru"}, "outbound": ruTag},
	)
	return rules
}

func resolveGroup(cfg *config.Config, name, ruTag, tgTag, autoTag string) string {
	switch strings.ToLower(name) {
	case "direct":
		return "direct"
	case "ru":
		return ruTag
	case "telegram":
		return tgTag
	case "auto", "proxy", "default":
		return autoTag
	default:
		return name
	}
}

func remoteRuleSets(autoTag string) []any {
	type rs struct {
		tag, url, detour string
	}
	items := []rs{
		{"geosite-category-ru", geositeBase + "geosite-category-ru.srs", autoTag},
		{"geoip-ru", geoipBase + "geoip-ru.srs", autoTag},
		{"geosite-telegram", geositeBase + "geosite-telegram.srs", autoTag},
	}
	for _, tag := range forceAutoSites {
		items = append(items, rs{tag, geositeBase + tag + ".srs", autoTag})
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"tag":             it.tag,
			"type":            "remote",
			"format":          "binary",
			"url":             it.url,
			"download_detour": it.detour,
		})
	}
	return out
}
