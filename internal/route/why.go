package route

import (
	"fmt"
	"net"
	"strings"

	"routeproxy/internal/config"
	"routeproxy/internal/generate"
	"routeproxy/internal/idna"
)

type Decision struct {
	Host     string
	Outbound string
	Rule     string
}

func Why(cfg *config.Config, host string) Decision {
	res, err := generate.Build(cfg)
	if err != nil {
		return Decision{Host: host, Outbound: "error", Rule: err.Error()}
	}
	h := strings.TrimSpace(strings.ToLower(host))
	h = strings.TrimSuffix(h, ".")
	ascii, err := idna.ToASCII(h)
	if err == nil && ascii != "" {
		h = ascii
	}

	if ip := net.ParseIP(h); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return Decision{Host: host, Outbound: "direct", Rule: "ip_is_private"}
		}
	}

	for _, ex := range cfg.Routing.Exceptions {
		target := ex.Target()
		if target == "" {
			continue
		}
		if ex.MatchDomain != "" && strings.EqualFold(ex.MatchDomain, h) {
			return Decision{Host: host, Outbound: mapGroup(res, target), Rule: "exception domain " + ex.MatchDomain}
		}
		if ex.MatchDomainSuffix != "" && hasSuffix(h, ex.MatchDomainSuffix) {
			return Decision{Host: host, Outbound: mapGroup(res, target), Rule: "exception suffix " + ex.MatchDomainSuffix}
		}
		if ex.MatchCIDR != "" && ipInCIDR(h, ex.MatchCIDR) {
			return Decision{Host: host, Outbound: mapGroup(res, target), Rule: "exception cidr " + ex.MatchCIDR}
		}
	}

	if forceAuto(h) {
		return Decision{Host: host, Outbound: res.AutoTag, Rule: "force-auto geosite (google/youtube/instagram/twitter/facebook/discord)"}
	}
	if isTelegram(h) {
		return Decision{Host: host, Outbound: res.TGTag, Rule: "geosite-telegram"}
	}
	if isRUSuffix(h) {
		return Decision{Host: host, Outbound: res.RUTag, Rule: "domain_suffix .ru / .рф / .su"}
	}
	if isRUGeosite(h) {
		return Decision{Host: host, Outbound: res.RUTag, Rule: "geosite-category-ru"}
	}
	return Decision{Host: host, Outbound: res.AutoTag, Rule: "final"}
}

func (d Decision) String() string {
	return fmt.Sprintf("%s → %s (%s)", d.Host, d.Outbound, d.Rule)
}

func mapGroup(res *generate.Result, name string) string {
	switch strings.ToLower(name) {
	case "direct":
		return "direct"
	case "ru":
		return res.RUTag
	case "telegram":
		return res.TGTag
	case "auto", "proxy", "default":
		return res.AutoTag
	default:
		return name
	}
}

func hasSuffix(host, suffix string) bool {
	s := strings.ToLower(strings.TrimSpace(suffix))
	if !strings.HasPrefix(s, ".") {
		s = "." + s
	}
	ascii, err := idna.ToASCII(strings.TrimPrefix(s, "."))
	if err == nil && ascii != "" {
		s = "." + strings.ToLower(ascii)
	}
	return host == strings.TrimPrefix(s, ".") || strings.HasSuffix(host, s)
}

func isRUSuffix(host string) bool {
	for _, s := range []string{".ru", ".xn--p1ai", ".su"} {
		if hasSuffix(host, s) {
			return true
		}
	}
	// Unicode .рф already converted via idna on host; also match raw
	if strings.HasSuffix(host, ".рф") || host == "рф" {
		return true
	}
	return false
}

func forceAuto(host string) bool {
	for _, s := range []string{
		"google.com", "youtube.com", "youtu.be", "gstatic.com", "googleapis.com",
		"instagram.com", "cdninstagram.com", "twitter.com", "x.com", "t.co",
		"facebook.com", "fbcdn.net", "discord.com", "discord.gg",
	} {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func isTelegram(host string) bool {
	for _, s := range []string{"telegram.org", "t.me", "tdesktop.com", "telegra.ph", "telesco.pe"} {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func isRUGeosite(host string) bool {
	for _, s := range []string{"vk.com", "vk.ru", "yandex.com", "yandex.net", "mail.ru", "ok.ru", "wildberries.ru"} {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func ipInCIDR(host, cidr string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}
