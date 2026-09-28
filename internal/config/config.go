package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"routeproxy/internal/importurl"
)

type Config struct {
	Listen          string        `yaml:"listen"`
	SetSystemProxy  bool          `yaml:"set_system_proxy"`
	GeneratedPath   string        `yaml:"generated_path"`
	CacheDir        string        `yaml:"cache_dir"`
	Checker         CheckerConfig `yaml:"checker"`
	Proxies         []Proxy       `yaml:"proxies"`
	TelegramMTProto []MTProto     `yaml:"telegram_mtproto"`
	Routing         Routing       `yaml:"routing"`
	Alerts          Alerts        `yaml:"alerts"`
	BotAPI          BotAPI        `yaml:"bot_api"`
	Apply           Apply         `yaml:"apply"`
	DNS             DNS           `yaml:"dns"`
}

type DNS struct {
	DirectNames []string `yaml:"direct_names,omitempty"`
}

type CheckerConfig struct {
	Listen     string `yaml:"listen"`
	StatusAddr string `yaml:"status_addr"`
	Health     Health `yaml:"health"`
}

type Health struct {
	IntervalSec   float64 `yaml:"interval_sec"`
	TimeoutSec    float64 `yaml:"timeout_sec"`
	FailThreshold int     `yaml:"fail_threshold"`
	OKThreshold   int     `yaml:"ok_threshold"`
	Concurrency   int     `yaml:"concurrency"`
}

type Proxy struct {
	Name           string     `yaml:"name"`
	Purpose        []string   `yaml:"purpose"`
	Type           string     `yaml:"type"`
	URL            string     `yaml:"url,omitempty"`
	Server         string     `yaml:"server,omitempty"`
	Port           int        `yaml:"port,omitempty"`
	UUID           string     `yaml:"uuid,omitempty"`
	Flow           string     `yaml:"flow,omitempty"`
	Password       string     `yaml:"password,omitempty"`
	User           string     `yaml:"user,omitempty"`
	Username       string     `yaml:"username,omitempty"`
	PrivateKeyPath string     `yaml:"private_key_path,omitempty"`
	ConfigFile     string     `yaml:"config_file,omitempty"`
	Interface      string     `yaml:"interface,omitempty"`
	PrivateKey     string     `yaml:"private_key,omitempty"`
	PeerPublicKey  string     `yaml:"peer_public_key,omitempty"`
	PreSharedKey   string     `yaml:"pre_shared_key,omitempty"`
	LocalAddress   []string   `yaml:"local_address,omitempty"`
	Endpoint       string     `yaml:"endpoint,omitempty"`
	MTU            int        `yaml:"mtu,omitempty"`
	TLS            *TLS       `yaml:"tls,omitempty"`
	Transport      *Transport `yaml:"transport,omitempty"`
	Enabled        *bool      `yaml:"enabled,omitempty"`
	Reserve        bool       `yaml:"reserve,omitempty"`
}

type Transport struct {
	Type        string `yaml:"type,omitempty"`
	ServiceName string `yaml:"service_name,omitempty"`
}

type TLS struct {
	ServerName string `yaml:"server_name,omitempty"`
	Reality    bool   `yaml:"reality,omitempty"`
	PublicKey  string `yaml:"public_key,omitempty"`
	ShortID    string `yaml:"short_id,omitempty"`
	Insecure   bool   `yaml:"insecure,omitempty"`
	UTLS       string `yaml:"utls,omitempty"`
}

type MTProto struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url,omitempty"`
	Server  string `yaml:"server,omitempty"`
	Port    int    `yaml:"port,omitempty"`
	Secret  string `yaml:"secret,omitempty"`
	Enabled *bool  `yaml:"enabled,omitempty"`
	Reserve bool   `yaml:"reserve,omitempty"`
}

type Routing struct {
	Private    string      `yaml:"private"`
	RU         string      `yaml:"ru"`
	Telegram   string      `yaml:"telegram"`
	Default    string      `yaml:"default"`
	Exceptions []Exception `yaml:"exceptions"`
}

type Exception struct {
	MatchDomainSuffix string `yaml:"match_domain_suffix,omitempty"`
	MatchDomain       string `yaml:"match_domain,omitempty"`
	MatchCIDR         string `yaml:"match_cidr,omitempty"`
	Outbound          string `yaml:"outbound,omitempty"`
	Force             string `yaml:"force,omitempty"`
}

func (e Exception) Target() string {
	if e.Force != "" {
		return e.Force
	}
	return e.Outbound
}

type Alerts struct {
	Telegram            TelegramAlert `yaml:"telegram"`
	SMTP                SMTPAlert     `yaml:"smtp"`
	ForbidDirect        bool          `yaml:"forbid_direct"`
	MTProtoDeadFor      string        `yaml:"mtproto_dead_for"`
	MTProtoAliveFor     string        `yaml:"mtproto_alive_for"`
	WarnWhenHealthyLeft int           `yaml:"warn_when_healthy_left"`
}

type TelegramAlert struct {
	BotToken string `yaml:"bot_token"`
	ChatID   int64  `yaml:"chat_id"`
	Via      string `yaml:"via"`
}

type SMTPAlert struct {
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
	Via      string   `yaml:"via"`
}

type BotAPI struct {
	EnvFile        string   `yaml:"env_file"`
	CheckerHost    string   `yaml:"checker_host"`
	RestartCommand []string `yaml:"restart_command"`
}

type Apply struct {
	Commands [][]string `yaml:"commands"`
}

func DefaultPath() string {
	if p := os.Getenv("ROUTEPROXY_CONFIG"); p != "" {
		return p
	}
	for _, p := range []string{"config.yaml", "/etc/routeproxy/config.yaml"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "config.yaml"
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:1080"
	}
	if c.GeneratedPath == "" {
		c.GeneratedPath = "generated/config.json"
	}
	if c.CacheDir == "" {
		c.CacheDir = "generated/cache"
	}
	if c.Checker.Listen == "" {
		c.Checker.Listen = "127.0.0.1:1443"
	}
	if c.Checker.StatusAddr == "" {
		c.Checker.StatusAddr = "127.0.0.1:18080"
	}
	h := &c.Checker.Health
	if h.IntervalSec == 0 {
		h.IntervalSec = 8
	}
	if h.TimeoutSec == 0 {
		h.TimeoutSec = 4
	}
	if h.FailThreshold == 0 {
		h.FailThreshold = 2
	}
	if h.OKThreshold == 0 {
		h.OKThreshold = 1
	}
	if h.Concurrency == 0 {
		h.Concurrency = 6
	}
	if c.Routing.Private == "" {
		c.Routing.Private = "direct"
	}
	if c.Routing.RU == "" {
		c.Routing.RU = "ru"
	}
	if c.Routing.Telegram == "" {
		c.Routing.Telegram = "telegram"
	}
	if c.Routing.Default == "" {
		c.Routing.Default = "auto"
	}
	if c.Alerts.MTProtoDeadFor == "" {
		c.Alerts.MTProtoDeadFor = "30s"
	}
	if c.Alerts.MTProtoAliveFor == "" {
		c.Alerts.MTProtoAliveFor = "60s"
	}
	if c.Alerts.WarnWhenHealthyLeft == 0 {
		c.Alerts.WarnWhenHealthyLeft = 1
	}
	if c.Alerts.Telegram.Via == "" {
		c.Alerts.Telegram.Via = "auto"
	}
	if c.Alerts.SMTP.Via == "" {
		c.Alerts.SMTP.Via = "direct"
	}
	if c.BotAPI.EnvFile == "" {
		c.BotAPI.EnvFile = "generated/telegram-bot-api.env"
	}
	if c.BotAPI.CheckerHost == "" {
		host, _, err := net.SplitHostPort(c.Checker.Listen)
		if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		c.BotAPI.CheckerHost = host
	}
}

func (c *Config) normalize() error {
	for i := range c.Proxies {
		p := &c.Proxies[i]
		if p.URL != "" {
			parsed, err := importurl.Parse(p.URL)
			if err != nil {
				return fmt.Errorf("proxy %q url: %w", p.Name, err)
			}
			if parsed.Kind != importurl.KindSOCKS && parsed.Kind != importurl.KindVLESS && parsed.Kind != importurl.KindTrojan {
				return fmt.Errorf("proxy %q url is %s, put MTProto under telegram_mtproto", p.Name, parsed.Kind)
			}
			if p.Type == "" {
				p.Type = parsed.Type
			}
			if p.Server == "" {
				p.Server = parsed.Server
			}
			if p.Port == 0 {
				p.Port = parsed.Port
			}
			if p.Username == "" {
				p.Username = parsed.Username
			}
			if p.Password == "" {
				p.Password = parsed.Password
			}
			if p.UUID == "" {
				p.UUID = parsed.UUID
			}
			if p.Flow == "" {
				p.Flow = parsed.Flow
			}
			if parsed.TLS != nil && p.TLS == nil {
				p.TLS = &TLS{
					ServerName: parsed.TLS.ServerName,
					Reality:    parsed.TLS.Reality,
					PublicKey:  parsed.TLS.PublicKey,
					ShortID:    parsed.TLS.ShortID,
				}
			}
		}
		if p.Type == "" {
			p.Type = "socks"
		}
		p.Type = strings.ToLower(p.Type)
		if len(p.Purpose) == 0 {
			p.Purpose = []string{"auto"}
		}
		if p.Name == "" {
			p.Name = fmt.Sprintf("%s-%s-%d", p.Type, p.Server, p.Port)
		}
	}
	for i := range c.TelegramMTProto {
		m := &c.TelegramMTProto[i]
		if m.URL != "" {
			parsed, err := importurl.Parse(m.URL)
			if err != nil {
				return fmt.Errorf("mtproto %q url: %w", m.Name, err)
			}
			if parsed.Kind != importurl.KindMTProto {
				return fmt.Errorf("telegram_mtproto %q is not an mtproto url", m.Name)
			}
			if m.Server == "" {
				m.Server = parsed.Server
			}
			if m.Port == 0 {
				m.Port = parsed.Port
			}
			if m.Secret == "" {
				m.Secret = parsed.Secret
			}
		}
		if m.Name == "" {
			m.Name = fmt.Sprintf("mtproto-%s-%d", m.Server, m.Port)
		}
		m.Secret = strings.ToLower(strings.TrimSpace(m.Secret))
	}
	return nil
}

func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	names := map[string]bool{}
	for _, p := range c.Proxies {
		if names[p.Name] {
			return fmt.Errorf("duplicate proxy name %q", p.Name)
		}
		names[p.Name] = true
		switch p.Type {
		case "vless", "trojan", "socks", "http", "ssh", "wireguard":
		default:
			return fmt.Errorf("proxy %q: unsupported type %q", p.Name, p.Type)
		}
		if p.Type != "wireguard" && p.Server == "" && p.ConfigFile == "" {
			return fmt.Errorf("proxy %q: server required", p.Name)
		}
	}
	return nil
}

func (c *Config) ListenHostPort() (string, int, error) {
	h, p, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	return h, port, err
}

func (c *Config) CheckerListenHostPort() (string, int, error) {
	h, p, err := net.SplitHostPort(c.Checker.Listen)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	return h, port, err
}

func (c *Config) StatusHostPort() (string, int, error) {
	h, p, err := net.SplitHostPort(c.Checker.StatusAddr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	return h, port, err
}

func (c *Config) HasPurpose(purpose string) bool {
	for _, p := range c.Proxies {
		if p.HasPurpose(purpose) && p.IsEnabled() {
			return true
		}
	}
	return false
}

func (c *Config) HasWireGuard() bool {
	for _, p := range c.Proxies {
		if p.IsEnabled() && strings.EqualFold(p.Type, "wireguard") {
			return true
		}
	}
	return false
}

func (c *Config) DeadFor() time.Duration {
	d, err := time.ParseDuration(c.Alerts.MTProtoDeadFor)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

func (c *Config) AliveFor() time.Duration {
	d, err := time.ParseDuration(c.Alerts.MTProtoAliveFor)
	if err != nil {
		return 60 * time.Second
	}
	return d
}

func (p Proxy) IsEnabled() bool {
	return p.Enabled == nil || *p.Enabled
}

func (p Proxy) HasPurpose(purpose string) bool {
	for _, x := range p.Purpose {
		if strings.EqualFold(x, purpose) {
			return true
		}
	}
	return false
}

func (m MTProto) IsEnabled() bool {
	return m.Enabled == nil || *m.Enabled
}

func Save(path string, cfg *Config) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
