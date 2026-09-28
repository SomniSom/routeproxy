package fallback

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"routeproxy/internal/alert"
	"routeproxy/internal/config"
	"routeproxy/internal/mtproxy"
)

type Controller struct {
	cfg    *config.Config
	reg    *mtproxy.Registry
	alerts *alert.Sender

	mu        sync.Mutex
	deadSince *time.Time
	liveSince *time.Time
	mode      string // mtproto | socks
	lastWarn  int
}

func New(cfg *config.Config, reg *mtproxy.Registry, alerts *alert.Sender) *Controller {
	return &Controller{cfg: cfg, reg: reg, alerts: alerts, mode: "mtproto", lastWarn: -1}
}

func (c *Controller) Tick() {
	healthy := c.reg.MTProtoHealthy()
	groups := c.reg.MTProtoGroups()
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if groups == 0 {
		return
	}

	left := healthy
	warnAt := c.cfg.Alerts.WarnWhenHealthyLeft
	if left <= warnAt && left != c.lastWarn {
		c.lastWarn = left
		subj := fmt.Sprintf("routeproxy: %d/%d MTProto groups healthy", left, groups)
		body := fmt.Sprintf("MTProto checker has %d healthy group(s) of %d.\nStatus: %s", left, groups, c.cfg.Checker.StatusAddr)
		key := fmt.Sprintf("warn-%d", left)
		c.mu.Unlock()
		c.alerts.Notify(key, subj, body)
		c.mu.Lock()
	}
	if left > warnAt {
		c.lastWarn = left
	}

	if healthy == 0 {
		c.liveSince = nil
		if c.deadSince == nil {
			t := now
			c.deadSince = &t
		}
		if c.mode != "socks" && now.Sub(*c.deadSince) >= c.cfg.DeadFor() {
			c.mu.Unlock()
			err := c.switchTo("socks")
			c.mu.Lock()
			if err != nil {
				fmt.Printf("fallback socks: %v\n", err)
			} else {
				c.mode = "socks"
				c.mu.Unlock()
				c.alerts.Notify("fallback", "routeproxy: bots switched to SOCKS :1080",
					"All MTProto groups are down. Bot API env rewritten to SOCKS mixed inbound.")
				c.mu.Lock()
			}
		}
		return
	}

	c.deadSince = nil
	if c.liveSince == nil {
		t := now
		c.liveSince = &t
	}
	if c.mode != "mtproto" && now.Sub(*c.liveSince) >= c.cfg.AliveFor() {
		c.mu.Unlock()
		err := c.switchTo("mtproto")
		c.mu.Lock()
		if err != nil {
			fmt.Printf("restore mtproto: %v\n", err)
		} else {
			c.mode = "mtproto"
			c.mu.Unlock()
			c.alerts.Notify("restore", "routeproxy: bots restored to MTProto :1443",
				"MTProto group is healthy again. Bot API env restored.")
			c.mu.Lock()
		}
	}
}

func (c *Controller) WriteInitial() error {
	return c.switchTo("mtproto")
}

func (c *Controller) switchTo(mode string) error {
	env, err := c.envFor(mode)
	if err != nil {
		return err
	}
	path := c.cfg.BotAPI.EnvFile
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(env), 0o600); err != nil {
		return err
	}
	if len(c.cfg.BotAPI.RestartCommand) > 0 {
		cmd := exec.Command(c.cfg.BotAPI.RestartCommand[0], c.cfg.BotAPI.RestartCommand[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("restart: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (c *Controller) envFor(mode string) (string, error) {
	if mode == "socks" {
		host, port, err := c.cfg.ListenHostPort()
		if err != nil {
			return "", err
		}
		if host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		return fmt.Sprintf("TDLIB_PROXY_TYPE=socks5\nPROXY_SERVER=%s\nPROXY_PORT=%d\n", host, port), nil
	}
	g := c.reg.FirstMTProtoGroup()
	if g == nil {
		return "", fmt.Errorf("no mtproto group")
	}
	host := c.cfg.BotAPI.CheckerHost
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("TDLIB_PROXY_TYPE=mtproto\nPROXY_SERVER=%s\nPROXY_PORT=%d\nPROXY_SECRET=%s\n",
		host, g.ListenPort, g.Secret), nil
}
