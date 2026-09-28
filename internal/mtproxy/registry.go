package mtproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"routeproxy/internal/config"
)

type Proxy struct {
	Name     string
	Server   string
	Port     int
	Secret   string
	Kind     string
	Username string
	Password string
	Reserve  bool
	Enabled  bool

	mu          sync.Mutex
	OK          bool
	LastError   string
	LastCheck   time.Time
	Fails       int
	OKs         int
	ActiveConns int32
}

type Group struct {
	Key        string
	Kind       string
	Secret     string
	ListenHost string
	ListenPort int
	Proxies    []*Proxy

	mu      sync.Mutex
	Current *Proxy
}

type Registry struct {
	Groups  []*Group
	Proxies []*Proxy
	Probe   ProbeFunc

	mu sync.Mutex
}

func BuildRegistry(cfg *config.Config) (*Registry, error) {
	host, port, err := cfg.CheckerListenHostPort()
	if err != nil {
		return nil, err
	}
	var proxies []*Proxy
	for _, m := range cfg.TelegramMTProto {
		proxies = append(proxies, &Proxy{
			Name:    m.Name,
			Server:  m.Server,
			Port:    m.Port,
			Secret:  m.Secret,
			Kind:    "mtproto",
			Reserve: m.Reserve,
			Enabled: m.IsEnabled(),
		})
	}
	for _, p := range cfg.Proxies {
		if p.Type != "socks" || !p.Reserve {
			continue
		}
		proxies = append(proxies, &Proxy{
			Name:     p.Name,
			Server:   p.Server,
			Port:     p.Port,
			Kind:     "socks5",
			Username: p.Username,
			Password: p.Password,
			Reserve:  true,
			Enabled:  p.IsEnabled(),
		})
	}
	byKey := map[string][]*Proxy{}
	var order []string
	for _, p := range proxies {
		key := "mtproto:" + p.Secret
		if p.Kind == "socks5" {
			key = fmt.Sprintf("socks5:%s@%s:%d", p.Username, p.Server, p.Port)
		}
		if _, ok := byKey[key]; !ok {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], p)
	}
	var groups []*Group
	for i, key := range order {
		members := byKey[key]
		groups = append(groups, &Group{
			Key:        key,
			Kind:       members[0].Kind,
			Secret:     members[0].Secret,
			ListenHost: host,
			ListenPort: port + i,
			Proxies:    members,
		})
	}
	return &Registry{Groups: groups, Proxies: proxies, Probe: Probe}, nil
}

func (r *Registry) Recompute() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, g := range r.Groups {
		var chosen *Proxy
		for _, p := range g.Proxies {
			p.mu.Lock()
			ok := p.Enabled && p.OK
			p.mu.Unlock()
			if ok {
				chosen = p
				break
			}
		}
		g.mu.Lock()
		if chosen != g.Current {
			old := "none"
			if g.Current != nil {
				old = g.Current.Name
			}
			nw := "none"
			if chosen != nil {
				nw = fmt.Sprintf("%s %s:%d", chosen.Name, chosen.Server, chosen.Port)
			}
			log.Printf("failover :%d %s -> %s", g.ListenPort, old, nw)
			g.Current = chosen
		}
		g.mu.Unlock()
	}
}

func (r *Registry) Pick(g *Group) *Proxy {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.Current
}

func (r *Registry) AnyUp() bool {
	for _, g := range r.Groups {
		g.mu.Lock()
		cur := g.Current
		g.mu.Unlock()
		if cur != nil {
			return true
		}
	}
	return false
}

func (r *Registry) MTProtoHealthy() int {
	n := 0
	for _, g := range r.Groups {
		if g.Kind == "socks5" {
			continue
		}
		g.mu.Lock()
		if g.Current != nil {
			n++
		}
		g.mu.Unlock()
	}
	return n
}

func (r *Registry) MTProtoGroups() int {
	n := 0
	for _, g := range r.Groups {
		if g.Kind != "socks5" {
			n++
		}
	}
	return n
}

func (r *Registry) FirstMTProtoGroup() *Group {
	for _, g := range r.Groups {
		if g.Kind != "socks5" {
			return g
		}
	}
	return nil
}

func (r *Registry) Snapshot() map[string]any {
	var groups []any
	anyUp := false
	for _, g := range r.Groups {
		g.mu.Lock()
		cur := g.Current
		g.mu.Unlock()
		if cur != nil {
			anyUp = true
		}
		meta := SecretMetaFrom(g.Secret)
		if g.Kind == "socks5" {
			meta = SecretMeta{Kind: SecretSOCKS}
		}
		var current any
		if cur != nil {
			current = map[string]any{
				"name":         cur.Name,
				"server":       cur.Server,
				"port":         cur.Port,
				"active_conns": atomic.LoadInt32(&cur.ActiveConns),
			}
		}
		reserve := false
		var views []any
		for _, p := range g.Proxies {
			if p.Reserve {
				reserve = true
			}
			views = append(views, proxyView(p))
		}
		groups = append(groups, map[string]any{
			"listen":      fmt.Sprintf("%s:%d", g.ListenHost, g.ListenPort),
			"kind":        g.Kind,
			"reserve":     reserve,
			"secret_kind": string(meta.Kind),
			"secret_tail": meta.Tail,
			"sni":         emptyNil(meta.SNI),
			"current":     current,
			"proxies":     views,
		})
	}
	var plist []any
	for _, p := range r.Proxies {
		plist = append(plist, proxyView(p))
	}
	return map[string]any{"any_up": anyUp, "groups": groups, "proxies": plist}
}

func proxyView(p *Proxy) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	meta := SecretMetaFrom(p.Secret)
	if p.Kind == "socks5" {
		return map[string]any{
			"name":            p.Name,
			"server":          p.Server,
			"port":            p.Port,
			"enabled":         p.Enabled,
			"reserve":         p.Reserve,
			"secret_kind":     "socks5",
			"login":           p.Username,
			"ok":              p.OK,
			"last_error":      p.LastError,
			"last_check_unix": p.LastCheck.Unix(),
			"active_conns":    atomic.LoadInt32(&p.ActiveConns),
			"fails":           p.Fails,
			"oks":             p.OKs,
		}
	}
	return map[string]any{
		"name":            p.Name,
		"server":          p.Server,
		"port":            p.Port,
		"enabled":         p.Enabled,
		"reserve":         p.Reserve,
		"secret_kind":     string(meta.Kind),
		"secret_tail":     meta.Tail,
		"sni":             emptyNil(meta.SNI),
		"ok":              p.OK,
		"last_error":      p.LastError,
		"last_check_unix": p.LastCheck.Unix(),
		"active_conns":    atomic.LoadInt32(&p.ActiveConns),
		"fails":           p.Fails,
		"oks":             p.OKs,
	}
}

func emptyNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (r *Registry) CheckOne(p *Proxy, timeout time.Duration, failTh, okTh int) {
	p.mu.Lock()
	if !p.Enabled {
		p.OK = false
		p.LastError = "disabled"
		p.LastCheck = time.Now()
		p.mu.Unlock()
		return
	}
	if p.Kind != "socks5" && p.Secret == "" {
		p.OK = false
		p.LastError = "empty-secret"
		p.LastCheck = time.Now()
		p.mu.Unlock()
		return
	}
	if p.Kind == "socks5" && p.Username == "" {
		p.OK = false
		p.LastError = "empty-socks-login"
		p.LastCheck = time.Now()
		p.mu.Unlock()
		return
	}
	tgt := ProbeTarget{Kind: p.Kind, Server: p.Server, Port: p.Port, Secret: p.Secret, Username: p.Username, Password: p.Password}
	p.mu.Unlock()

	probe := r.Probe
	if probe == nil {
		probe = Probe
	}
	ok, detail := probe(tgt, timeout)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastCheck = time.Now()
	if ok {
		p.LastError = ""
		p.OKs++
		p.Fails = 0
		if p.OKs >= okTh {
			if !p.OK {
				log.Printf("up %s %s:%d (%s)", p.Name, p.Server, p.Port, detail)
			}
			p.OK = true
		}
	} else {
		p.LastError = detail
		p.Fails++
		p.OKs = 0
		if p.Fails >= failTh {
			if p.OK {
				log.Printf("down %s %s:%d (%s)", p.Name, p.Server, p.Port, detail)
			}
			p.OK = false
		}
	}
}

func (r *Registry) CheckAll(cfg *config.Config) {
	h := cfg.Checker.Health
	timeout := time.Duration(h.TimeoutSec * float64(time.Second))
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	sem := make(chan struct{}, max(1, h.Concurrency))
	var wg sync.WaitGroup
	for _, p := range r.Proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(p *Proxy) {
			defer wg.Done()
			defer func() { <-sem }()
			r.CheckOne(p, timeout, h.FailThreshold, h.OKThreshold)
		}(p)
	}
	wg.Wait()
	r.Recompute()
}

type StatusServer struct {
	Reg *Registry
}

func (s StatusServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	snap := s.Reg.Snapshot()
	path := req.URL.Path
	if path == "/healthz" || path == "/health" {
		anyUp, _ := snap["any_up"].(bool)
		if !anyUp {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": anyUp})
		return
	}
	if path == "/metrics" {
		writeMetrics(w, s.Reg)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

func writeMetrics(w http.ResponseWriter, r *Registry) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	anyUp := 0
	if r.AnyUp() {
		anyUp = 1
	}
	fmt.Fprintf(w, "routeproxy_checker_any_up %d\n", anyUp)
	fmt.Fprintf(w, "routeproxy_mtproto_groups %d\n", r.MTProtoGroups())
	fmt.Fprintf(w, "routeproxy_mtproto_healthy_groups %d\n", r.MTProtoHealthy())
	for _, p := range r.Proxies {
		p.mu.Lock()
		ok := 0
		if p.OK {
			ok = 1
		}
		fails := p.Fails
		p.mu.Unlock()
		fmt.Fprintf(w, "routeproxy_proxy_up{name=%q} %d\n", p.Name, ok)
		fmt.Fprintf(w, "routeproxy_proxy_fails{name=%q} %d\n", p.Name, fails)
		fmt.Fprintf(w, "routeproxy_proxy_active_conns{name=%q} %d\n", p.Name, atomic.LoadInt32(&p.ActiveConns))
	}
}

func ServeGroup(ctx context.Context, g *Group, r *Registry, timeout time.Duration) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(g.ListenHost, fmt.Sprint(g.ListenPort)))
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	log.Printf("listen %s:%d kind=%s proxies=%d", g.ListenHost, g.ListenPort, g.Kind, len(g.Proxies))
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handleClient(c, g, r, timeout)
	}
}

func handleClient(c net.Conn, g *Group, r *Registry, timeout time.Duration) {
	defer c.Close()
	backend := r.Pick(g)
	if backend == nil {
		log.Printf("reject %s :%d: no healthy proxy", c.RemoteAddr(), g.ListenPort)
		return
	}
	bc, err := net.DialTimeout("tcp", net.JoinHostPort(backend.Server, fmt.Sprint(backend.Port)), timeout)
	if err != nil {
		log.Printf("backend dial fail %s: %v", backend.Name, err)
		backend.mu.Lock()
		backend.OK = false
		backend.mu.Unlock()
		r.Recompute()
		return
	}
	defer bc.Close()
	atomic.AddInt32(&backend.ActiveConns, 1)
	defer atomic.AddInt32(&backend.ActiveConns, -1)
	errc := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(bc, c); errc <- struct{}{} }()
	go func() { _, _ = io.Copy(c, bc); errc <- struct{}{} }()
	<-errc
}
