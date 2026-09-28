package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"routeproxy/internal/alert"
	"routeproxy/internal/cli"
	"routeproxy/internal/config"
	"routeproxy/internal/fallback"
	"routeproxy/internal/generate"
	"routeproxy/internal/importurl"
	"routeproxy/internal/mtproxy"
	"routeproxy/internal/route"
)

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "generate":
		err = cmdGenerate(args)
	case "generate-sfa":
		err = cmdGenerateSFA(args)
	case "check":
		err = cmdCheck(args)
	case "apply":
		err = cmdApply(args)
	case "add":
		err = cmdAdd(args)
	case "telegram-urls":
		err = cmdTelegramURLs(args)
	case "why":
		err = cmdWhy(args)
	case "probe":
		err = cmdProbe(args)
	case "checker":
		err = cmdChecker(args)
	case "completion":
		err = cmdCompletion(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, cli.Usage())
}

func cmdCompletion(args []string) error {
	if len(args) < 1 || args[0] == "-h" || args[0] == "--help" {
		return fmt.Errorf("usage: rpctl completion bash|zsh")
	}
	switch args[0] {
	case "bash":
		_, err := os.Stdout.WriteString(cli.Bash())
		return err
	case "zsh":
		_, err := os.Stdout.WriteString(cli.Zsh())
		return err
	default:
		return fmt.Errorf("unknown shell %q (want bash or zsh)", args[0])
	}
}

func loadCfg(fs *flag.FlagSet, args []string) (*config.Config, string, error) {
	path := config.DefaultPath()
	fs.StringVar(&path, "config", path, "yaml config")
	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(path)
	return cfg, path, err
}

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	res, err := generate.Write(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes) auto=%s ru=%s telegram=%s\n",
		cfg.GeneratedPath, len(res.JSON), res.AutoTag, res.RUTag, res.TGTag)
	if len(res.Warnings) > 0 {
		fmt.Fprintf(os.Stderr, "warn: WireGuard in config (%d check(s))\n", len(res.Warnings))
	}
	return nil
}

func cmdGenerateSFA(args []string) error {
	fs := flag.NewFlagSet("generate-sfa", flag.ExitOnError)
	out := generate.DefaultSFAPath
	fs.StringVar(&out, "out", out, "output JSON (`-` for stdout)")
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	if out == "-" {
		res, err := generate.BuildSFA(cfg)
		if err != nil {
			return err
		}
		for _, w := range res.Warnings {
			fmt.Fprintln(os.Stderr, "warn:", w)
		}
		_, err = os.Stdout.Write(res.JSON)
		return err
	}
	res, err := generate.WriteSFA(cfg, out)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes) auto=%s ru=%s telegram=%s\n",
		out, len(res.JSON), res.AutoTag, res.RUTag, res.TGTag)
	fmt.Fprintln(os.Stderr, "import in SFA: Profiles → + → Import from file")
	return nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	if _, err := generate.Write(cfg); err != nil {
		return err
	}
	bin := os.Getenv("SINGBOX")
	if bin == "" {
		bin = "sing-box"
	}
	cmd := exec.Command(bin, "check", "-c", cfg.GeneratedPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	if _, err := generate.Write(cfg); err != nil {
		return err
	}
	bin := os.Getenv("SINGBOX")
	if bin == "" {
		bin = "sing-box"
	}
	check := exec.Command(bin, "check", "-c", cfg.GeneratedPath)
	check.Stdout = os.Stdout
	check.Stderr = os.Stderr
	if err := check.Run(); err != nil {
		return err
	}
	if len(cfg.Apply.Commands) == 0 {
		fmt.Println("generated; no apply.commands — restart sing-box / rpctl checker yourself")
		return nil
	}
	for _, c := range cfg.Apply.Commands {
		if len(c) == 0 {
			continue
		}
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%v: %w", c, err)
		}
	}
	return nil
}

func cmdAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	purpose := fs.String("purpose", "auto,telegram", "comma purposes for SOCKS/VLESS")
	name := fs.String("name", "", "optional name")
	path := config.DefaultPath()
	fs.StringVar(&path, "config", path, "yaml config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: rpctl add <url>")
	}
	raw := fs.Arg(0)
	parsed, err := importurl.Parse(raw)
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	n := *name
	if parsed.Kind == importurl.KindMTProto {
		if n == "" {
			n = fmt.Sprintf("mtproto-%s-%d", parsed.Server, parsed.Port)
		}
		cfg.TelegramMTProto = append(cfg.TelegramMTProto, config.MTProto{
			Name: n, URL: raw, Server: parsed.Server, Port: parsed.Port, Secret: parsed.Secret,
		})
		if err := config.Save(path, cfg); err != nil {
			return err
		}
		fmt.Printf("added telegram_mtproto %s\n", n)
		return nil
	}
	if n == "" {
		n = fmt.Sprintf("%s-%s-%d", parsed.Type, parsed.Server, parsed.Port)
	}
	p := config.Proxy{
		Name: n, Type: parsed.Type, URL: raw,
		Server: parsed.Server, Port: parsed.Port,
		Username: parsed.Username, Password: parsed.Password,
		UUID: parsed.UUID, Flow: parsed.Flow,
		Purpose: splitCSV(*purpose),
	}
	if parsed.TLS != nil {
		p.TLS = &config.TLS{
			ServerName: parsed.TLS.ServerName,
			Reality:    parsed.TLS.Reality,
			PublicKey:  parsed.TLS.PublicKey,
			ShortID:    parsed.TLS.ShortID,
		}
	}
	cfg.Proxies = append(cfg.Proxies, p)
	if err := config.Save(path, cfg); err != nil {
		return err
	}
	fmt.Printf("added proxy %s type=%s purpose=%v\n", n, p.Type, p.Purpose)
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdTelegramURLs(args []string) error {
	fs := flag.NewFlagSet("telegram-urls", flag.ExitOnError)
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	fmt.Println("# mixed SOCKS for Telegram Desktop")
	fmt.Println(importurl.LocalSOCKSURL(cfg.Listen))
	fmt.Println("# stored MTProto")
	for _, m := range cfg.TelegramMTProto {
		if m.URL != "" {
			fmt.Printf("%s\t%s\n", m.Name, m.URL)
			continue
		}
		fmt.Printf("%s\t%s\n", m.Name, importurl.MTProtoURL(m.Server, m.Port, m.Secret))
	}
	return nil
}

func cmdWhy(args []string) error {
	fs := flag.NewFlagSet("why", flag.ExitOnError)
	path := config.DefaultPath()
	fs.StringVar(&path, "config", path, "yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: rpctl why <host>")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	fmt.Println(route.Why(cfg, fs.Arg(0)))
	return nil
}

func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	status := cfg.Checker.StatusAddr
	if h, _, err := net.SplitHostPort(status); err == nil && (h == "0.0.0.0" || h == "::") {
		status = net.JoinHostPort("127.0.0.1", strings.Split(cfg.Checker.StatusAddr, ":")[1])
	}
	u := "http://" + status + "/healthz"
	resp, err := http.Get(u)
	if err != nil {
		return fmt.Errorf("checker %s: %w", u, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	fmt.Printf("checker %s → %d %s\n", u, resp.StatusCode, strings.TrimSpace(string(b)))
	if resp.StatusCode != 200 {
		return fmt.Errorf("checker unhealthy")
	}
	return nil
}

func cmdChecker(args []string) error {
	fs := flag.NewFlagSet("checker", flag.ExitOnError)
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	reg, err := mtproxy.BuildRegistry(cfg)
	if err != nil {
		return err
	}
	if len(reg.Proxies) == 0 {
		return fmt.Errorf("telegram_mtproto is empty")
	}
	alerts := alert.New(cfg)
	fb := fallback.New(cfg, reg, alerts)
	if err := fb.WriteInitial(); err != nil {
		log.Printf("bot_api env: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg.CheckAll(cfg)
	fb.Tick()

	sh, sp, err := cfg.StatusHostPort()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:    net.JoinHostPort(sh, fmt.Sprint(sp)),
		Handler: mtproxy.StatusServer{Reg: reg},
	}
	go func() {
		log.Printf("status %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	timeout := time.Duration(cfg.Checker.Health.TimeoutSec * float64(time.Second))
	for _, g := range reg.Groups {
		g := g
		go func() {
			if err := mtproxy.ServeGroup(ctx, g, reg, timeout); err != nil {
				log.Printf("serve :%d: %v", g.ListenPort, err)
			}
		}()
	}

	tick := time.NewTicker(time.Duration(cfg.Checker.Health.IntervalSec * float64(time.Second)))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = srv.Close()
			return nil
		case <-tick.C:
			reg.CheckAll(cfg)
			fb.Tick()
		}
	}
}
