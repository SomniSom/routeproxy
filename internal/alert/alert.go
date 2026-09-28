package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"routeproxy/internal/config"
)

var telegramAPI = "https://api.telegram.org"

type Sender struct {
	cfg          *config.Config
	mu           sync.Mutex
	last         map[string]time.Time
	transportFor func(via string) http.RoundTripper
}

func New(cfg *config.Config) *Sender {
	return &Sender{cfg: cfg, last: map[string]time.Time{}}
}

func (s *Sender) Notify(key, subject, body string) {
	s.mu.Lock()
	if t, ok := s.last[key]; ok && time.Since(t) < 5*time.Minute && key != "fallback" && key != "restore" {
		s.mu.Unlock()
		return
	}
	s.last[key] = time.Now()
	s.mu.Unlock()

	msg := subject + "\n\n" + body
	var errs []string
	if err := s.sendTelegram(msg); err != nil {
		errs = append(errs, "telegram: "+err.Error())
	}
	if err := s.sendSMTP(subject, body); err != nil {
		errs = append(errs, "smtp: "+err.Error())
	}
	if len(errs) > 0 {
		fmt.Printf("alert errors: %s\n", strings.Join(errs, "; "))
	}
}

type httpStatusError struct {
	status int
	body   string
}

func (e httpStatusError) Error() string {
	return fmt.Sprintf("http %d %s", e.status, e.body)
}

func isRateLimited(err error) bool {
	var st httpStatusError
	return errors.As(err, &st) && st.status == http.StatusTooManyRequests
}

func altVia(via string) string {
	if strings.EqualFold(via, "direct") {
		return "auto"
	}
	return "direct"
}

func (s *Sender) resolveVia(via string) string {
	if via == "" {
		via = "auto"
	}
	if s.cfg.Alerts.ForbidDirect && strings.EqualFold(via, "direct") {
		return "auto"
	}
	return via
}

func (s *Sender) allowVia(via string) bool {
	return !s.cfg.Alerts.ForbidDirect || !strings.EqualFold(via, "direct")
}

func (s *Sender) sendTelegram(text string) error {
	via := s.resolveVia(s.cfg.Alerts.Telegram.Via)
	err := s.sendTelegramVia(text, via)
	if err == nil || !isRateLimited(err) {
		return err
	}
	next := altVia(via)
	if !s.allowVia(next) {
		return err
	}
	fmt.Printf("alert telegram 429 via %s, retry via %s\n", via, next)
	return s.sendTelegramVia(text, next)
}

func (s *Sender) sendTelegramVia(text, via string) error {
	tok := s.cfg.Alerts.Telegram.BotToken
	chat := s.cfg.Alerts.Telegram.ChatID
	if tok == "" || chat == 0 {
		return nil
	}
	client, err := s.clientFor(via)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{
		"chat_id": chat,
		"text":    text,
	})
	u := fmt.Sprintf("%s/bot%s/sendMessage", telegramAPI, tok)
	resp, err := client.Post(u, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return httpStatusError{status: resp.StatusCode, body: string(b)}
	}
	return nil
}

func (s *Sender) clientFor(via string) (*http.Client, error) {
	if s.transportFor != nil {
		return &http.Client{Timeout: 20 * time.Second, Transport: s.transportFor(via)}, nil
	}
	client := &http.Client{Timeout: 20 * time.Second}
	if strings.EqualFold(via, "auto") {
		d, err := socksDialer(s.cfg.Listen)
		if err != nil {
			return nil, err
		}
		client.Transport = &http.Transport{DialContext: d.DialContext}
	}
	return client, nil
}

func (s *Sender) sendSMTP(subject, body string) error {
	a := s.cfg.Alerts.SMTP
	if a.Host == "" || len(a.To) == 0 || a.Username == "" {
		return nil
	}
	from := a.From
	if from == "" {
		from = a.Username
	}
	port := a.Port
	if port == 0 {
		port = 465
	}
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		from, strings.Join(a.To, ", "), subject, body))
	addr := net.JoinHostPort(a.Host, fmt.Sprint(port))
	auth := smtp.PlainAuth("", a.Username, a.Password, a.Host)
	via := s.resolveVia(a.Via)
	conn, err := s.netDial(via, "tcp", addr)
	if err != nil {
		return err
	}
	if port == 465 {
		conn = tls.Client(conn, &tls.Config{ServerName: a.Host})
	}
	return smtpOver(conn, a.Host, auth, from, a.To, msg, port != 465)
}

func (s *Sender) netDial(via, network, addr string) (net.Conn, error) {
	via = s.resolveVia(via)
	if strings.EqualFold(via, "auto") {
		d, err := socksDialer(s.cfg.Listen)
		if err != nil {
			return nil, err
		}
		return d.DialContext(context.Background(), network, addr)
	}
	return net.DialTimeout(network, addr, 20*time.Second)
}

func smtpOver(conn net.Conn, host string, auth smtp.Auth, from string, to []string, msg []byte, startTLS bool) error {
	defer conn.Close()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if startTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return err
			}
		}
	}
	if err := c.Auth(auth); err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func socksDialer(listen string) (proxy.ContextDialer, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	d, err := proxy.SOCKS5("tcp", net.JoinHostPort(host, port), nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks dialer has no DialContext")
	}
	return cd, nil
}
