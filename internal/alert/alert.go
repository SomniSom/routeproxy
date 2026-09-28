package alert

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
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

type Sender struct {
	cfg  *config.Config
	mu   sync.Mutex
	last map[string]time.Time
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

func (s *Sender) sendTelegram(text string) error {
	tok := s.cfg.Alerts.Telegram.BotToken
	chat := s.cfg.Alerts.Telegram.ChatID
	if tok == "" || chat == 0 {
		return nil
	}
	client := &http.Client{Timeout: 20 * time.Second}
	if strings.EqualFold(s.cfg.Alerts.Telegram.Via, "auto") {
		d, err := socksDialer(s.cfg.Listen)
		if err != nil {
			return err
		}
		client.Transport = &http.Transport{
			DialContext: d.DialContext,
		}
	}
	payload, _ := json.Marshal(map[string]any{
		"chat_id": chat,
		"text":    text,
	})
	u := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tok)
	resp, err := client.Post(u, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("http %d %s", resp.StatusCode, b)
	}
	return nil
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
	if port == 465 {
		return sendSMTPTLS(addr, a.Host, auth, from, a.To, msg)
	}
	return smtp.SendMail(addr, auth, from, a.To, msg)
}

func sendSMTPTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 20 * time.Second}, "tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
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
