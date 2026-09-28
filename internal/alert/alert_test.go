package alert

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"routeproxy/internal/config"
)

func TestNotifyNoopWithoutChannels(t *testing.T) {
	s := New(&config.Config{})
	s.Notify("warn-1", "subj", "body")
	s.Notify("warn-1", "subj", "body")
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.last) != 1 {
		t.Fatalf("debounce last=%d", len(s.last))
	}
}

func TestSocksDialerRewritesWildcard(t *testing.T) {
	d, err := socksDialer("0.0.0.0:8079")
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal("nil dialer")
	}
}

func TestSocksDialerBadListen(t *testing.T) {
	if _, err := socksDialer("nope"); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := net.SplitHostPort("127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResp(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(`{"ok":false}`)),
		Header:     make(http.Header),
	}
}

func TestAltVia(t *testing.T) {
	if got := altVia("auto"); got != "direct" {
		t.Fatalf("altVia(auto)=%s", got)
	}
	if got := altVia("direct"); got != "auto" {
		t.Fatalf("altVia(direct)=%s", got)
	}
	if got := altVia(""); got != "direct" {
		t.Fatalf("altVia()=%s", got)
	}
}

func TestIsRateLimited(t *testing.T) {
	if isRateLimited(httpStatusError{status: 429, body: "slow"}) != true {
		t.Fatal("429 should be rate limited")
	}
	if isRateLimited(httpStatusError{status: 500}) {
		t.Fatal("500 is not rate limited")
	}
	if isRateLimited(errors.New("http 429")) {
		t.Fatal("plain error is not a status")
	}
}

func TestSendTelegram429RetriesOtherVia(t *testing.T) {
	var vias []string
	s := New(&config.Config{
		Listen: "127.0.0.1:8079",
		Alerts: config.Alerts{
			Telegram: config.TelegramAlert{BotToken: "tok", ChatID: 1, Via: "auto"},
		},
	})
	s.transportFor = func(via string) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			vias = append(vias, via)
			if via == "auto" {
				return jsonResp(http.StatusTooManyRequests), nil
			}
			return jsonResp(http.StatusOK), nil
		})
	}
	if err := s.sendTelegram("hi"); err != nil {
		t.Fatal(err)
	}
	if len(vias) != 2 || vias[0] != "auto" || vias[1] != "direct" {
		t.Fatalf("vias=%v", vias)
	}
}

func TestSendTelegram429BothChannelsFail(t *testing.T) {
	s := New(&config.Config{
		Alerts: config.Alerts{
			Telegram: config.TelegramAlert{BotToken: "tok", ChatID: 1, Via: "direct"},
		},
	})
	s.transportFor = func(string) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResp(http.StatusTooManyRequests), nil
		})
	}
	err := s.sendTelegram("hi")
	if !isRateLimited(err) {
		t.Fatalf("want 429 after failover, got %v", err)
	}
}

func TestForbidDirectSkips429RetryToDirect(t *testing.T) {
	var vias []string
	s := New(&config.Config{
		Alerts: config.Alerts{
			ForbidDirect: true,
			Telegram:     config.TelegramAlert{BotToken: "tok", ChatID: 1, Via: "auto"},
		},
	})
	s.transportFor = func(via string) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			vias = append(vias, via)
			return jsonResp(http.StatusTooManyRequests), nil
		})
	}
	if err := s.sendTelegram("hi"); !isRateLimited(err) {
		t.Fatalf("want 429 without direct fallback, got %v", err)
	}
	if len(vias) != 1 || vias[0] != "auto" {
		t.Fatalf("vias=%v", vias)
	}
}

func TestForbidDirectCoercesConfiguredDirect(t *testing.T) {
	var vias []string
	s := New(&config.Config{
		Alerts: config.Alerts{
			ForbidDirect: true,
			Telegram:     config.TelegramAlert{BotToken: "tok", ChatID: 1, Via: "direct"},
		},
	})
	s.transportFor = func(via string) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			vias = append(vias, via)
			return jsonResp(http.StatusOK), nil
		})
	}
	if err := s.sendTelegram("hi"); err != nil {
		t.Fatal(err)
	}
	if len(vias) != 1 || vias[0] != "auto" {
		t.Fatalf("vias=%v", vias)
	}
}

func TestResolveVia(t *testing.T) {
	s := New(&config.Config{Alerts: config.Alerts{ForbidDirect: true}})
	if got := s.resolveVia("direct"); got != "auto" {
		t.Fatalf("resolveVia(direct)=%s", got)
	}
	if s.allowVia("direct") {
		t.Fatal("direct must be forbidden")
	}
	open := New(&config.Config{})
	if got := open.resolveVia("direct"); got != "direct" {
		t.Fatalf("resolveVia without forbid=%s", got)
	}
}

func TestSendTelegramNoRetryOnOtherHTTP(t *testing.T) {
	var n int
	s := New(&config.Config{
		Alerts: config.Alerts{
			Telegram: config.TelegramAlert{BotToken: "tok", ChatID: 1, Via: "direct"},
		},
	})
	s.transportFor = func(string) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			n++
			return jsonResp(http.StatusBadRequest), nil
		})
	}
	err := s.sendTelegram("hi")
	var st httpStatusError
	if !errors.As(err, &st) || st.status != 400 {
		t.Fatalf("want 400, got %v", err)
	}
	if n != 1 {
		t.Fatalf("retries on non-429: n=%d", n)
	}
}
