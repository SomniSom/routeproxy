package alert

import (
	"net"
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
