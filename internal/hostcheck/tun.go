package hostcheck

import (
	"fmt"
	"math/big"
	"os"
	"strings"

	"routeproxy/internal/config"
)

// Linux CAP_NET_ADMIN is bit 12 in CapEff.
const capNetAdmin uint = 12

var (
	tunDevice  = "/dev/net/tun"
	statusFile = "/proc/self/status"
)

func WireGuardWarnings(cfg *config.Config) []string {
	if cfg == nil || !cfg.HasWireGuard() {
		return nil
	}
	var out []string
	if _, err := os.Stat(tunDevice); err != nil {
		if os.IsNotExist(err) {
			out = append(out, "/dev/net/tun отсутствует. На хосте: sudo modprobe tun. В Docker сервису routeproxy: devices: [/dev/net/tun:/dev/net/tun]. Чекеру (rpctl checker / routeproxy-checker) это не нужно; --privileged не требуется.")
		} else {
			out = append(out, fmt.Sprintf("/dev/net/tun недоступен: %v. В Docker: devices: [/dev/net/tun:/dev/net/tun]. Чекеру это не нужно; --privileged не требуется.", err))
		}
	} else if f, err := os.OpenFile(tunDevice, os.O_RDWR, 0); err != nil {
		out = append(out, fmt.Sprintf("не открыть /dev/net/tun (%v). В Docker сервису routeproxy: devices: [/dev/net/tun:/dev/net/tun] и cap_add: [NET_ADMIN]. Чекеру это не нужно; --privileged не требуется.", err))
	} else {
		_ = f.Close()
	}
	if ok, err := hasCapNetAdmin(); err == nil && !ok {
		out = append(out, "нет CAP_NET_ADMIN. В Docker сервису routeproxy: cap_add: [NET_ADMIN]. Чекеру (rpctl checker) это не нужно; --privileged не требуется.")
	}
	return out
}

func hasCapNetAdmin() (bool, error) {
	raw, err := os.ReadFile(statusFile)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || k != "CapEff" {
			continue
		}
		hex := strings.TrimSpace(v)
		n := new(big.Int)
		if _, ok := n.SetString(hex, 16); !ok {
			return false, fmt.Errorf("CapEff: %q", hex)
		}
		return n.Bit(int(capNetAdmin)) == 1, nil
	}
	return false, fmt.Errorf("CapEff not found")
}
