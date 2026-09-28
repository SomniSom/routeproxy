package generate

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type WGQuick struct {
	Interface    string
	PrivateKey   string
	Address      []string
	MTU          int
	PublicKey    string
	PresharedKey string
	Endpoint     string
}

func ParseWGQuick(path string) (*WGQuick, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := &WGQuick{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "PrivateKey":
				out.PrivateKey = v
			case "Address":
				for _, a := range strings.Split(v, ",") {
					a = strings.TrimSpace(a)
					if a != "" {
						out.Address = append(out.Address, a)
					}
				}
			case "MTU":
				out.MTU, _ = strconv.Atoi(v)
			}
		case "peer":
			switch k {
			case "PublicKey":
				out.PublicKey = v
			case "PresharedKey":
				out.PresharedKey = v
			case "Endpoint":
				out.Endpoint = v
			}
		}
	}
	return out, sc.Err()
}
