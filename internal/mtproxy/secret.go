package mtproxy

import (
	"strings"
)

type SecretKind string

const (
	SecretEE      SecretKind = "ee"
	SecretDD      SecretKind = "dd"
	SecretClassic SecretKind = "classic"
	SecretSOCKS   SecretKind = "socks5"
)

type SecretMeta struct {
	Kind SecretKind
	SNI  string
	Tail string
}

func SecretMetaFrom(secret string) SecretMeta {
	s := strings.ToLower(strings.TrimSpace(secret))
	tail := ""
	if len(s) >= 6 {
		tail = s[len(s)-6:]
	}
	if strings.HasPrefix(s, "ee") && len(s) > 34 {
		sni := "telegram.org"
		domHex := s[34:]
		if b, err := decodeHexASCII(domHex); err == nil && b != "" && printable(b) {
			sni = b
		}
		return SecretMeta{Kind: SecretEE, SNI: sni, Tail: tail}
	}
	if strings.HasPrefix(s, "dd") {
		return SecretMeta{Kind: SecretDD, SNI: "telegram.org", Tail: tail}
	}
	return SecretMeta{Kind: SecretClassic, Tail: tail}
}

func decodeHexASCII(hex string) (string, error) {
	if len(hex)%2 != 0 {
		return "", errOddHex
	}
	out := make([]byte, len(hex)/2)
	for i := 0; i < len(out); i++ {
		a := unhex(hex[i*2])
		b := unhex(hex[i*2+1])
		if a < 0 || b < 0 {
			return "", errBadHex
		}
		out[i] = byte(a<<4 | b)
	}
	return string(out), nil
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

func printable(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 32 {
			return false
		}
	}
	return true
}

type hexError string

func (e hexError) Error() string { return string(e) }

const errOddHex hexError = "odd hex"
const errBadHex hexError = "bad hex"
