package idna

import "golang.org/x/net/idna"

func ToASCII(s string) (string, error) {
	return idna.Lookup.ToASCII(s)
}
