package api

import "crypto/tls"

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}
