package secrets

import (
	"os"
	"strings"
)

// Env is the environment: each secret named in it read from the variable it
// maps to, "strava/client_secret" from STRAVA_CLIENT_SECRET. A variable that
// is unset or empty does not have the secret.
type Env map[string]string

func (e Env) Get(name string) (string, error) {
	v, ok := e[name]
	if !ok {
		return "", ErrNotFound
	}
	if s := strings.TrimSpace(os.Getenv(v)); s != "" {
		return s, nil
	}
	return "", ErrNotFound
}

func (e Env) Where(name string) string {
	if v, ok := e[name]; ok {
		return "$" + v
	}
	return ""
}
