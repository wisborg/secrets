// Package secrets finds the secrets a program is given -- API keys, an OAuth
// application's client secret -- wherever its user keeps them, and keeps the
// ones a program is handed itself, such as a login's token, in the safest
// place the system offers.
//
// A secret is known by a name of a service and an item, "strava/client_secret",
// and is looked for in a Chain of Sources in turn: typically the environment,
// then the system's keychain, then a file the user wrote. The keychain is the
// macOS Keychain, the Windows Credential Manager, or a Secret Service such as
// GNOME Keyring or KWallet on Linux; where the system has none that answers --
// a server with no desktop session -- files alone are used, as they were
// before the keychain was.
//
// No error this package returns, and no description of where a secret is,
// holds a secret's value: they name secrets and places, never what is in
// them, so a program can print any of them as they are.
package secrets

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound is a secret that is not where it was looked for. A Chain goes
// on to its next Source past one, and stops at any other error.
var ErrNotFound = errors.New("secret not found")

// Source is somewhere secrets can be found.
type Source interface {
	// Get is the named secret's value, or ErrNotFound.
	Get(name string) (string, error)
	// Where is where the named secret is looked for here, for the user to
	// read: "$STRAVA_CLIENT_SECRET", "/home/ann/.config/strava.yaml". It
	// is empty for a source that is not in use, which a Chain then leaves
	// out of what it says it looked in.
	Where(name string) string
}

// Store is a Source a program can also keep secrets in.
type Store interface {
	Source
	Set(name, value string) error
	// Delete forgets the named secret; one that is not there is already
	// gone, and no error.
	Delete(name string) error
}

// Chain is where a secret is looked for, in order: the first Source to have
// it gives it.
type Chain []Source

// Get is the named secret from the first Source that has it, and that
// Source. When none has it the error is ErrNotFound, saying where it was
// looked for.
func (c Chain) Get(name string) (string, Source, error) {
	var where, notes []string
	for _, s := range c {
		v, err := s.Get(name)
		if err == nil && v != "" {
			return v, s, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return "", s, err
		}
		if w := s.Where(name); w != "" {
			where = append(where, w)
		}
		// A Source may say more than that it has no such secret -- which
		// names a file does hold -- and that is worth keeping.
		if err != nil && err.Error() != ErrNotFound.Error() {
			notes = append(notes, strings.TrimPrefix(err.Error(), ErrNotFound.Error()+": "))
		}
	}
	msg := fmt.Sprintf("%s is not set", name)
	if len(where) > 0 {
		msg = fmt.Sprintf("%s is not in %s", name, orList(where))
	}
	if len(notes) > 0 {
		msg += " (" + strings.Join(notes, "; ") + ")"
	}
	return "", nil, fmt.Errorf("%w: %s", ErrNotFound, msg)
}

// orList is "a", "a or b", "a, b or c".
func orList(s []string) string {
	if len(s) == 1 {
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " or " + s[len(s)-1]
}

// Secret is one secret a program uses, and where it looks for it: what a
// list of a program's secrets shows, and what lets its user set one.
type Secret struct {
	// Name is the secret's name: "strava/client_secret".
	Name string
	// About is what it is, for a list of them: "client secret of your
	// Strava API application".
	About string
	// Sources are where it is looked for, in order.
	Sources Chain
	// Kept is true of a secret the program keeps itself, such as a login's
	// token: one its user does not set, but logs in for.
	Kept bool
}

// Get is the secret's value, and the Source it was found in.
func (s Secret) Get() (string, Source, error) { return s.Sources.Get(s.Name) }
