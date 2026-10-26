package secrets

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
)

// EnvStore is the variable that says whether the keychain is used: "file"
// never to touch it, files alone kept and read; "keychain" always to, and
// to fail where there is none; unset, to use it where the system has one
// that answers.
const EnvStore = "SECRETS_STORE"

// keychainPrefix begins the service every secret is kept under in the
// keychain, so they are found together there and apart from other
// programs': "strava/client_secret" is the item "client_secret" of the
// service "wisborg/strava".
const keychainPrefix = "wisborg/"

// Keychain is the system's keychain, as EnvStore says to use it.
//
// On macOS it is reached through /usr/bin/security, and the value is handed
// to it on its standard input rather than its command line, where any
// process could read it. The Keychain then lets any program the user runs
// read it through the same tool without asking -- as any program of theirs
// can read a file of theirs -- but it is kept encrypted, out of the files a
// backup or a sync copies, and away from other users.
type Keychain struct{}

func (Keychain) Get(name string) (string, error) {
	if err := keychainUsable(); err != nil {
		if errors.Is(err, errNoKeychain) {
			return "", ErrNotFound
		}
		return "", err
	}
	service, item := keychainItem(name)
	v, err := keyring.Get(service, item)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("reading %s from %s: %w", name, KeychainName(), err)
	}
	return v, nil
}

func (Keychain) Set(name, value string) error {
	if err := keychainUsable(); err != nil {
		return err
	}
	service, item := keychainItem(name)
	if err := keyring.Set(service, item, value); err != nil {
		return fmt.Errorf("keeping %s in %s: %w", name, KeychainName(), err)
	}
	return nil
}

func (Keychain) Delete(name string) error {
	if err := keychainUsable(); err != nil {
		if errors.Is(err, errNoKeychain) {
			return nil
		}
		return err
	}
	service, item := keychainItem(name)
	if err := keyring.Delete(service, item); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("removing %s from %s: %w", name, KeychainName(), err)
	}
	return nil
}

// Where is the keychain and the item the secret is kept as, or empty when
// the keychain is not used.
func (Keychain) Where(name string) string {
	if keychainUsable() != nil {
		return ""
	}
	service, item := keychainItem(name)
	return fmt.Sprintf("%s (%s, %s)", KeychainName(), service, item)
}

func keychainItem(name string) (service, item string) {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return keychainPrefix + name[:i], name[i+1:]
	}
	return strings.TrimSuffix(keychainPrefix, "/"), name
}

// KeychainName is what the system's keychain is called.
func KeychainName() string {
	switch runtime.GOOS {
	case "darwin":
		return "the macOS Keychain"
	case "windows":
		return "the Windows Credential Manager"
	default:
		return "the Secret Service keyring"
	}
}

// errNoKeychain is a keychain not used, because there is none that answers
// or EnvStore says not to.
var errNoKeychain = errors.New("no keychain is used")

// KeychainUsed is whether the keychain is used: as EnvStore says, and
// unless it says to always, whether the system has one that answers.
func KeychainUsed() bool { return keychainUsable() == nil }

// KeychainStatus says whether the keychain is used and why, for a user
// asking where their secrets are.
func KeychainStatus() string {
	if err := keychainUsable(); err != nil {
		return strings.TrimPrefix(err.Error(), errNoKeychain.Error()+": ")
	}
	return KeychainName() + ", used"
}

// keychainUsable is nil when the keychain is used; errNoKeychain, saying
// why, when it is not; and another error when EnvStore is not understood or
// asks for a keychain there is not.
func keychainUsable() error {
	switch mode := os.Getenv(EnvStore); mode {
	case "file":
		return fmt.Errorf("%w: $%s is file", errNoKeychain, EnvStore)
	case "keychain":
		if err := probe(); err != nil {
			return fmt.Errorf("$%s is keychain, but %s does not answer: %v", EnvStore, KeychainName(), err)
		}
		return nil
	case "":
		if err := probe(); err != nil {
			return fmt.Errorf("%w: %s does not answer (%v), so files are used", errNoKeychain, KeychainName(), err)
		}
		return nil
	default:
		return fmt.Errorf("$%s is %q; it is keychain, file, or unset to use the keychain where there is one", EnvStore, mode)
	}
}

var (
	probeOnce sync.Once
	probeErr  error
)

// probe asks the keychain for an item that is never kept, once: an answer
// that it is not there is a keychain that answers. A locked one the system
// cannot unlock without the user -- over ssh -- or none at all answers
// otherwise.
func probe() error {
	probeOnce.Do(func() {
		_, err := keyring.Get(keychainPrefix+"secrets", "probe")
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			probeErr = err
		}
	})
	return probeErr
}

// MockKeychain replaces the system's keychain, for the rest of the process,
// with one in memory -- broken with err, when it is not nil -- for a test
// that must never reach the user's own.
func MockKeychain(err error) {
	if err != nil {
		keyring.MockInitWithError(err)
	} else {
		keyring.MockInit()
	}
	probeOnce = sync.Once{}
	probeErr = nil
}
