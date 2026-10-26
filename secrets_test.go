package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every test runs against a keychain in memory: none may reach the user's
// own. Every value here is invented.
func TestMain(m *testing.M) {
	MockKeychain(nil)
	os.Exit(m.Run())
}

func write(t *testing.T, name, text string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

var stravaKeys = map[string][]string{
	"strava/client_id":     {"strava.client_id"},
	"strava/client_secret": {"strava.client_secret"},
}

func TestMappingFile_NestedKeysAndNumbers(t *testing.T) {
	for _, text := range []string{
		"strava:\n  client_id: 4242\n  client_secret: s3cret\n",
		`{"strava": {"client_id": 4242, "client_secret": "s3cret"}}`,
	} {
		f := MappingFile{Path: write(t, "strava.yaml", text, 0o600), Keys: stravaKeys}
		id, err := f.Get("strava/client_id")
		secret, err2 := f.Get("strava/client_secret")
		if id != "4242" || secret != "s3cret" || err != nil || err2 != nil {
			t.Errorf("%s: id %q (%v), secret %q (%v)", text, id, err, secret, err2)
		}
		if _, err := f.Get("thunderforest/key"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a secret it does not hold: %v", err)
		}
	}
}

// A key file may be the bare key, a mapping of provider to key, or one
// holding a single key as "key".
func TestMappingFile_BareOrByName(t *testing.T) {
	keys := map[string][]string{"thunderforest/key": {"thunderforest", "key"}}
	for text, want := range map[string]string{
		"abc123\n":                            "abc123",
		"thunderforest: abc123\nother: zzz\n": "abc123",
		`{"key": "abc123"}`:                   "abc123",
	} {
		f := MappingFile{Path: write(t, "key", text, 0o600), Keys: keys, Bare: "thunderforest/key"}
		if got, err := f.Get("thunderforest/key"); got != want || err != nil {
			t.Errorf("%q: %q, %v", text, got, err)
		}
	}
}

// A file without the secret says which names it has -- names, not values --
// and nothing of what a file that is not a mapping holds.
func TestMappingFile_SaysWhatItHasButNoValue(t *testing.T) {
	keys := map[string][]string{"thunderforest/key": {"thunderforest", "key"}}
	f := MappingFile{Path: write(t, "key", "mapbox: s3cret-value\n", 0o600), Keys: keys, Bare: "thunderforest/key"}
	_, err := f.Get("thunderforest/key")
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), `"mapbox"`) || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("err %v", err)
	}
	f = MappingFile{Path: write(t, "strava.yaml", "strava: [s3cret-value\n", 0o600), Keys: stravaKeys}
	_, err = f.Get("strava/client_secret")
	if !errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("err %v", err)
	}
}

func TestMappingFile_MissingAndOptional(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strava.yaml")
	if _, err := (MappingFile{Path: path, Keys: stravaKeys, Optional: true}).Get("strava/client_id"); !errors.Is(err, ErrNotFound) {
		t.Errorf("optional: %v", err)
	}
	if _, err := (MappingFile{Path: path, Keys: stravaKeys}).Get("strava/client_id"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("named: %v", err)
	}
}

func TestMappingFile_Warning(t *testing.T) {
	if w := (MappingFile{Path: write(t, "k", "x", 0o644)}).Warning(); !strings.Contains(w, "chmod 600") {
		t.Errorf("warning %q", w)
	}
	if w := (MappingFile{Path: write(t, "k", "x", 0o600)}).Warning(); w != "" {
		t.Errorf("warning %q", w)
	}
}

// The environment comes first, then the keychain, then the file; when none
// has the secret the error says where it was looked for.
func TestChain_InOrder(t *testing.T) {
	t.Setenv(EnvStore, "")
	t.Setenv("TEST_SECRET", "")
	file := MappingFile{Path: write(t, "strava.yaml", "strava:\n  client_secret: from-file\n", 0o600), Keys: stravaKeys}
	chain := Chain{Env{"strava/client_secret": "TEST_SECRET"}, Keychain{}, file}
	if v, from, _ := chain.Get("strava/client_secret"); v != "from-file" || from.Where("") != file.Path {
		t.Errorf("%q from %v", v, from)
	}
	if err := (Keychain{}).Set("strava/client_secret", "from-keychain"); err != nil {
		t.Fatal(err)
	}
	defer Keychain{}.Delete("strava/client_secret")
	if v, _, _ := chain.Get("strava/client_secret"); v != "from-keychain" {
		t.Errorf("%q", v)
	}
	t.Setenv("TEST_SECRET", "from-env")
	if v, _, _ := chain.Get("strava/client_secret"); v != "from-env" {
		t.Errorf("%q", v)
	}
	_, _, err := chain.Get("strava/client_id")
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "Keychain") && !strings.Contains(err.Error(), "keyring") && !strings.Contains(err.Error(), "Credential") ||
		!strings.Contains(err.Error(), file.Path) {
		t.Errorf("err %v", err)
	}
}

// SECRETS_STORE=file never touches the keychain, even a broken one.
func TestKeychain_TurnedOff(t *testing.T) {
	defer MockKeychain(nil)
	MockKeychain(errors.New("must not be asked"))
	t.Setenv(EnvStore, "file")
	if _, err := (Keychain{}).Get("strava/client_secret"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get: %v", err)
	}
	if w := (Keychain{}).Where("strava/client_secret"); w != "" {
		t.Errorf("where %q", w)
	}
	file := File{Path: filepath.Join(t.TempDir(), "token.json"), Name: "strava/token"}
	if s := Kept(file); s != Store(file) {
		t.Errorf("kept in %v", s)
	}
}

// A system without a keychain that answers keeps secrets in files, unless
// the keychain was asked for.
func TestKeychain_NoneAnswers(t *testing.T) {
	defer MockKeychain(nil)
	MockKeychain(errors.New("no secret service"))
	t.Setenv(EnvStore, "")
	file := File{Path: filepath.Join(t.TempDir(), "token.json"), Name: "strava/token"}
	if s := Kept(file); s != Store(file) {
		t.Errorf("kept in %v", s)
	}
	t.Setenv(EnvStore, "keychain")
	if err := Kept(file).Set("strava/token", "t"); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Errorf("asked for: %v", err)
	}
	t.Setenv(EnvStore, "sometimes")
	if _, err := (Keychain{}).Get("x/y"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("not understood: %v", err)
	}
}

// A secret kept in a file before the keychain was is moved into it when it
// is first read, and the file deleted.
func TestKept_MovedFromTheFile(t *testing.T) {
	t.Setenv(EnvStore, "")
	file := File{Path: filepath.Join(t.TempDir(), "token.json"), Name: "strava/token"}
	if err := file.Set("strava/token", `{"t":1}`); err != nil {
		t.Fatal(err)
	}
	s := Kept(file)
	if v, err := s.Get("strava/token"); v != `{"t":1}` || err != nil {
		t.Fatalf("%q, %v", v, err)
	}
	if _, err := os.Stat(file.Path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file kept: %v", err)
	}
	if v, _ := (Keychain{}).Get("strava/token"); v != `{"t":1}` {
		t.Errorf("keychain holds %q", v)
	}
	if err := s.Delete("strava/token"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("strava/token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

func TestFile_ForItsOwnerAlone(t *testing.T) {
	file := File{Path: filepath.Join(t.TempDir(), "sub", "token.json"), Name: "strava/token"}
	if err := file.Set("strava/token", "t"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", info.Mode().Perm(), err)
	}
	if err := file.Delete("strava/token"); err != nil {
		t.Fatal(err)
	}
	if err := file.Delete("strava/token"); err != nil {
		t.Errorf("deleting what is gone: %v", err)
	}
}
