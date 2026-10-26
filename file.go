package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// MappingFile is a file a user writes: a YAML or JSON mapping with each
// secret at a path of keys in it, or, for a file holding a single secret,
// that secret as the file's whole text.
//
//	strava:
//	  client_id: 12345
//	  client_secret: 0123abcd...
//
// It is only read: a program does not rewrite the user's file.
//
// A file that is not a mapping is not reported as malformed, with what the
// parser made of it: what it holds may be the secret. It is taken as a bare
// secret where Bare names one, and is otherwise a file without the secret.
type MappingFile struct {
	Path string
	// Keys are where each secret is in the mapping: one dotted path of
	// keys, "strava.client_secret", or several, the first that is there
	// taken.
	Keys map[string][]string
	// Bare is the secret a file that is not a mapping holds, if any.
	Bare string
	// Optional is a file that need not be there: one the program looks
	// for in its usual place, rather than one its user named. A file
	// named and not there is an error, and the chain stops at it.
	Optional bool
}

func (f MappingFile) Get(name string) (string, error) {
	paths, ok := f.Keys[name]
	if !ok && name != f.Bare {
		return "", ErrNotFound
	}
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) && f.Optional {
		return "", ErrNotFound
	}
	if err != nil {
		// os.ReadFile's error names the path and why, never the contents.
		return "", fmt.Errorf("reading %s: %w", name, err)
	}
	text := strings.TrimSpace(string(data))
	m := mapping(text)
	if m == nil {
		if name == f.Bare && text != "" {
			return text, nil
		}
		if text == "" {
			return "", fmt.Errorf("%w: %s is empty", ErrNotFound, f.Path)
		}
		return "", fmt.Errorf("%w: %s is not a YAML or JSON mapping", ErrNotFound, f.Path)
	}
	for _, p := range paths {
		if v := lookup(m, strings.Split(p, ".")); v != "" {
			return v, nil
		}
	}
	// The mapping's keys are names, not secrets, so naming them is safe,
	// and is what makes a file with the wrong ones put right.
	return "", fmt.Errorf("%w: %s has no %s, but %s", ErrNotFound, f.Path, orList(paths), keyNames(m))
}

func (f MappingFile) Where(string) string { return f.Path }

// Warning is what is worth telling the user about the file that does not
// stop it being read: that others can read it. Empty when the file is not
// there or is theirs alone.
func (f MappingFile) Warning() string {
	info, err := os.Stat(f.Path)
	if err != nil || info.Mode().Perm()&0o077 == 0 {
		return ""
	}
	return fmt.Sprintf("%s can be read by others (mode %v); it holds a secret, so chmod 600 it", f.Path, info.Mode().Perm())
}

// mapping is text's top-level mapping, or nil when text is not one. YAML
// reads JSON too.
func mapping(text string) *yaml.Node {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	if n := doc.Content[0]; n.Kind == yaml.MappingNode {
		return n
	}
	return nil
}

// lookup is the scalar at path in mapping m, or empty. A number is read as
// it is written: a client id of 12345 is "12345".
func lookup(m *yaml.Node, path []string) string {
	n := m
	for _, k := range path {
		if n.Kind != yaml.MappingNode {
			return ""
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == k {
				next = n.Content[i+1]
			}
		}
		if next == nil {
			return ""
		}
		n = next
	}
	if n.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(n.Value)
}

// keyNames says which keys a mapping has at its top: `it names "a" and "b"`.
func keyNames(m *yaml.Node) string {
	var names []string
	for i := 0; i < len(m.Content); i += 2 {
		names = append(names, fmt.Sprintf("%q", m.Content[i].Value))
	}
	if len(names) == 0 {
		return "it is empty"
	}
	sort.Strings(names)
	return "it names " + andList(names)
}

func andList(s []string) string {
	if len(s) == 1 {
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// File is a secret a program keeps itself, whole, in a file of its own for
// its owner alone: a login's token, which it writes and rewrites.
type File struct {
	Path string
	// Name is the secret the file holds; it has no other.
	Name string
}

func (f File) Get(name string) (string, error) {
	if name != f.Name {
		return "", ErrNotFound
	}
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", name, err)
	}
	return string(data), nil
}

// Set writes the secret for its owner alone, whole or not at all: to a
// file beside it first, renamed over it, so a crash part-way leaves the
// secret it had rather than half of the new one.
func (f File) Set(name, value string) error {
	if name != f.Name {
		return fmt.Errorf("%s keeps %s, not %s", f.Path, f.Name, name)
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(f.Path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(value); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

func (f File) Delete(name string) error {
	if name != f.Name {
		return nil
	}
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (f File) Where(string) string { return f.Path }

// Kept is where a program keeps a secret it is handed itself: the keychain
// where one is used, and file where not.
//
// A secret found in file while the keychain is used -- kept there before
// the keychain was, or before the user's system had one -- is moved into
// the keychain the first time it is read, and the file deleted; it stays in
// the file, and is read from there, if the keychain will not take it.
func Kept(file File) Store {
	if KeychainUsed() {
		return moving{file}
	}
	if err := keychainUsable(); !errors.Is(err, errNoKeychain) {
		// A keychain asked for and missing, or EnvStore not understood:
		// said at the first use rather than kept quiet in a file.
		return broken{err}
	}
	return file
}

// moving is the keychain, taking the secret over from a file it was kept in
// before.
type moving struct{ file File }

func (m moving) Get(name string) (string, error) {
	v, err := Keychain{}.Get(name)
	if !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if v, err = m.file.Get(name); err != nil {
		return "", err
	}
	if (Keychain{}).Set(name, v) == nil {
		m.file.Delete(name)
	}
	return v, nil
}

func (m moving) Set(name, value string) error { return Keychain{}.Set(name, value) }

// Delete forgets the secret in both places, a file a failed move left
// behind as well.
func (m moving) Delete(name string) error {
	if err := (Keychain{}).Delete(name); err != nil {
		return err
	}
	return m.file.Delete(name)
}

func (m moving) Where(name string) string { return Keychain{}.Where(name) }

// broken is a Store that cannot be used, and says why.
type broken struct{ err error }

func (b broken) Get(string) (string, error) { return "", b.err }
func (b broken) Set(string, string) error   { return b.err }
func (b broken) Delete(string) error        { return b.err }
func (b broken) Where(string) string        { return "" }
