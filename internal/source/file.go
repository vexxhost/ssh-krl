package source

import (
	"context"
	"fmt"
	"os"
	"sort"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/vexxhost/ssh-krl/internal/revocation"
)

// File reads entries from a YAML (or JSON) file on every refresh:
//
//	cas:
//	  users: ssh-ed25519 AAAA...
//	revocations:
//	  alice:
//	    key_id: alice@example.com
//	    reason: left the company
type File struct {
	Path string
}

type fileContent struct {
	CAs         map[string]string         `yaml:"cas"`
	Revocations map[string]map[string]any `yaml:"revocations"`
}

func (f *File) load() (fileContent, error) {
	var c fileContent
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("%s: %w", f.Path, err)
	}
	return c, nil
}

// Entries implements Source.
func (f *File) Entries(_ context.Context) ([]revocation.Entry, []error, error) {
	c, err := f.load()
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(c.Revocations))
	for name := range c.Revocations {
		names = append(names, name)
	}
	sort.Strings(names)
	var entries []revocation.Entry
	var invalid []error
	for _, name := range names {
		e, err := revocation.FromMap(name, c.Revocations[name])
		if err != nil {
			invalid = append(invalid, fmt.Errorf("%s: %w", name, err))
			continue
		}
		entries = append(entries, e)
	}
	return entries, invalid, nil
}

// ResolveCA implements Source. A literal public key is returned as is;
// otherwise ref names an entry under cas.
func (f *File) ResolveCA(_ context.Context, ref string) (ssh.PublicKey, error) {
	if key := revocation.ParseCAKey(ref); key != nil {
		return key, nil
	}
	c, err := f.load()
	if err != nil {
		return nil, err
	}
	v, ok := c.CAs[ref]
	if !ok {
		return nil, fmt.Errorf("unknown CA %q", ref)
	}
	key := revocation.ParseCAKey(v)
	if key == nil {
		return nil, fmt.Errorf("CA %q is not a public key", ref)
	}
	return key, nil
}

// String implements Source.
func (f *File) String() string { return "file:" + f.Path }
