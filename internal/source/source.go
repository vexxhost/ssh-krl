// Package source loads revocation entries and resolves the CA keys they
// reference.
package source

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/ssh-krl/internal/revocation"
)

// Source provides revocation entries.
type Source interface {
	// Entries returns the valid entries and one error per invalid entry. A
	// non-nil error means the source could not be read at all.
	Entries(ctx context.Context) ([]revocation.Entry, []error, error)
	// ResolveCA returns the public key a CA reference names.
	ResolveCA(ctx context.Context, ref string) (ssh.PublicKey, error)
	// String describes the source for logs.
	String() string
}
