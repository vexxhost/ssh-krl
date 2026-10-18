// Package krl builds OpenSSH key revocation lists (KRLs) in the binary format
// described by PROTOCOL.krl in OpenSSH, the format sshd reads through its
// RevokedKeys option.
package krl

import (
	"bytes"
	"encoding/binary"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	magic         = "SSHKRL\n\x00"
	formatVersion = 1

	sectionCertificates = 1
	sectionExplicitKey  = 2

	certSectionSerialList = 0x20
	certSectionKeyID      = 0x23
)

// Builder accumulates revocations and marshals them into a KRL.
//
// Certificates are revoked by serial number or key ID under a specific CA,
// or by key ID under any CA. Plain keys, including CA keys, are revoked
// explicitly; sshd also refuses certificates whose underlying key or signing
// CA key is revoked this way.
type Builder struct {
	comment string
	cas     map[string]*caSection
	keys    map[string][]byte
}

type caSection struct {
	key     []byte
	serials map[uint64]struct{}
	keyIDs  map[string]struct{}
}

// NewBuilder returns an empty Builder. The comment is stored in the KRL header.
func NewBuilder(comment string) *Builder {
	return &Builder{comment: comment, cas: map[string]*caSection{}, keys: map[string][]byte{}}
}

func (b *Builder) ca(ca ssh.PublicKey) *caSection {
	var blob []byte
	if ca != nil {
		blob = plain(ca).Marshal()
	}
	s, ok := b.cas[string(blob)]
	if !ok {
		s = &caSection{key: blob, serials: map[uint64]struct{}{}, keyIDs: map[string]struct{}{}}
		b.cas[string(blob)] = s
	}
	return s
}

// RevokeSerial revokes the certificate with the given serial signed by ca.
func (b *Builder) RevokeSerial(ca ssh.PublicKey, serial uint64) {
	b.ca(ca).serials[serial] = struct{}{}
}

// RevokeKeyID revokes certificates with the given key ID signed by ca, or by
// any CA when ca is nil.
func (b *Builder) RevokeKeyID(ca ssh.PublicKey, keyID string) {
	b.ca(ca).keyIDs[keyID] = struct{}{}
}

// RevokeKey revokes a plain public key. A certificate is reduced to its
// underlying key.
func (b *Builder) RevokeKey(key ssh.PublicKey) {
	blob := plain(key).Marshal()
	b.keys[string(blob)] = blob
}

// Len returns the number of revocations held by the builder.
func (b *Builder) Len() int {
	n := len(b.keys)
	for _, s := range b.cas {
		n += len(s.serials) + len(s.keyIDs)
	}
	return n
}

// Marshal encodes the KRL. Output is deterministic for a given set of
// revocations, version and generation time.
func (b *Builder) Marshal(version uint64, generated time.Time) []byte {
	var out bytes.Buffer
	out.WriteString(magic)
	putUint32(&out, formatVersion)
	putUint64(&out, version)
	putUint64(&out, unixSeconds(generated))
	putUint64(&out, 0)
	putString(&out, nil)
	putString(&out, []byte(b.comment))

	cas := make([]string, 0, len(b.cas))
	for k := range b.cas {
		cas = append(cas, k)
	}
	sort.Strings(cas)
	for _, k := range cas {
		s := b.cas[k]
		if len(s.serials) == 0 && len(s.keyIDs) == 0 {
			continue
		}
		var sec bytes.Buffer
		putString(&sec, s.key)
		putString(&sec, nil)
		if len(s.serials) > 0 {
			serials := make([]uint64, 0, len(s.serials))
			for v := range s.serials {
				serials = append(serials, v)
			}
			sort.Slice(serials, func(i, j int) bool { return serials[i] < serials[j] })
			var sub bytes.Buffer
			for _, v := range serials {
				putUint64(&sub, v)
			}
			sec.WriteByte(certSectionSerialList)
			putString(&sec, sub.Bytes())
		}
		if len(s.keyIDs) > 0 {
			ids := make([]string, 0, len(s.keyIDs))
			for v := range s.keyIDs {
				ids = append(ids, v)
			}
			sort.Strings(ids)
			var sub bytes.Buffer
			for _, v := range ids {
				putString(&sub, []byte(v))
			}
			sec.WriteByte(certSectionKeyID)
			putString(&sec, sub.Bytes())
		}
		out.WriteByte(sectionCertificates)
		putString(&out, sec.Bytes())
	}

	if len(b.keys) > 0 {
		blobs := make([]string, 0, len(b.keys))
		for k := range b.keys {
			blobs = append(blobs, k)
		}
		sort.Strings(blobs)
		var sec bytes.Buffer
		for _, k := range blobs {
			putString(&sec, b.keys[k])
		}
		out.WriteByte(sectionExplicitKey)
		putString(&out, sec.Bytes())
	}
	return out.Bytes()
}

func plain(key ssh.PublicKey) ssh.PublicKey {
	if cert, ok := key.(*ssh.Certificate); ok {
		return cert.Key
	}
	return key
}

func putUint32(b *bytes.Buffer, v uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	b.Write(buf[:])
}

func putUint64(b *bytes.Buffer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	b.Write(buf[:])
}

func putString(b *bytes.Buffer, s []byte) {
	putUint32(b, uint32(len(s))) // #nosec G115 -- KRL sections are far below 4 GiB
	b.Write(s)
}

// unixSeconds returns t as seconds since the epoch, clamped to zero.
func unixSeconds(t time.Time) uint64 {
	if s := t.Unix(); s > 0 {
		return uint64(s)
	}
	return 0
}

// UnixSeconds is unixSeconds for other packages.
func UnixSeconds(t time.Time) uint64 { return unixSeconds(t) }
