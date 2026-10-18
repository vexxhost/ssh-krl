package source

import "golang.org/x/crypto/ssh"

func sshAuthorized(key ssh.PublicKey) []byte { return ssh.MarshalAuthorizedKey(key) }
