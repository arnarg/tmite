// Package keys derives the ephemeral server and client iroh identities
// from a pairing code. The boot-time entropy of the code is the identity;
// there is no key file anywhere.
//
//	IKM   = code[0:5]                       (5 bytes)
//	salt  = "tmite/v1"
//	HKDF-SHA256(ikm, salt, info="server") -> 32-byte server seed
//	HKDF-SHA256(ikm, salt, info="client") -> 32-byte client seed
//
// Role separation prevents self-connect and lets the server allowlist
// exactly one client EndpointID. Bump Salt (to tmite/v2) if the scheme
// ever changes; both sides embed the version and refuse mismatches at the
// wire handshake.
package keys

import (
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/tmc/go-iroh/key"

	"github.com/arnarg/tmite/internal/code"
)

// Salt is the HKDF salt and doubles as the derivation scheme version.
const Salt = "tmite/v1"

const (
	// ServerInfo is the HKDF info string for the server identity.
	ServerInfo = "server"
	// ClientInfo is the HKDF info string for the client identity.
	ClientInfo = "client"
)

// Derive derives the server and client secret keys from a pairing code.
func Derive(c [code.TotalLen]byte) (server, client key.SecretKey, err error) {
	ikm := code.IKM(c)
	serverSeed, err := hkdf.Key(sha256.New, ikm, []byte(Salt), ServerInfo, key.SeedSize)
	if err != nil {
		return server, client, err
	}
	clientSeed, err := hkdf.Key(sha256.New, ikm, []byte(Salt), ClientInfo, key.SeedSize)
	if err != nil {
		return server, client, err
	}
	server = key.NewSecretKey([key.SeedSize]byte(serverSeed))
	client = key.NewSecretKey([key.SeedSize]byte(clientSeed))
	return server, client, nil
}

// DeriveServer derives only the server secret key.
func DeriveServer(c [code.TotalLen]byte) (key.SecretKey, error) {
	server, _, err := Derive(c)
	return server, err
}

// DeriveClient derives only the client secret key.
func DeriveClient(c [code.TotalLen]byte) (key.SecretKey, error) {
	_, client, err := Derive(c)
	return client, err
}

// ServerID returns the server's EndpointID for a code.
func ServerID(c [code.TotalLen]byte) (key.EndpointID, error) {
	sk, err := DeriveServer(c)
	if err != nil {
		return key.EndpointID{}, err
	}
	return sk.Public().EndpointID(), nil
}

// ClientID returns the client's EndpointID for a code.
func ClientID(c [code.TotalLen]byte) (key.EndpointID, error) {
	sk, err := DeriveClient(c)
	if err != nil {
		return key.EndpointID{}, err
	}
	return sk.Public().EndpointID(), nil
}
