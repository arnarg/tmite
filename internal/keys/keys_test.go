package keys

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/arnarg/tmite/internal/code"
)

func TestDeriveDeterministic(t *testing.T) {
	c, err := code.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s1, cl1, err := Derive(c)
	if err != nil {
		t.Fatal(err)
	}
	s2, cl2, err := Derive(c)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Bytes() != s2.Bytes() || cl1.Bytes() != cl2.Bytes() {
		t.Fatal("derivation not deterministic")
	}
	if s1.Bytes() == cl1.Bytes() {
		t.Fatal("server and client seeds collide")
	}
}

func TestRoleSeparation(t *testing.T) {
	// Server and client IDs must differ so the server can allowlist the
	// client and neither can self-connect.
	for range 20 {
		c, err := code.Generate()
		if err != nil {
			t.Fatal(err)
		}
		sid, err := ServerID(c)
		if err != nil {
			t.Fatal(err)
		}
		cid, err := ClientID(c)
		if err != nil {
			t.Fatal(err)
		}
		if sid == cid {
			t.Fatalf("code %x: server and client EndpointIDs collide", c)
		}
	}
}

// TestGoldenVectors pins the derivation so that client and server can
// never silently diverge. Any change here is a breaking change to the
// pairing scheme and must bump Salt.
func TestGoldenVectors(t *testing.T) {
	ikm := []byte{0xde, 0xad, 0xbe, 0xef, 0x2a}
	var c [code.TotalLen]byte
	copy(c[:], ikm)
	c[code.RandomLen] = code.Checksum(c[:code.RandomLen])

	serverSeed, err := hkdf.Key(sha256.New, ikm, []byte(Salt), ServerInfo, 32)
	if err != nil {
		t.Fatal(err)
	}
	clientSeed, err := hkdf.Key(sha256.New, ikm, []byte(Salt), ClientInfo, 32)
	if err != nil {
		t.Fatal(err)
	}

	server, client, err := Derive(c)
	if err != nil {
		t.Fatal(err)
	}

	sb := server.Bytes()
	cb := client.Bytes()
	if got := hex.EncodeToString(sb[:]); got != hex.EncodeToString(serverSeed) {
		t.Errorf("server seed mismatch:\ngot  %s\nwant %s", got, hex.EncodeToString(serverSeed))
	}
	if got := hex.EncodeToString(cb[:]); got != hex.EncodeToString(clientSeed) {
		t.Errorf("client seed mismatch:\ngot  %s\nwant %s", got, hex.EncodeToString(clientSeed))
	}

	// Frozen values: update these only together with a Salt bump.
	// Regenerate with: go test ./internal/keys/ -run TestGoldenVectors -v
	const (
		frozenServerSeed = "1bac05162e71b57ea9c5553fd2de4a42deb89a2dceeb3174328c553c9ca8951a"
		frozenClientSeed = "9ec5d1bb9a09f1de1c306129281ef8cee0dcc8afcdde8b1aba44fce6ddcbf35e"
	)
	if got := hex.EncodeToString(serverSeed); got != frozenServerSeed {
		t.Errorf("frozen server seed mismatch:\ngot  %s\nwant %s\n(update only with a Salt bump)", got, frozenServerSeed)
	}
	if got := hex.EncodeToString(clientSeed); got != frozenClientSeed {
		t.Errorf("frozen client seed mismatch:\ngot  %s\nwant %s\n(update only with a Salt bump)", got, frozenClientSeed)
	}
}
