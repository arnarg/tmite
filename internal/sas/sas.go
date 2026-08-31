// Package sas implements the tmite short authentication string: a
// 6-digit number computed independently on both ends of a session from
// an ephemeral X25519 shared secret and the handshake transcript (the
// forward line and both ephemeral public keys). It is displayed on
// both screens and compared by the human; it is never transmitted.
//
// The exchange uses a hash commitment (RFC 6189 §4.4.1): the client
// first sends SHA-256 of its ephemeral public key, the server then
// reveals its key, and only then does the client reveal its own. Both
// parties' keys are therefore chosen blind, which is what makes SAS
// grinding detectable: an interposition attack cannot steer both
// displays to the same value offline, and every interactive retry
// lands a fresh SAS pair in front of the human.
package sas

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/flynn/noise"
)

// PublicKeySize is the X25519 public key size in bytes.
const PublicKeySize = 32

// CommitmentSize is the size of the SHA-256 key commitment in bytes.
const CommitmentSize = 32

// Digits is the number of decimal digits in the SAS.
const Digits = 6

// CommitTag is the domain-separation tag for the key commitment.
const CommitTag = "tmite/sas/commit/v1"

// Tag is the domain-separation tag for the SAS derivation.
const Tag = "tmite/sas/v1"

// suite fixes the X25519 curve for the ephemeral keypairs. Only the DH
// function is used; there is no Noise handshake (iroh's QUIC already
// provides transport encryption and key confirmation).
var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// Keypair is one side's ephemeral X25519 keypair for a session.
type Keypair struct {
	dh  noise.DHKey
	pub [PublicKeySize]byte
}

// Generate returns a fresh ephemeral X25519 keypair. One per session;
// anti-grinding relies on fresh keys.
func Generate() (*Keypair, error) {
	dh, err := suite.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sas: generating ephemeral key: %w", err)
	}
	kp := &Keypair{dh: dh}
	copy(kp.pub[:], dh.Public)
	return kp, nil
}

// Public returns the keypair's public key.
func (kp *Keypair) Public() [PublicKeySize]byte { return kp.pub }

// Shared computes the X25519 shared secret with the peer's public key.
func (kp *Keypair) Shared(peer [PublicKeySize]byte) ([]byte, error) {
	return suite.DH(kp.dh.Private, peer[:])
}

// Commitment returns the SHA-256 commitment to an ephemeral public
// key. The client sends it before learning the server's key and
// reveals the public key itself only afterwards; the server aborts
// unless the reveal matches.
func Commitment(pub [PublicKeySize]byte) [CommitmentSize]byte {
	h := sha256.New()
	h.Write([]byte(CommitTag))
	h.Write(pub[:])
	var out [CommitmentSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Compute maps the shared secret and handshake transcript to the
// 6-digit SAS string. The forward line (the exact bytes the client
// sent) is length-prefixed so the hash fields are unambiguous; binding
// it means a MITM who changes the targets changes both displays.
func Compute(ss, forwardLine []byte, clientPub, serverPub [PublicKeySize]byte) string {
	h := sha256.New()
	h.Write([]byte(Tag))
	h.Write(ss)
	var flen [2]byte
	binary.BigEndian.PutUint16(flen[:], uint16(len(forwardLine)))
	h.Write(flen[:])
	h.Write(forwardLine)
	h.Write(clientPub[:])
	h.Write(serverPub[:])
	sum := h.Sum(nil)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sum[:4])%1_000_000)
}
