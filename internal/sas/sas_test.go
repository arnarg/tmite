package sas

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestCommitmentMatchesVectors(t *testing.T) {
	var pub [PublicKeySize]byte
	for i := range pub {
		pub[i] = byte(i)
	}
	// Reference: SHA-256(CommitTag || pub).
	h := sha256.New()
	h.Write([]byte(CommitTag))
	h.Write(pub[:])
	want := h.Sum(nil)
	if got := Commitment(pub); !bytes.Equal(got[:], want) {
		t.Fatalf("commitment mismatch:\ngot  %x\nwant %x", got, want)
	}
}

func TestCommitmentDomainSeparation(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	c := Commitment(kp.Public())
	// A bare SHA-256 of the key (no tag) must not be a valid
	// commitment; neither must the SAS-tag domain.
	bare := sha256.Sum256(kp.pub[:])
	if bytes.Equal(c[:], bare[:]) {
		t.Fatal("commitment collides with untagged hash")
	}
	h := sha256.New()
	h.Write([]byte(Tag))
	h.Write(kp.pub[:])
	if bytes.Equal(c[:], h.Sum(nil)) {
		t.Fatal("commitment collides with SAS domain")
	}
}

func TestSharedSecretAgreement(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	sa, err := a.Shared(b.Public())
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Shared(a.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("shared secrets differ")
	}
	if len(sa) != 32 {
		t.Fatalf("shared secret len = %d, want 32", len(sa))
	}
}

func TestSharedRejectsLowOrderKey(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	var zero [PublicKeySize]byte
	if _, err := a.Shared(zero); err == nil {
		t.Fatal("DH with all-zero public key must fail")
	}
}

func TestComputeDeterministic(t *testing.T) {
	var cp, sp [PublicKeySize]byte
	for i := range cp {
		cp[i] = byte(i)
		sp[i] = 0xff - byte(i)
	}
	ss := bytes.Repeat([]byte{0x42}, 32)
	fwd := []byte("localhost:22,localhost:5432")
	s1 := Compute(ss, fwd, cp, sp)
	s2 := Compute(ss, fwd, cp, sp)
	if s1 != s2 {
		t.Fatalf("SAS not deterministic: %q vs %q", s1, s2)
	}
	if len(s1) != Digits {
		t.Fatalf("SAS %q has %d digits, want %d", s1, len(s1), Digits)
	}
	for _, r := range s1 {
		if r < '0' || r > '9' {
			t.Fatalf("SAS %q contains non-digit %q", s1, r)
		}
	}
}

func TestComputeBindsTranscript(t *testing.T) {
	var cp, sp [PublicKeySize]byte
	ss := bytes.Repeat([]byte{0x42}, 32)
	fwd := []byte("localhost:22")
	base := Compute(ss, fwd, cp, sp)

	// Changing any input must change the SAS (with overwhelming
	// probability; a collision here would be a 1-in-1M fluke, but
	// these specific vectors are fixed).
	cp[0] = 1
	if got := Compute(ss, fwd, cp, sp); got == base {
		t.Error("SAS unchanged after client key change")
	}
	cp[0] = 0
	sp[0] = 1
	if got := Compute(ss, fwd, cp, sp); got == base {
		t.Error("SAS unchanged after server key change")
	}
	sp[0] = 0
	if got := Compute(ss, []byte("localhost:23"), cp, sp); got == base {
		t.Error("SAS unchanged after forward line change")
	}
	if got := Compute(bytes.Repeat([]byte{0x43}, 32), fwd, cp, sp); got == base {
		t.Error("SAS unchanged after shared secret change")
	}
}

// TestComputeVector pins the derivation so client and server can never
// silently diverge. Any change here is a breaking protocol change and
// must bump Tag.
func TestComputeVector(t *testing.T) {
	var cp, sp [PublicKeySize]byte
	for i := range cp {
		cp[i] = byte(i)
		sp[i] = byte(i * 3)
	}
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte(i * 7)
	}
	fwd := []byte("localhost:22,localhost:5432")

	// Independent reference implementation of the spec.
	h := sha256.New()
	h.Write([]byte(Tag))
	h.Write(ss)
	var flen [2]byte
	binary.BigEndian.PutUint16(flen[:], uint16(len(fwd)))
	h.Write(flen[:])
	h.Write(fwd)
	h.Write(cp[:])
	h.Write(sp[:])
	sum := h.Sum(nil)
	want := binary.BigEndian.Uint32(sum[:4]) % 1_000_000

	got := Compute(ss, fwd, cp, sp)
	var gotNum int
	if _, err := fmtSscan(got, &gotNum); err != nil {
		t.Fatal(err)
	}
	if uint32(gotNum) != want {
		t.Fatalf("SAS = %s, want %06d", got, want)
	}
	t.Logf("frozen SAS vector: %s (update only with a Tag bump)", got)
}

func fmtSscan(s string, v *int) (int, error) {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	*v = n
	return 1, nil
}
