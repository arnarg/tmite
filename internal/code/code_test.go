package code

import (
	"errors"
	"strings"
	"testing"

	"github.com/schollz/mnemonicode"
)

func TestEncodeIsFiveWords(t *testing.T) {
	for range 100 {
		c, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		words := Encode(c)
		if len(words) != WordCount {
			t.Fatalf("Encode(%x) = %d words, want %d", c, len(words), WordCount)
		}
		if mnemonicode.WordsRequired(TotalLen) != WordCount {
			t.Fatalf("WordsRequired(%d) = %d, want %d", TotalLen, mnemonicode.WordsRequired(TotalLen), WordCount)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for range 100 {
		c, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(Encode(c))
		if err != nil {
			t.Fatalf("Decode(Encode(%x)): %v", c, err)
		}
		if got != c {
			t.Fatalf("round trip mismatch: got %x want %x", got, c)
		}
	}
}

func TestDecodeCaseAndWhitespace(t *testing.T) {
	c, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	words := Encode(c)
	mangled := make([]string, len(words))
	for i, w := range words {
		mangled[i] = " " + strings.ToUpper(w[:1]) + w[1:] + " "
	}
	got, err := Decode(mangled)
	if err != nil {
		t.Fatalf("Decode(mangled): %v", err)
	}
	if got != c {
		t.Fatalf("mangled round trip mismatch: got %x want %x", got, c)
	}
}

func TestGoldenVector(t *testing.T) {
	// Pins the mnemonicode encoding of a fixed code so that a word-list
	// change in the dependency is caught immediately.
	c := [TotalLen]byte{0xde, 0xad, 0xbe, 0xef, 0x2a, Checksum([]byte{0xde, 0xad, 0xbe, 0xef, 0x2a})}
	words := Encode(c)
	want := []string{"cigar", "piano", "round", "arizona", "academy"}
	if len(words) != len(want) {
		t.Fatalf("Encode golden = %v, want %v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Fatalf("Encode golden[%d] = %q, want %q (all: %v)", i, words[i], want[i], words)
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	c, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	words := Encode(c)

	// Wrong number of words.
	if _, err := Decode(words[:4]); !errors.Is(err, ErrWordCount) {
		t.Errorf("Decode(4 words) err = %v, want ErrWordCount", err)
	}

	// Unknown word.
	bad := append([]string(nil), words...)
	bad[2] = "notaword"
	if _, err := Decode(bad); err == nil {
		t.Error("Decode(unknown word) = nil error, want typed word error")
	} else if !strings.Contains(err.Error(), "notaword") {
		t.Errorf("Decode(unknown word) err = %v, want it to name the word", err)
	}

	// Checksum mismatch: swap a valid middle word for another valid word.
	// Deterministic: fixed code, "aloha" has word-list index 29.
	fixed := [TotalLen]byte{0x01, 0x02, 0x03, 0x04, 0x05, Checksum([]byte{0x01, 0x02, 0x03, 0x04, 0x05})}
	flipped := append([]string(nil), Encode(fixed)...)
	flipped[3] = "aloha"
	if _, err := Decode(flipped); !errors.Is(err, ErrChecksum) {
		t.Errorf("Decode(flipped) err = %v, want ErrChecksum", err)
	}

	// Last-word constraint: "canal" has word-list index 100 and can never
	// be the final word of a 6-byte encoding (valid indices are 0..40).
	badLast := append([]string(nil), words...)
	badLast[4] = "canal"
	if _, err := Decode(badLast); !errors.Is(err, ErrLastWord) {
		t.Errorf("Decode(bad last word) err = %v, want ErrLastWord", err)
	}
}

func TestChecksumSeparation(t *testing.T) {
	// Two codes differing only in the checksum byte must both be
	// constructible but only one decodes.
	var a [TotalLen]byte
	copy(a[:RandomLen], []byte{1, 2, 3, 4, 5})
	a[RandomLen] = Checksum(a[:RandomLen])
	b := a
	b[RandomLen] ^= 1
	if _, err := Decode(Encode(a)); err != nil {
		t.Fatalf("Decode(a): %v", err)
	}
	if _, err := Decode(Encode(b)); err == nil {
		t.Error("Decode(b) = nil error, want checksum failure")
	}
}

func TestIKM(t *testing.T) {
	c := [TotalLen]byte{1, 2, 3, 4, 5, 6}
	ikm := IKM(c)
	if len(ikm) != 5 {
		t.Fatalf("IKM length = %d, want 5", len(ikm))
	}
	for i := range ikm {
		if ikm[i] != c[i] {
			t.Fatalf("IKM[%d] = %d, want %d", i, ikm[i], c[i])
		}
	}
	// Mutating the result must not alias the original.
	ikm[0] = 0xff
	if c[0] == 0xff {
		t.Fatal("IKM aliases code storage")
	}
}

func TestValidLastWordSetSmall(t *testing.T) {
	n := len(validLastWords())
	if n == 0 || n > 41 {
		t.Fatalf("valid last word set has %d entries, want 1..41", n)
	}
}
