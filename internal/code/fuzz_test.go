package code

import (
	"strings"
	"testing"
)

// FuzzDecode feeds arbitrary argv-like word lists into Decode. It must
// never panic, and any successful decode must round-trip.
func FuzzDecode(f *testing.F) {
	f.Add("cigar piano round arizona academy")
	f.Add("cigar piano round arizona canal")
	f.Add("")
	f.Add("a b")
	f.Add("CIGAR Piano ROUND arizona  academy ")
	f.Add("cigar piano round arizona academy extra")
	f.Add("cigar\tpiano\nround\r\narizona   academy")
	f.Fuzz(func(t *testing.T, s string) {
		words := strings.Fields(s)
		c, err := Decode(words)
		if err != nil {
			return
		}
		if len(words) != WordCount {
			t.Fatalf("Decode accepted %d words", len(words))
		}
		re, err := Decode(Encode(c))
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if re != c {
			t.Fatalf("round trip mismatch: %x != %x", re, c)
		}
		if !validLastWord(strings.ToLower(strings.TrimSpace(words[WordCount-1]))) {
			t.Fatalf("accepted invalid last word %q", words[WordCount-1])
		}
	})
}

// FuzzEncodeBytes checks that any 6 bytes encode to words that decode back
// to the same 6 bytes.
func FuzzEncodeBytes(f *testing.F) {
	f.Add([]byte{0xde, 0xad, 0xbe, 0xef, 0x2a, 0x00})
	f.Add([]byte{0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < TotalLen {
			b = append(b, make([]byte, TotalLen-len(b))...)
		}
		var c [TotalLen]byte
		copy(c[:], b)
		// Only codes with a valid checksum can round-trip; repair it so
		// arbitrary IKM values are still exercised.
		c[RandomLen] = Checksum(c[:RandomLen])
		words := Encode(c)
		got, err := Decode(words)
		if err != nil {
			t.Fatalf("Decode(Encode(%x)) = %v", c, err)
		}
		if got != c {
			t.Fatalf("round trip mismatch: %x != %x", got, c)
		}
	})
}
