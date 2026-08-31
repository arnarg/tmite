// Package code implements the tmite 5-word pairing code: 5 random bytes
// plus one SHA-256 checksum byte, encoded with mnemonicode into exactly
// five words.
//
// Layout: the first 5 bytes are the key derivation input (IKM), the 6th
// byte is sha256(ikm)[0], catching roughly 255/256 of single-word typos.
package code

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/schollz/mnemonicode"
)

const (
	// RandomLen is the number of random bytes carrying entropy.
	RandomLen = 5
	// ChecksumLen is the number of trailing checksum bytes.
	ChecksumLen = 1
	// TotalLen is the full encoded length in bytes.
	TotalLen = RandomLen + ChecksumLen
	// WordCount is the number of words in a pairing code.
	WordCount = 5
)

// Sentinel errors returned (wrapped) by Decode. Word-list membership errors
// from mnemonicode are surfaced as typed mnemonicode errors.
var (
	ErrWordCount = errors.New("code: wrong number of words")
	ErrLength    = errors.New("code: wrong decoded length")
	ErrChecksum  = errors.New("code: checksum mismatch")
	ErrLastWord  = errors.New("code: invalid final word")
)

// WordCountError reports an argument count other than WordCount.
type WordCountError int

func (e WordCountError) Error() string {
	return fmt.Sprintf("%s: got %d, want %d", ErrWordCount, int(e), WordCount)
}

// Unwrap allows errors.Is(err, ErrWordCount).
func (e WordCountError) Unwrap() error { return ErrWordCount }

// LengthError reports a decoded byte length other than TotalLen.
type LengthError int

func (e LengthError) Error() string {
	return fmt.Sprintf("%s: got %d, want %d", ErrLength, int(e), TotalLen)
}

// Unwrap allows errors.Is(err, ErrLength).
func (e LengthError) Unwrap() error { return ErrLength }

// LastWordError reports a final word that cannot occur in a 6-byte
// encoding (the second word of a 2-byte tail always has word-list index
// below 41).
type LastWordError string

func (e LastWordError) Error() string { return fmt.Sprintf("%s: %q", ErrLastWord, string(e)) }

// Unwrap allows errors.Is(err, ErrLastWord).
func (e LastWordError) Unwrap() error { return ErrLastWord }

// Word returns the offending word.
func (e LastWordError) Word() string { return string(e) }

// Checksum returns the checksum byte for a 5-byte payload.
func Checksum(data []byte) byte {
	sum := sha256.Sum256(data)
	return sum[0]
}

// Generate returns a fresh code: RandomLen crypto/rand bytes (blocking
// until the kernel CRNG is seeded) plus the checksum byte.
func Generate() ([TotalLen]byte, error) {
	var c [TotalLen]byte
	if _, err := rand.Read(c[:RandomLen]); err != nil {
		return c, fmt.Errorf("code: reading random bytes: %w", err)
	}
	c[RandomLen] = Checksum(c[:RandomLen])
	return c, nil
}

// GenerateWords returns a fresh code as its five words.
func GenerateWords() ([]string, error) {
	c, err := Generate()
	if err != nil {
		return nil, err
	}
	return Encode(c), nil
}

// Encode encodes a code into exactly WordCount words.
func Encode(c [TotalLen]byte) []string {
	return mnemonicode.EncodeWordList(nil, c[:])
}

// IKM returns the 5 key-derivation input bytes of a code.
func IKM(c [TotalLen]byte) []byte {
	out := make([]byte, RandomLen)
	copy(out, c[:RandomLen])
	return out
}

// DecodeString splits s on whitespace and decodes the resulting words.
// Helpers and shells hand over the code as a single string.
func DecodeString(s string) ([TotalLen]byte, error) {
	return Decode(strings.Fields(s))
}

// Decode validates five words and returns the encoded 6 bytes. Words are
// trimmed of surrounding whitespace and matched case-insensitively, as in
// mnemonicode itself.
func Decode(words []string) ([TotalLen]byte, error) {
	var c [TotalLen]byte
	if len(words) != WordCount {
		return c, WordCountError(len(words))
	}
	trimmed := make([]string, len(words))
	for i, w := range words {
		trimmed[i] = strings.ToLower(strings.TrimSpace(w))
	}
	b, err := mnemonicode.DecodeWordList(nil, trimmed)
	if err != nil {
		return c, fmt.Errorf("code: decoding words: %w", err)
	}
	if len(b) != TotalLen {
		return c, LengthError(len(b))
	}
	if !validLastWord(trimmed[WordCount-1]) {
		return c, LastWordError(trimmed[WordCount-1])
	}
	if b[RandomLen] != Checksum(b[:RandomLen]) {
		return c, ErrChecksum
	}
	copy(c[:], b)
	return c, nil
}

// validLastWords is the set of words that can appear as the fifth word of
// a 6-byte mnemonicode encoding. In a 6-byte encoding the trailing two
// bytes expand to two words whose indices are x%1626 and x/1626%1626 for
// x < 65536, so the final word always has an index below 41. The set is
// derived from the library's own encoder so it stays correct even if the
// word list changes.
var validLastWords = sync.OnceValue(func() map[string]struct{} {
	m := make(map[string]struct{}, 64)
	var b [2]byte
	for x := 0; x <= 0xffff; x++ {
		b[0], b[1] = byte(x), byte(x>>8)
		words := mnemonicode.EncodeWordList(nil, b[:])
		if len(words) == 2 {
			m[words[1]] = struct{}{}
		}
	}
	return m
})

func validLastWord(w string) bool {
	_, ok := validLastWords()[w]
	return ok
}
