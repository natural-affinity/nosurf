package nosurf

import (
	"crypto/rand"
	"testing"
)

func TestChecksForPRNG(t *testing.T) {
	// Monkeypatch crypto/rand with an always-failing reader
	oldReader := rand.Reader
	rand.Reader = failReader{}
	// Restore it later for other tests
	defer func() {
		rand.Reader = oldReader
	}()

	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("Expected checkForPRNG() to panic")
		}
	}()

	generateToken(32)
}

func TestGeneratesAValidToken(t *testing.T) {
	// We can't test much with any certainity here,
	// since we generate tokens randomly
	// Basically we check that the length of the
	// token is what it should be
	tokenLength := 32
	token := generateToken(tokenLength)
	l := len(token)

	if l != tokenLength {
		t.Errorf("Bad decoded token length: expected %d, got %d", tokenLength, l)
	}
}

func TestVerifyTokenChecksLengthCorrectly(t *testing.T) {
	tokenLength := 32
	for i := 0; i < tokenLength*2; i++ {
		slice := make([]byte, i)
		result := verifyToken(slice, slice, tokenLength)
		if result != false {
			t.Errorf("VerifyToken should've returned false with slices of length %d", i)
		}
	}

	slice := make([]byte, 64)
	result := verifyToken(slice[:32], slice, tokenLength)
	if result != true {
		t.Errorf("VerifyToken should've returned true on a zeroed slice of length 64")
	}
}

func TestVerifiesMaskedTokenCorrectly(t *testing.T) {
	tokenLength := 32
	realToken := []byte("qwertyuiopasdfghjklzxcvbnm123456")
	sentToken := []byte("qwertyuiopasdfghjklzxcvbnm123456" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	if !verifyToken(realToken, sentToken, tokenLength) {
		t.Errorf("VerifyToken returned a false negative")
	}

	realToken[0] = 'x'

	if verifyToken(realToken, sentToken, tokenLength) {
		t.Errorf("VerifyToken returned a false positive")
	}
}
