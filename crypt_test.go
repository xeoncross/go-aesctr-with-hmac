package aesctr

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

// Fixed synthetic vectors so every run compares the same bytes.
var (
	fixedIV       = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff}
	fixedHmacKey  = bytes.Repeat([]byte{0x5a}, 32)
	testBufSizes  = []int{MinBufferSize, 4 * 1024, BUFFER_SIZE, 1024 * 1024}
	testDataSizes = []int{0, 1, 63, 64, 65, BUFFER_SIZE - 1, BUFFER_SIZE, BUFFER_SIZE + 1, 1024*1024 + 5}
)

// syntheticData returns n deterministic, non-repeating-looking bytes.
func syntheticData(n int) []byte {
	data := make([]byte, n)

	for i := range data {
		data[i] = byte(i*31 + i/251)
	}

	return data
}

// referenceEncrypt builds the expected wire format independently of crypt.go:
// one CTR pass over the whole input and an HMAC over IV || ciphertext.
func referenceEncrypt(t *testing.T, plain, keyAes, keyHmac, iv []byte) []byte {
	block, err := aes.NewCipher(keyAes)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := make([]byte, len(plain))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plain)

	mac := hmac.New(sha512.New, keyHmac)
	mac.Write(iv)
	mac.Write(ciphertext)

	out := append([]byte{V1}, iv...)
	out = append(out, ciphertext...)

	return append(out, mac.Sum(nil)...)
}

// The buffer size must never change the encrypted bytes (AES behavior freeze).
func TestEncryptBufferSizeByteEquality(t *testing.T) {
	for _, dataSize := range testDataSizes {
		plain := syntheticData(dataSize)
		want := referenceEncrypt(t, plain, aesKey, fixedHmacKey, fixedIV)

		for _, bufSize := range testBufSizes {
			out := &bytes.Buffer{}

			err := encrypt(bytes.NewReader(plain), out, aesKey, fixedHmacKey, fixedIV, bufSize)
			if err != nil {
				t.Fatalf("data %d buf %d: %v", dataSize, bufSize, err)
			}

			if !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("data %d buf %d: output differs from reference", dataSize, bufSize)
			}
		}
	}
}

// Data written by the default Encrypt must decrypt with every buffer size,
// and data written with any buffer size must decrypt with the default Decrypt.
func TestDecryptBufferSizeCompatibility(t *testing.T) {
	for _, dataSize := range testDataSizes {
		plain := syntheticData(dataSize)
		legacy := &bytes.Buffer{}

		err := Encrypt(bytes.NewReader(plain), legacy, aesKey, fixedHmacKey)
		if err != nil {
			t.Fatal(err)
		}

		for _, bufSize := range testBufSizes {
			out := &bytes.Buffer{}

			err = DecryptWithBufferSize(bytes.NewReader(legacy.Bytes()), out, aesKey, fixedHmacKey, bufSize)
			if err != nil {
				t.Fatalf("data %d buf %d: %v", dataSize, bufSize, err)
			}

			if !bytes.Equal(out.Bytes(), plain) {
				t.Fatalf("data %d buf %d: plaintext differs", dataSize, bufSize)
			}

			custom, back := &bytes.Buffer{}, &bytes.Buffer{}

			err = EncryptWithBufferSize(bytes.NewReader(plain), custom, aesKey, fixedHmacKey, bufSize)
			if err != nil {
				t.Fatal(err)
			}

			err = Decrypt(bytes.NewReader(custom.Bytes()), back, aesKey, fixedHmacKey)
			if err != nil || !bytes.Equal(back.Bytes(), plain) {
				t.Fatalf("data %d buf %d: default Decrypt failed: %v", dataSize, bufSize, err)
			}
		}
	}
}

// A modified ciphertext or tag must fail authentication for every buffer size.
func TestDecryptBufferSizeRejectsTampering(t *testing.T) {
	sealed := referenceEncrypt(t, syntheticData(BUFFER_SIZE+1), aesKey, fixedHmacKey, fixedIV)

	for _, index := range []int{1, 1 + IV_SIZE, len(sealed) - 1} {
		tampered := append([]byte(nil), sealed...)
		tampered[index] ^= 0x01

		for _, bufSize := range testBufSizes {
			err := DecryptWithBufferSize(bytes.NewReader(tampered), &bytes.Buffer{}, aesKey, fixedHmacKey, bufSize)
			if !errors.Is(err, ErrInvalidHMAC) {
				t.Fatalf("byte %d buf %d: want ErrInvalidHMAC, got %v", index, bufSize, err)
			}
		}
	}
}

// Out-of-range sizes are rejected before any input is read or output written.
func TestBufferSizeValidation(t *testing.T) {
	sealed := referenceEncrypt(t, syntheticData(10), aesKey, fixedHmacKey, fixedIV)

	for _, bufSize := range []int{-1, 0, hmacSize, MaxBufferSize + 1} {
		in, out := bytes.NewReader(sealed), &bytes.Buffer{}

		err := DecryptWithBufferSize(in, out, aesKey, fixedHmacKey, bufSize)
		if !errors.Is(err, ErrInvalidBufferSize) || in.Len() != len(sealed) || out.Len() != 0 {
			t.Fatalf("decrypt buf %d: err %v, consumed or wrote data", bufSize, err)
		}

		in, out = bytes.NewReader(sealed), &bytes.Buffer{}

		err = EncryptWithBufferSize(in, out, aesKey, fixedHmacKey, bufSize)
		if !errors.Is(err, ErrInvalidBufferSize) || in.Len() != len(sealed) || out.Len() != 0 {
			t.Fatalf("encrypt buf %d: err %v, consumed or wrote data", bufSize, err)
		}
	}
}

// Short reads, a caller-owned *bufio.Reader and truncated input must not change
// the result or skip authentication.
func TestDecryptBufferSizeReaders(t *testing.T) {
	plain := syntheticData(300)
	sealed := referenceEncrypt(t, plain, aesKey, fixedHmacKey, fixedIV)

	for _, bufSize := range []int{MinBufferSize, MinBufferSize + 1, 100, 4096, MaxBufferSize} {
		readers := []io.Reader{
			iotest.OneByteReader(bytes.NewReader(sealed)),
			iotest.HalfReader(bytes.NewReader(sealed)),
			iotest.DataErrReader(bytes.NewReader(sealed)),
			bufio.NewReaderSize(bytes.NewReader(sealed), bufSize),
		}

		for i, in := range readers {
			out := &bytes.Buffer{}

			err := DecryptWithBufferSize(in, out, aesKey, fixedHmacKey, bufSize)
			if err != nil || !bytes.Equal(out.Bytes(), plain) {
				t.Fatalf("reader %d buf %d: %v", i, bufSize, err)
			}
		}

		// Every truncation point must end in an error, never in nil.
		for cut := 0; cut < len(sealed); cut += 7 {
			err := DecryptWithBufferSize(bytes.NewReader(sealed[:cut]), &bytes.Buffer{}, aesKey, fixedHmacKey, bufSize)
			if err == nil {
				t.Fatalf("buf %d: truncated input at %d accepted", bufSize, cut)
			}
		}
	}
}
