package aesctr

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
)

// BUFFER_SIZE is the default read buffer size used by Encrypt and Decrypt.
// It only controls how much input is processed per step; the encrypted
// output is the same for every buffer size because AES-CTR is a stream mode.
const BUFFER_SIZE int = 16 * 1024
const IV_SIZE int = 16
const V1 byte = 0x1
const hmacSize = sha512.Size

// MinBufferSize is the smallest buffer size accepted by the WithBufferSize
// functions. Decrypt always keeps hmacSize bytes in the buffer to find the
// trailing HMAC, so the buffer must hold at least one more byte than that.
const MinBufferSize int = hmacSize + 1

// MaxBufferSize is the largest accepted buffer size. It keeps the per-call
// memory use finite when the size comes from configuration or user input.
const MaxBufferSize int = 64 * 1024 * 1024

// ErrInvalidHMAC for authentication failure
var ErrInvalidHMAC = errors.New("Invalid HMAC")

// ErrInvalidBufferSize is returned when a buffer size is outside
// [MinBufferSize, MaxBufferSize].
var ErrInvalidBufferSize = errors.New("Invalid buffer size")

// validateBufferSize returns ErrInvalidBufferSize when bufferSize is outside
// [MinBufferSize, MaxBufferSize].
func validateBufferSize(bufferSize int) error {
	if bufferSize < MinBufferSize || bufferSize > MaxBufferSize {
		return ErrInvalidBufferSize
	}

	return nil
}

// Encrypt the stream using the given AES-CTR and SHA512-HMAC key
// with the default BUFFER_SIZE.
func Encrypt(in io.Reader, out io.Writer, keyAes, keyHmac []byte) (err error) {
	return EncryptWithBufferSize(in, out, keyAes, keyHmac, BUFFER_SIZE)
}

// EncryptWithBufferSize encrypts the stream like Encrypt, reading the input
// bufferSize bytes at a time. The output is byte-for-byte the same as Encrypt
// for the same key and IV; only memory use and call count per step change.
// It returns ErrInvalidBufferSize before writing anything when bufferSize is
// outside [MinBufferSize, MaxBufferSize], and any read, write or key error.
func EncryptWithBufferSize(in io.Reader, out io.Writer, keyAes, keyHmac []byte, bufferSize int) (err error) {
	err = validateBufferSize(bufferSize)
	if err != nil {
		return err
	}

	iv := make([]byte, IV_SIZE)
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	return encrypt(in, out, keyAes, keyHmac, iv, bufferSize)
}

// encrypt writes [V1][iv][AES-CTR(in)][HMAC-SHA512(iv || ciphertext)] to out.
// It is separate from EncryptWithBufferSize so tests can pin the IV and
// compare outputs byte-for-byte; bufferSize must already be validated.
func encrypt(in io.Reader, out io.Writer, keyAes, keyHmac, iv []byte, bufferSize int) (err error) {
	AES, err := aes.NewCipher(keyAes)
	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(AES, iv)
	HMAC := hmac.New(sha512.New, keyHmac) // https://golang.org/pkg/crypto/hmac/#New

	// Version
	_, err = out.Write([]byte{V1})
	if err != nil {
		return
	}

	w := io.MultiWriter(out, HMAC)

	_, err = w.Write(iv)
	if err != nil {
		return
	}

	buf := make([]byte, bufferSize)
	for {
		n, err := in.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		if n != 0 {
			outBuf := make([]byte, n)
			ctr.XORKeyStream(outBuf, buf[:n])
			_, err = w.Write(outBuf)
			if err != nil {
				return err
			}
		}

		if err == io.EOF {
			break
		}
	}

	_, err = out.Write(HMAC.Sum(nil))

	return err
}

// Decrypt the stream and verify HMAC using the given AES-CTR and SHA512-HMAC key
// with the default BUFFER_SIZE.
// Do not trust the out io.Writer contents until the function returns the result
// of validating the ending HMAC hash.
func Decrypt(in io.Reader, out io.Writer, keyAes, keyHmac []byte) (err error) {
	return DecryptWithBufferSize(in, out, keyAes, keyHmac, BUFFER_SIZE)
}

// DecryptWithBufferSize decrypts and verifies the stream like Decrypt,
// buffering bufferSize bytes of input at a time. Data encrypted with any
// buffer size (including the default) decrypts with any valid buffer size.
// It returns ErrInvalidBufferSize before reading anything when bufferSize is
// outside [MinBufferSize, MaxBufferSize], ErrInvalidHMAC when authentication
// fails, and any read, write or key error.
// Do not trust the out io.Writer contents until the function returns the result
// of validating the ending HMAC hash.
func DecryptWithBufferSize(in io.Reader, out io.Writer, keyAes, keyHmac []byte, bufferSize int) (err error) {
	// Validate first so an invalid size never consumes input; a size of
	// hmacSize or less would make the limit below zero or negative.
	err = validateBufferSize(bufferSize)
	if err != nil {
		return err
	}

	// Read version (up to 0-255)
	var version int8
	err = binary.Read(in, binary.LittleEndian, &version)
	if err != nil {
		return
	}

	iv := make([]byte, IV_SIZE)
	_, err = io.ReadFull(in, iv)
	if err != nil {
		return
	}

	AES, err := aes.NewCipher(keyAes)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(AES, iv)
	h := hmac.New(sha512.New, keyHmac)
	h.Write(iv)
	mac := make([]byte, hmacSize)

	w := out

	buf := bufio.NewReaderSize(in, bufferSize)
	var limit int
	var b []byte
	for {
		b, err = buf.Peek(bufferSize)
		if err != nil && err != io.EOF {
			return
		}

		limit = len(b) - hmacSize

		// We reached the end
		if err == io.EOF {

			left := buf.Buffered()
			if left < hmacSize {
				return errors.New("not enough left")
			}

			copy(mac, b[left-hmacSize:left])

			if left == hmacSize {
				break
			}
		}

		h.Write(b[:limit])

		// We always leave at least hmacSize bytes left in the buffer
		// That way, our next Peek() might be EOF, but we will still have enough
		outBuf := make([]byte, int64(limit))
		_, err = buf.Read(b[:limit])
		if err != nil {
			return
		}
		ctr.XORKeyStream(outBuf, b[:limit])
		_, err = w.Write(outBuf)
		if err != nil {
			return
		}

		if err == io.EOF {
			break
		}
	}

	if !hmac.Equal(mac, h.Sum(nil)) {
		return ErrInvalidHMAC
	}

	return nil
}
