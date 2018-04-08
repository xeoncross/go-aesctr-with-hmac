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

const BUFFER_SIZE int = 16 * 1024
const IV_SIZE int = 16
const V1 byte = 0x1

const (
	// The size of the HMAC sum.
	hmacSize = sha512.Size
)

// Encrypt the stream using the given AES-CTR and SHA512-HMAC key
func Encrypt(in io.Reader, out io.Writer, keyAes, keyHmac []byte) (err error) {

	iv := make([]byte, IV_SIZE)
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	aes, err := aes.NewCipher(keyAes)
	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(aes, iv)
	hmac := hmac.New(sha512.New, keyHmac) // https://golang.org/pkg/crypto/hmac/#New

	// Version
	out.Write([]byte{V1})

	w := io.MultiWriter(out, hmac)

	w.Write(iv)

	buf := make([]byte, BUFFER_SIZE)
	for {
		n, err := in.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		if n != 0 {
			outBuf := make([]byte, n)
			ctr.XORKeyStream(outBuf, buf[:n])
			w.Write(outBuf)
		}

		if err == io.EOF {
			break
		}
	}

	out.Write(hmac.Sum(nil))

	return nil
}

// Decrypt the stream and verify HMAC using the given AES-CTR and SHA512-HMAC key
// Do not trust the out io.Writer contents until the funtion returns the result
// of validating the ending HMAC hash.
func Decrypt(in io.Reader, out io.Writer, keyAes, keyHmac []byte) (err error) {

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

	aes, err := aes.NewCipher(keyAes)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(aes, iv)
	h := hmac.New(sha512.New, keyHmac)
	h.Write(iv)
	mac := make([]byte, hmacSize)

	w := out

	buf := bufio.NewReaderSize(in, BUFFER_SIZE)
	var limit int
	var b []byte
	for {
		b, err = buf.Peek(BUFFER_SIZE)
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
		buf.Read(b[:limit])
		ctr.XORKeyStream(outBuf, b[:limit])
		w.Write(outBuf)

		if err == io.EOF {
			break
		}

		if err != nil {
			return
		}
	}

	if !hmac.Equal(mac, h.Sum(nil)) {
		return errors.New("Invalid HMAC")
	}

	return nil
}
