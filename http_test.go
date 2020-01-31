package aesctr

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// var aesKey = make([]byte, 32)
var aesKey = []byte{139, 46, 150, 181, 48, 123, 170, 178, 55, 133, 209, 214, 35, 46, 101,
	32, 231, 24, 92, 86, 3, 41, 59, 198, 221, 2, 193, 66, 26, 100, 154, 147}
var hmacKey = aesKey

var encryptHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	// r.Body -> pipeWriter -> {Encrypt} -> pipeReader -> ResponseWriter
	pipeReader, pipeWriter := io.Pipe()

	go func() {
		// Write to stdout so we can see what is being read
		tee := io.TeeReader(r.Body, os.Stdout)

		err := Encrypt(tee, pipeWriter, aesKey, hmacKey)
		if err != nil {
			log.Fatal(err)
		}
		pipeWriter.Close() // Nothing else to write
	}()

	// Let the client know what we encrypted by sending it back
	_, err := io.Copy(w, pipeReader)
	if err != nil {
		log.Fatal(err)
	}
})

func TestHTTPClient(t *testing.T) {

	secretMessage := "My Secret Message"

	// Expected output
	in := strings.NewReader(secretMessage)
	out := &bytes.Buffer{}

	err := Encrypt(in, out, aesKey, hmacKey)
	if err != nil {
		t.Fatal(err)
	}

	// Create the request and call the HTTP handler
	req, err := http.NewRequest("POST", "ABC", strings.NewReader(secretMessage))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	resp := httptest.NewRecorder()
	encryptHandler(resp, req)

	result := resp.Body.String()

	if result != out.String() {
		t.Logf("\nWant: %v\nGot: %v", out.Bytes(), resp.Body.Bytes())
		t.Fail()
	}

}
