package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"sync/atomic"
	"time"

	aesctr "github.com/Xeoncross/go-aesctr-with-hmac"
)

//
// For the demo
//

type devZero byte

func (z devZero) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(z)
	}
	return len(b), nil
}

func mockDataSrc(size int64) io.Reader {
	fmt.Printf("dev/zero of size %d (%d MB)\n", size, size/1024/1024)
	var z devZero
	return io.LimitReader(z, size)
}

// WriteCounter counts the number of bytes written to it.
type WriteCounter struct {
	total  int64 // Total # of bytes transferred
	recent int64 // Used for per-second/minute/etc.. reports
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	atomic.AddInt64(&wc.total, int64(n))
	atomic.AddInt64(&wc.recent, int64(n))
	return n, nil
}

func (wc *WriteCounter) Total() int64 {
	return atomic.LoadInt64(&wc.total)
}

func (wc *WriteCounter) Recent() (n int64) {
	n = atomic.LoadInt64(&wc.recent)
	atomic.StoreInt64(&wc.recent, int64(0))
	return n
}

func main() {

	var err error

	// Could be a file, TCP connection, etc...
	in := mockDataSrc(2 << 28) // ~536MB
	// in := strings.NewReader(strings.Repeat("Hello World! 012345\n", 4))

	out := ioutil.Discard // throw it away
	// out := os.Stdout // dump it to the console
	// out := new(bytes.Buffer)

	// Process flow
	// in -> encrypt -> (pw -> pr) -> (decrypt) -> out

	// To pipe encryption to decryption
	pr, pw := io.Pipe()

	// This is our logger innstance to see the whole byte stream (demo below)
	// var b bytes.Buffer
	// writer := bufio.NewWriter(&b)
	// r := io.TeeReader(pr, writer)

	// In real life we would generate a random key
	// aesKey := make([]byte, 32)
	// _, err = rand.Read(aesKey)
	// if err != nil {
	// 	return err
	// }

	// But this isn't real life now is it?
	keyAes, _ := hex.DecodeString(strings.Repeat("6368616e676520746869732070617373", 2))
	keyHmac := keyAes // don't do this either, use a different key or kids may die

	// writing without a reader will deadlock so write in a goroutine
	go func() {
		err = aesctr.Encrypt(in, pw, keyAes, keyHmac)
		if err != nil {
			log.Fatal(err)
		}

		pw.Close()
	}()

	// Log how much data passed through
	wc := &WriteCounter{}
	finalwriter := io.MultiWriter(wc, out)

	go func() {
		for {
			select {
			case <-time.After(time.Second):
				fmt.Printf("Encrypted and Decrypted %10d MB/s of %10d MB\n", wc.Recent()/1024/1024, wc.Total()/1024/1024)
			}
		}
	}()

	err = aesctr.Decrypt(pr, finalwriter, keyAes, keyHmac)

	// writer.Flush()
	// x := b.Bytes()
	// fmt.Println("Version", x[:1])
	// fmt.Println("IV ", x[1:IV_SIZE+1])
	// fmt.Println("B  ", x[IV_SIZE+1:len(x)-hmacSize])
	// fmt.Println("MAC", x[len(x)-hmacSize:])
	// // fmt.Println("MAC", hex.EncodeToString(x[len(x)-hmacSize:]))

	if err != nil {
		log.Fatal(err)
	}

}
