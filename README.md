# Encryption and Decryption

This package is a simple AES-CTR encryption wrapper with SHA512 HMAC authentication. I wrote it to handle large blobs of data that would not fit into memory (or would take to much memory). Examples include files and client-to-client uploads. The assumption is that this will be used with public/private key cryptography where the AES password (and HMAC password) will be strong and random providing a strong security guarantee.

I also wanted this to be [easy to](https://gist.github.com/AndiDittrich/4629e7db04819244e843) implement [in Javascript](https://stackoverflow.com/questions/36909746/aes-ctr-encrypt-in-cryptojs-and-decrypt-in-go-lang) for client-to-client communication via electron or react-native.

## Benchmarks

Included the example folder is a benchmark of encrypting an decrypting a 500MB stream of data. I get over 100MB/sec on my local computer using two cores.

    go get github.com/Xeoncross/go-aesctr-with-hmac
    cd $GOPATH/src/github.com/Xeoncross/go-aesctr-with-hmac/example
    go run main.go

## Using passwords

If using passwords to encrypt things I recommend you use this the "decrypto" AES-CTR + HMAC + scrypt password strengthening implementation found in [odeke-em/drive](https://github.com/sselph/drive/tree/master/src/dcrypto). It might be slower (and uses a temp file) but is worth it for the security gains. Human-passwords aren't safe to use alone.

## Encrypting small blobs

If the data you are encrypting is small and easily fits into memory then you should use GCM. GCM is [nice and simple to use](https://github.com/gtank/cryptopasta/blob/master/encrypt.go) if your data is small.

## Encrypting a Media stream

If you need to encrypt video/audio stream, then a more complex chunked version of GCM is for you. https://github.com/minio/sio (D.A.R.E. v2) provides a way to break data up into chunks that can be decrypted as they arrive and used without waiting for the rest of the stream to finish arriving.

# Warning

I am not a cryptographer. However, this implementation has very few moving parts all of which are written by real cryptographers and used as described.


## Reference

- [Cryptography lessons-learned](https://security.stackexchange.com/questions/2202/lessons-learned-and-misconceptions-regarding-encryption-and-cryptology)
- [Symmetric Security (NaCI, GCM, CTR)](https://leanpub.com/gocrypto/read#leanpub-auto-chapter-3-symmetric-security)
- https://www.imperialviolet.org/2014/06/27/streamingencryption.html
- [streaming encryption with AES-OFB](https://golang.org/src/crypto/cipher/example_test.go#L335)
- [Encrypt then MAC](http://www.daemonology.net/blog/2009-06-24-encrypt-then-mac.html)
- [AES OFB vs CRT](https://security.stackexchange.com/questions/27776/block-chaining-modes-to-avoid/27780#27780)
- [How do you encrypt large streams?](https://stackoverflow.com/questions/49546567/how-do-you-encrypt-large-files-byte-streams-in-go/49546791?noredirect=1#comment86134522_49546791)
- [Authenticated Encryption "AHEAD"](https://en.wikipedia.org/wiki/Authenticated_encryption)
- [PBKDF2 is redundant for bits from a CSPRNG (for use in AES)](https://crypto.stackexchange.com/questions/14842/is-it-overkill-to-run-a-key-generated-by-openssl-through-pbkdf2)
- [AES-256-GCM basic implementation](https://gist.github.com/cannium/c167a19030f2a3c6adbb5a5174bea3ff)
- [Golang AES-CFB encrypted TCP stream ](https://gist.github.com/raincious/96bb69414859e7ea0abfdb177ee97a1f)
- https://github.com/SermoDigital/boxer/blob/master/boxer.go
- [AES-256-GCM in C using OpenSSL for iPhone](https://gist.github.com/eliburke/24f06a1590d572e86a01504e1b38b27f)
- [AES-CTR + HMAC + RFC2898 key derivation (Go)](https://github.com/xeodou/aesf)
