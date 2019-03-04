package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"hash"
)

type CipherMode interface {
	Encrypt(plainText []byte, puk *rsa.PublicKey) ([]byte, error)
	Decrypt(cipherText []byte, prk *rsa.PrivateKey) ([]byte, error)
}

type cipherMode int64

type pkcs1v15Cipher cipherMode

func NewPKCS1v15Cipher() CipherMode {
	return new(pkcs1v15Cipher)
}

func (pkcs1v15 *pkcs1v15Cipher) Encrypt(plainText []byte, puk *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, puk, plainText)
}

func (pkcs1v15 *pkcs1v15Cipher) Decrypt(cipherText []byte, prk *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, prk, cipherText)
}

type oaepCipher struct {
	h hash.Hash
}

func NewOAEPCipher() CipherMode {
	oaep := new(oaepCipher)
	oaep.h = sha1.New()
	return oaep
}

func (oaep *oaepCipher) Encrypt(plainText []byte, puk *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(oaep.h, rand.Reader, puk, plainText, make([]byte, 0))
}

func (oaep *oaepCipher) Decrypt(cipherText []byte, prk *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(oaep.h, rand.Reader, prk, cipherText, make([]byte, 0))
}
