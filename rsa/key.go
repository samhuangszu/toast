package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"
)

type Key interface {
	PublicKey() *rsa.PublicKey
	Modulus() int
}

func ParsePKCS8Key(publicKey []byte) (Key, error) {
	puk, _ := pem.Decode(publicKey)
	if puk == nil {
		return nil, errors.New("publicKey is not pem formate")
	}
	pub, err := x509.ParsePKIXPublicKey(puk.Bytes)
	if err != nil {
		return nil, err
	}
	return &key{publicKey: pub.(*rsa.PublicKey)}, nil
}

func ParsePKCS1Key(publicKey []byte) (Key, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("publicKey is not pem formate")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &key{publicKey: pub}, nil
}

func LoadKeyFromPEMFile(publicKeyFilePath string, ParseKey func([]byte) (Key, error)) (Key, error) {
	//TODO 断言如果入参为"" ，则直接报错
	publicKeyFilePath = strings.TrimSpace(publicKeyFilePath)
	pukBytes, err := ioutil.ReadFile(publicKeyFilePath)
	if err != nil {
		return nil, err
	}
	puk, _ := pem.Decode(pukBytes)
	if puk == nil {
		return nil, errors.New("publicKey is not pem formate")
	}
	return ParseKey(puk.Bytes)
}

type key struct {
	publicKey *rsa.PublicKey
}

func (key *key) Modulus() int {
	return len(key.publicKey.N.Bytes())
}

func (key *key) PublicKey() *rsa.PublicKey {
	return key.publicKey
}
