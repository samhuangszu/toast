package rsa

import (
	"bytes"

	"github.com/sirupsen/logrus"
)

type Cipher interface {
	Encrypt(plainText []byte) ([]byte, error)
}

func NewCipher(key Key, padding Padding, cipherMode CipherMode) Cipher {
	return &cipher{key: key, padding: padding, cipherMode: cipherMode}
}

type cipher struct {
	key        Key
	cipherMode CipherMode
	padding    Padding
}

func (cipher *cipher) Encrypt(plainText []byte) ([]byte, error) {
	groups := cipher.padding.Padding(plainText)
	buffer := bytes.Buffer{}
	for _, plainTextBlock := range groups {
		cipherText, err := cipher.cipherMode.Encrypt(plainTextBlock, cipher.key.PublicKey())
		if err != nil {
			logrus.Error(err)
			return nil, err
		}
		buffer.Write(cipherText)
	}
	return buffer.Bytes(), nil
}
