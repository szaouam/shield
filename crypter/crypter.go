package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"
)

type Crypter struct {
	Key             []byte
	Encrypt         func(input io.Reader, output io.Writer) error
	Decrypt         func(input io.Reader, output io.Writer) error
	CipherBlock     cipher.Block
	CipherBlockSize int
}

func NewCrypter(enctype string, key string) (*Crypter, error) {
	crypter := Crypter{}
	crypter.Key = []byte(key)
	// cipher-mode combinations included so far are:
	// aes-cfb, blowfish-cfb, twofish-cfb
	cipherName := strings.Split(enctype, "-")[0]
	mode := strings.Split(enctype, "-")[1]

	switch cipherName {
	// Was originally going to specify aes128 or aes256, but the keysize determines
	// which is used.
	case "aes":
		block, err := aes.NewCipher(crypter.Key)
		if err != nil {
			return nil, err
		}
		crypter.CipherBlock = block
		crypter.CipherBlockSize = aes.BlockSize
	case "blowfish":
		block, err := blowfish.NewCipher(crypter.Key)
		if err != nil {
			return nil, err
		}
		crypter.CipherBlock = block
		crypter.CipherBlockSize = blowfish.BlockSize
	case "twofish":
		block, err := twofish.NewCipher(crypter.Key)
		if err != nil {
			return nil, err
		}
		crypter.CipherBlock = block
		crypter.CipherBlockSize = aes.BlockSize
	default:
		return nil, errors.New("Invalid cipher " + cipherName + " specified")
	}

	switch mode {
	case "cfb":
		crypter.Encrypt = func(input io.Reader, output io.Writer) error {
			return CFBEncrypt(input, output, &crypter)
		}
		crypter.Decrypt = func(input io.Reader, output io.Writer) error {
			return CFBDecrypt(input, output, &crypter)
		}
	default:
		return nil, errors.New("Invalid encryption mode " + cipherName + " specified")
	}
	return &crypter, nil
}
