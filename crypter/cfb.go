package crypter

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

func CFBEncrypt(input io.Reader, output io.Writer, crypter *Crypter) error {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	iv := make([]byte, crypter.CipherBlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	io.WriteString(output, hex.EncodeToString(iv))
	// Initiate the stream here, then encrypt the file in crypter.CipherBlockSize increments
	stream := cipher.NewCFBEncrypter(crypter.CipherBlock, iv)
	for {
		buffer := make([]byte, crypter.CipherBlockSize)
		bytesRead, err := input.Read(buffer)
		if err != nil {
			// If we hit the EOF error, we've read the whole file and it happens to
			// have a length that is a multiple of crypter.CipherBlockSize
			if err.Error() == "EOF" {
				break
			}
			return err
		}
		ciphertext := make([]byte, crypter.CipherBlockSize)
		stream.XORKeyStream(ciphertext, buffer)
		// Stream encryption doesn't require padding, so if the last block is
		// smaller than crypter.CipherBlockSize, just encrypt what's there
		output.Write(ciphertext[:bytesRead])
		// Here we hit EOF if we happen to read less than the block size
		if bytesRead < crypter.CipherBlockSize {
			break
		}
	}
	return nil
}

func CFBDecrypt(input io.Reader, output io.Writer, crypter *Crypter) error {
	// Extract the IV from the beginning of the file stream
	encodedIV := make([]byte, hex.EncodedLen(crypter.CipherBlockSize))
	bytesRead, err := input.Read(encodedIV)
	if err != nil {
		return err
	}
	if bytesRead < hex.EncodedLen(crypter.CipherBlockSize) {
		return errors.New("Ciphertext too short")
	}

	iv := make([]byte, crypter.CipherBlockSize)
	hex.Decode(iv, encodedIV)
	// Initiate the stream here, then decrypt the file in crypter.CipherBlockSize increments
	stream := cipher.NewCFBDecrypter(crypter.CipherBlock, iv)
	for {
		buffer := make([]byte, crypter.CipherBlockSize)
		bytesRead, err := input.Read(buffer)
		if err != nil {
			// If we hit the EOF error, we've read the whole file and it happens to
			// have a length that is a multiple of crypter.CipherBlockSize
			if err.Error() == "EOF" {
				break
			}
			return err
		}
		decodedtext := make([]byte, crypter.CipherBlockSize)
		stream.XORKeyStream(decodedtext, buffer)
		output.Write(decodedtext[:bytesRead])
		// Here we hit EOF if we happen to read less than the block size
		if bytesRead < crypter.CipherBlockSize {
			break
		}
	}
	return nil
}
