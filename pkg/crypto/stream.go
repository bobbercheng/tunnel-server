package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// NonceSize is the size of the nonce for ChaCha20-Poly1305
	NonceSize = 12
	// KeySize is the size of the key for ChaCha20-Poly1305
	KeySize = 32
	// SaltSize is the size of the salt for key derivation
	SaltSize = 32
	// OverheadSize is the overhead of the AEAD cipher (tag size)
	OverheadSize = 16
	// MaxPlaintextSize is the maximum size of plaintext that can be encrypted in one message
	MaxPlaintextSize = 16 * 1024 * 1024 // 16MB - increased to handle large assets
)

var (
	ErrInvalidKeySize    = errors.New("invalid key size")
	ErrInvalidNonceSize  = errors.New("invalid nonce size")
	ErrMessageTooLarge   = errors.New("message too large")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// StreamCipher provides fast stream encryption using ChaCha20-Poly1305
type StreamCipher struct {
	aead    cipher.AEAD
	sendKey [KeySize]byte
	recvKey [KeySize]byte
	counter uint64
}

// NewStreamCipher creates a new stream cipher with derived keys
func NewStreamCipher(masterSecret []byte, salt []byte, isServer bool) (*StreamCipher, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be %d bytes", SaltSize)
	}

	// Derive send and receive keys using HKDF
	hkdf := hkdf.New(sha256.New, masterSecret, salt, []byte("gcp-proxy-v1"))

	var sendKey, recvKey [KeySize]byte

	if isServer {
		// Server: send with key1, receive with key2
		if _, err := io.ReadFull(hkdf, sendKey[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(hkdf, recvKey[:]); err != nil {
			return nil, err
		}
	} else {
		// Client: send with key2, receive with key1
		var key1, key2 [KeySize]byte
		if _, err := io.ReadFull(hkdf, key1[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(hkdf, key2[:]); err != nil {
			return nil, err
		}
		sendKey = key2
		recvKey = key1
	}

	aead, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		return nil, err
	}

	return &StreamCipher{
		aead:    aead,
		sendKey: sendKey,
		recvKey: recvKey,
		counter: 0,
	}, nil
}

// Encrypt encrypts the plaintext and returns the ciphertext with nonce prepended
func (sc *StreamCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintextSize {
		return nil, ErrMessageTooLarge
	}

	// Generate nonce from counter (little-endian)
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[:8], sc.counter)
	sc.counter++

	// Encrypt: [nonce][ciphertext+tag]
	ciphertext := make([]byte, NonceSize+len(plaintext)+OverheadSize)
	copy(ciphertext[:NonceSize], nonce[:])

	encrypted := sc.aead.Seal(ciphertext[NonceSize:NonceSize], nonce[:], plaintext, nil)
	return ciphertext[:NonceSize+len(encrypted)], nil
}

// Decrypt decrypts the ciphertext (with nonce prepended) and returns the plaintext
func (sc *StreamCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+OverheadSize {
		return nil, ErrInvalidCiphertext
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]

	// Create AEAD with receive key for decryption
	recvAEAD, err := chacha20poly1305.New(sc.recvKey[:])
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := recvAEAD.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// KeyExchange performs a simple key exchange using the shared secret
type KeyExchange struct {
	masterSecret []byte
	salt         []byte
}

// NewKeyExchange creates a new key exchange with a random master secret
func NewKeyExchange(secret string) *KeyExchange {
	// Use the tunnel secret as master key material
	masterSecret := sha256.Sum256([]byte(secret))

	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		panic(err) // Should never happen with crypto/rand
	}

	return &KeyExchange{
		masterSecret: masterSecret[:],
		salt:         salt,
	}
}

// GetSalt returns the salt for key derivation
func (kx *KeyExchange) GetSalt() []byte {
	return kx.salt
}

// DeriveStreamCipher creates a stream cipher from the key exchange
func (kx *KeyExchange) DeriveStreamCipher(isServer bool) (*StreamCipher, error) {
	return NewStreamCipher(kx.masterSecret, kx.salt, isServer)
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}
