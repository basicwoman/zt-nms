// Package crypto provides cryptographic primitives for ZT-NMS
package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/google/uuid"
)

// Constants
const (
	// Key sizes
	Ed25519PublicKeySize  = ed25519.PublicKeySize
	Ed25519PrivateKeySize = ed25519.PrivateKeySize
	Ed25519SignatureSize  = ed25519.SignatureSize
	X25519KeySize         = 32
	AES256KeySize         = 32
	NonceSize             = 12 // For AES-GCM
	SaltSize              = 32
)

// KeyPair represents an Ed25519 key pair
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair generates a new Ed25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// Sign signs a message with the private key
func (kp *KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, message)
}

// Verify verifies a signature with the public key
func (kp *KeyPair) Verify(message, signature []byte) bool {
	return ed25519.Verify(kp.PublicKey, message, signature)
}

// PublicKeyHash returns the SHA256 hash of the public key
func (kp *KeyPair) PublicKeyHash() []byte {
	hash := sha256.Sum256(kp.PublicKey)
	return hash[:]
}

// ExportPublicKeyPEM exports the public key in PEM format
func (kp *KeyPair) ExportPublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// ExportPrivateKeyPEM exports the private key in PEM format
func (kp *KeyPair) ExportPrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

// ImportPublicKeyPEM imports a public key from PEM format
func ImportPublicKeyPEM(pemData []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}
	return edPub, nil
}

// ImportPrivateKeyPEM imports a private key from PEM format
func ImportPrivateKeyPEM(pemData []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	edPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}
	return edPriv, nil
}

// Sign signs a message with an Ed25519 private key
func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// Verify verifies a signature with an Ed25519 public key
func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	if len(signature) != Ed25519SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// X25519KeyPair represents an X25519 key pair for key exchange
type X25519KeyPair struct {
	PublicKey  [X25519KeySize]byte
	PrivateKey [X25519KeySize]byte
}

// GenerateX25519KeyPair generates a new X25519 key pair
func GenerateX25519KeyPair() (*X25519KeyPair, error) {
	var privateKey [X25519KeySize]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	var publicKey [X25519KeySize]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &X25519KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// ComputeSharedSecret computes a shared secret using X25519
func (kp *X25519KeyPair) ComputeSharedSecret(peerPublicKey [X25519KeySize]byte) ([X25519KeySize]byte, error) {
	var sharedSecret [X25519KeySize]byte
	out, err := curve25519.X25519(kp.PrivateKey[:], peerPublicKey[:])
	if err != nil {
		return sharedSecret, fmt.Errorf("failed to compute shared secret: %w", err)
	}
	copy(sharedSecret[:], out)
	return sharedSecret, nil
}

// DeriveKey derives a key from a shared secret using HKDF
func DeriveKey(sharedSecret []byte, salt, info []byte, keyLen int) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	
	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	return key, nil
}

// EncryptedData represents encrypted data with all necessary components
type EncryptedData struct {
	Ciphertext   []byte `json:"ciphertext"`
	Nonce        []byte `json:"nonce"`
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"key_id,omitempty"`
}

// Encrypt encrypts data using AES-256-GCM
func Encrypt(key, plaintext, additionalData []byte) (*EncryptedData, error) {
	if len(key) != AES256KeySize {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)

	return &EncryptedData{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Algorithm:  "AES-256-GCM",
	}, nil
}

// Decrypt decrypts data using AES-256-GCM
func Decrypt(key []byte, data *EncryptedData, additionalData []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, data.Nonce, data.Ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Hash computes SHA-256 hash
func Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HashMultiple computes SHA-256 hash of multiple byte slices
func HashMultiple(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// GenerateNonce generates a random nonce
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// GenerateSalt generates a random salt
func GenerateSalt() ([]byte, error) {
	return GenerateNonce(SaltSize)
}

// SecureCompare performs constant-time comparison
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// NonceStore provides nonce tracking for replay protection
type NonceStore interface {
	// Add adds a nonce with timestamp
	Add(nonce []byte, timestamp int64) error
	// Exists checks if a nonce exists
	Exists(nonce []byte) bool
	// Cleanup removes expired nonces
	Cleanup(maxAge time.Duration) error
}

// InMemoryNonceStore implements NonceStore in memory
type InMemoryNonceStore struct {
	nonces map[string]int64
}

// NewInMemoryNonceStore creates a new in-memory nonce store
func NewInMemoryNonceStore() *InMemoryNonceStore {
	return &InMemoryNonceStore{
		nonces: make(map[string]int64),
	}
}

// Add adds a nonce
func (s *InMemoryNonceStore) Add(nonce []byte, timestamp int64) error {
	key := base64.StdEncoding.EncodeToString(nonce)
	s.nonces[key] = timestamp
	return nil
}

// Exists checks if a nonce exists
func (s *InMemoryNonceStore) Exists(nonce []byte) bool {
	key := base64.StdEncoding.EncodeToString(nonce)
	_, exists := s.nonces[key]
	return exists
}

// Cleanup removes expired nonces
func (s *InMemoryNonceStore) Cleanup(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge).UnixMilli()
	for key, timestamp := range s.nonces {
		if timestamp < cutoff {
			delete(s.nonces, key)
		}
	}
	return nil
}

// ThresholdKeyShare represents a share of a threshold key
type ThresholdKeyShare struct {
	Index      int       `json:"index"`
	ShareData  []byte    `json:"share_data"`
	PublicKey  []byte    `json:"public_key"`
	Threshold  int       `json:"threshold"`
	TotalShares int      `json:"total_shares"`
	KeyID      uuid.UUID `json:"key_id"`
}

// ThresholdSignature represents a partial signature from a share holder
type ThresholdSignature struct {
	Index     int    `json:"index"`
	Signature []byte `json:"signature"`
	KeyID     uuid.UUID `json:"key_id"`
}

// Note: Full threshold signature implementation would require a library
// like drand/kyber or a similar threshold cryptography library.
// This is a placeholder for the interface.

// KeyEncapsulation represents a key encapsulation for hybrid encryption
type KeyEncapsulation struct {
	EncapsulatedKey []byte `json:"encapsulated_key"`
	RecipientKeyID  string `json:"recipient_key_id"`
}

// HybridEncryptedData represents data encrypted with hybrid encryption
type HybridEncryptedData struct {
	Encapsulations []KeyEncapsulation `json:"encapsulations"`
	EncryptedData  *EncryptedData     `json:"encrypted_data"`
}

// HybridEncrypt encrypts data for multiple recipients using hybrid encryption
func HybridEncrypt(plaintext []byte, recipientKeys map[string]ed25519.PublicKey) (*HybridEncryptedData, error) {
	// Generate a random data encryption key
	dek := make([]byte, AES256KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt the data with DEK
	encryptedData, err := Encrypt(dek, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// For each recipient, encapsulate the DEK
	// Note: Ed25519 is not directly suitable for encryption
	// In production, use X25519 derived from Ed25519 or separate encryption keys
	// This is a simplified example
	encapsulations := make([]KeyEncapsulation, 0, len(recipientKeys))
	for keyID, pubKey := range recipientKeys {
		// Simple encapsulation using hash of pubkey + dek
		// In production, use proper KEM
		combined := HashMultiple(pubKey, dek)
		encapsulations = append(encapsulations, KeyEncapsulation{
			EncapsulatedKey: combined,
			RecipientKeyID:  keyID,
		})
	}

	return &HybridEncryptedData{
		Encapsulations: encapsulations,
		EncryptedData:  encryptedData,
	}, nil
}

// Signer interface for signing operations
type Signer interface {
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	Public() crypto.PublicKey
}

// Ed25519Signer wraps an Ed25519 private key to implement Signer
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
}

// NewEd25519Signer creates a new Ed25519 signer
func NewEd25519Signer(privateKey ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{privateKey: privateKey}
}

// Sign signs the digest
func (s *Ed25519Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ed25519.Sign(s.privateKey, digest), nil
}

// Public returns the public key
func (s *Ed25519Signer) Public() crypto.PublicKey {
	return s.privateKey.Public()
}

// MerkleTree represents a Merkle tree
type MerkleTree struct {
	Root   []byte
	Leaves [][]byte
	Nodes  [][]byte
}

// NewMerkleTree creates a new Merkle tree from leaves
func NewMerkleTree(leaves [][]byte) *MerkleTree {
	if len(leaves) == 0 {
		return &MerkleTree{}
	}

	// Hash all leaves
	hashedLeaves := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		hash := sha256.Sum256(leaf)
		hashedLeaves[i] = hash[:]
	}

	tree := &MerkleTree{
		Leaves: hashedLeaves,
	}
	tree.Nodes = buildMerkleTree(hashedLeaves)
	if len(tree.Nodes) > 0 {
		tree.Root = tree.Nodes[len(tree.Nodes)-1]
	}

	return tree
}

func buildMerkleTree(leaves [][]byte) [][]byte {
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return leaves
	}

	var nodes [][]byte
	nodes = append(nodes, leaves...)

	currentLevel := leaves
	for len(currentLevel) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			var combined []byte
			if i+1 < len(currentLevel) {
				combined = HashMultiple(currentLevel[i], currentLevel[i+1])
			} else {
				combined = currentLevel[i]
			}
			nextLevel = append(nextLevel, combined)
			nodes = append(nodes, combined)
		}
		currentLevel = nextLevel
	}

	return nodes
}

// MerkleProof represents a proof of inclusion in a Merkle tree
type MerkleProof struct {
	LeafIndex int      `json:"leaf_index"`
	LeafHash  []byte   `json:"leaf_hash"`
	Siblings  [][]byte `json:"siblings"`
	Root      []byte   `json:"root"`
}

// GetProof generates a proof for a leaf at the given index
func (mt *MerkleTree) GetProof(index int) (*MerkleProof, error) {
	if index < 0 || index >= len(mt.Leaves) {
		return nil, errors.New("index out of range")
	}

	proof := &MerkleProof{
		LeafIndex: index,
		LeafHash:  mt.Leaves[index],
		Root:      mt.Root,
	}

	currentIndex := index
	currentLevel := mt.Leaves

	for len(currentLevel) > 1 {
		siblingIndex := currentIndex ^ 1 // Toggle last bit
		if siblingIndex < len(currentLevel) {
			proof.Siblings = append(proof.Siblings, currentLevel[siblingIndex])
		}

		// Move to next level
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := HashMultiple(currentLevel[i], currentLevel[i+1])
				nextLevel = append(nextLevel, combined)
			} else {
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}
		currentLevel = nextLevel
		currentIndex = currentIndex / 2
	}

	return proof, nil
}

// VerifyProof verifies a Merkle proof
func VerifyMerkleProof(proof *MerkleProof) bool {
	currentHash := proof.LeafHash
	currentIndex := proof.LeafIndex

	for _, sibling := range proof.Siblings {
		if currentIndex%2 == 0 {
			currentHash = HashMultiple(currentHash, sibling)
		} else {
			currentHash = HashMultiple(sibling, currentHash)
		}
		currentIndex = currentIndex / 2
	}

	return SecureCompare(currentHash, proof.Root)
}
