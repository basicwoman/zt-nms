package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)
	assert.NotNil(t, kp)
	assert.Len(t, kp.PublicKey, Ed25519PublicKeySize)
	assert.Len(t, kp.PrivateKey, Ed25519PrivateKeySize)
}

func TestKeyPair_SignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("test message to sign")
	signature := kp.Sign(message)

	assert.Len(t, signature, Ed25519SignatureSize)
	assert.True(t, kp.Verify(message, signature))

	// Wrong message
	assert.False(t, kp.Verify([]byte("wrong message"), signature))

	// Wrong signature
	wrongSig := make([]byte, Ed25519SignatureSize)
	assert.False(t, kp.Verify(message, wrongSig))
}

func TestKeyPair_PublicKeyHash(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	hash := kp.PublicKeyHash()
	assert.Len(t, hash, 32) // SHA256

	// Same key should produce same hash
	hash2 := kp.PublicKeyHash()
	assert.Equal(t, hash, hash2)
}

func TestKeyPair_ExportImportPEM(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	// Export and import public key
	pubPEM, err := kp.ExportPublicKeyPEM()
	require.NoError(t, err)
	assert.Contains(t, string(pubPEM), "PUBLIC KEY")

	importedPub, err := ImportPublicKeyPEM(pubPEM)
	require.NoError(t, err)
	assert.Equal(t, kp.PublicKey, importedPub)

	// Export and import private key
	privPEM, err := kp.ExportPrivateKeyPEM()
	require.NoError(t, err)
	assert.Contains(t, string(privPEM), "PRIVATE KEY")

	importedPriv, err := ImportPrivateKeyPEM(privPEM)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, importedPriv)
}

func TestImportPublicKeyPEM_Invalid(t *testing.T) {
	_, err := ImportPublicKeyPEM([]byte("not a pem"))
	assert.Error(t, err)
}

func TestImportPrivateKeyPEM_Invalid(t *testing.T) {
	_, err := ImportPrivateKeyPEM([]byte("not a pem"))
	assert.Error(t, err)
}

func TestSign_Verify_Functions(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("test message")
	signature := Sign(kp.PrivateKey, message)

	assert.True(t, Verify(kp.PublicKey, message, signature))
	assert.False(t, Verify(kp.PublicKey, []byte("wrong"), signature))

	// Wrong signature length
	assert.False(t, Verify(kp.PublicKey, message, []byte("short")))
}

func TestGenerateX25519KeyPair(t *testing.T) {
	kp, err := GenerateX25519KeyPair()
	require.NoError(t, err)
	assert.NotNil(t, kp)
	assert.Len(t, kp.PublicKey, X25519KeySize)
	assert.Len(t, kp.PrivateKey, X25519KeySize)
}

func TestX25519KeyPair_ComputeSharedSecret(t *testing.T) {
	alice, err := GenerateX25519KeyPair()
	require.NoError(t, err)

	bob, err := GenerateX25519KeyPair()
	require.NoError(t, err)

	// Both should compute same shared secret
	aliceSecret, err := alice.ComputeSharedSecret(bob.PublicKey)
	require.NoError(t, err)

	bobSecret, err := bob.ComputeSharedSecret(alice.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, aliceSecret, bobSecret)
}

func TestDeriveKey(t *testing.T) {
	sharedSecret := []byte("shared-secret-32-bytes-long!!!!!")
	salt := []byte("salt")
	info := []byte("info")

	key, err := DeriveKey(sharedSecret, salt, info, 32)
	require.NoError(t, err)
	assert.Len(t, key, 32)

	// Same inputs should produce same key
	key2, err := DeriveKey(sharedSecret, salt, info, 32)
	require.NoError(t, err)
	assert.Equal(t, key, key2)

	// Nil salt should work
	key3, err := DeriveKey(sharedSecret, nil, info, 32)
	require.NoError(t, err)
	assert.Len(t, key3, 32)
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, AES256KeySize)
	copy(key, "32-byte-key-for-aes-256-encrypt!")

	plaintext := []byte("secret message")
	additionalData := []byte("additional data")

	encrypted, err := Encrypt(key, plaintext, additionalData)
	require.NoError(t, err)
	assert.NotNil(t, encrypted)
	assert.Equal(t, "AES-256-GCM", encrypted.Algorithm)
	assert.NotEmpty(t, encrypted.Ciphertext)
	assert.NotEmpty(t, encrypted.Nonce)

	decrypted, err := Decrypt(key, encrypted, additionalData)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	_, err := Encrypt([]byte("short"), []byte("data"), nil)
	assert.Error(t, err)
}

func TestDecrypt_InvalidKeySize(t *testing.T) {
	_, err := Decrypt([]byte("short"), &EncryptedData{}, nil)
	assert.Error(t, err)
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, AES256KeySize)
	key2 := make([]byte, AES256KeySize)
	copy(key1, "key-one-32-bytes-long-here!!!!")
	copy(key2, "key-two-32-bytes-long-here!!!!")

	encrypted, err := Encrypt(key1, []byte("secret"), nil)
	require.NoError(t, err)

	_, err = Decrypt(key2, encrypted, nil)
	assert.Error(t, err)
}

func TestHash(t *testing.T) {
	data := []byte("test data")
	hash := Hash(data)
	assert.Len(t, hash, 32) // SHA256

	// Same data should produce same hash
	hash2 := Hash(data)
	assert.Equal(t, hash, hash2)

	// Different data should produce different hash
	hash3 := Hash([]byte("different"))
	assert.NotEqual(t, hash, hash3)
}

func TestHashMultiple(t *testing.T) {
	data1 := []byte("first")
	data2 := []byte("second")

	hash := HashMultiple(data1, data2)
	assert.Len(t, hash, 32)

	// Order matters
	hashReversed := HashMultiple(data2, data1)
	assert.NotEqual(t, hash, hashReversed)
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce(16)
	require.NoError(t, err)
	assert.Len(t, nonce1, 16)

	nonce2, err := GenerateNonce(16)
	require.NoError(t, err)
	assert.NotEqual(t, nonce1, nonce2) // Should be random
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	require.NoError(t, err)
	assert.Len(t, salt, SaltSize)
}

func TestSecureCompare(t *testing.T) {
	a := []byte("same-value")
	b := []byte("same-value")
	c := []byte("different")
	d := []byte("same-value!")

	assert.True(t, SecureCompare(a, b))
	assert.False(t, SecureCompare(a, c))
	assert.False(t, SecureCompare(a, d)) // Different length
}

func TestInMemoryNonceStore(t *testing.T) {
	store := NewInMemoryNonceStore()

	nonce := []byte("test-nonce")
	timestamp := time.Now().UnixMilli()

	// Initially not exists
	assert.False(t, store.Exists(nonce))

	// Add nonce
	err := store.Add(nonce, timestamp)
	require.NoError(t, err)

	// Now exists
	assert.True(t, store.Exists(nonce))

	// Different nonce doesn't exist
	assert.False(t, store.Exists([]byte("other")))
}

func TestInMemoryNonceStore_Cleanup(t *testing.T) {
	store := NewInMemoryNonceStore()

	oldNonce := []byte("old-nonce")
	newNonce := []byte("new-nonce")

	// Add old nonce with old timestamp
	err := store.Add(oldNonce, time.Now().Add(-2*time.Hour).UnixMilli())
	require.NoError(t, err)

	// Add new nonce with current timestamp
	err = store.Add(newNonce, time.Now().UnixMilli())
	require.NoError(t, err)

	// Both exist before cleanup
	assert.True(t, store.Exists(oldNonce))
	assert.True(t, store.Exists(newNonce))

	// Cleanup old nonces
	err = store.Cleanup(1 * time.Hour)
	require.NoError(t, err)

	// Old nonce removed, new remains
	assert.False(t, store.Exists(oldNonce))
	assert.True(t, store.Exists(newNonce))
}

func TestEd25519Signer(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	signer := NewEd25519Signer(kp.PrivateKey)

	message := []byte("message to sign")
	signature, err := signer.Sign(nil, message, nil)
	require.NoError(t, err)

	// Verify with public key
	pub := signer.Public().(ed25519.PublicKey)
	assert.True(t, ed25519.Verify(pub, message, signature))
}

func TestMerkleTree(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
		[]byte("leaf4"),
	}

	tree := NewMerkleTree(leaves)
	assert.NotNil(t, tree)
	assert.NotEmpty(t, tree.Root)
	assert.Len(t, tree.Leaves, 4)
}

func TestMerkleTree_Empty(t *testing.T) {
	tree := NewMerkleTree([][]byte{})
	assert.NotNil(t, tree)
	assert.Empty(t, tree.Root)
}

func TestMerkleTree_SingleLeaf(t *testing.T) {
	tree := NewMerkleTree([][]byte{[]byte("single")})
	assert.NotNil(t, tree)
	assert.NotEmpty(t, tree.Root)
}

func TestMerkleTree_GetProof(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
		[]byte("leaf4"),
	}

	tree := NewMerkleTree(leaves)

	proof, err := tree.GetProof(0)
	require.NoError(t, err)
	assert.Equal(t, 0, proof.LeafIndex)
	assert.Equal(t, tree.Root, proof.Root)
}

func TestMerkleTree_GetProof_InvalidIndex(t *testing.T) {
	tree := NewMerkleTree([][]byte{[]byte("leaf")})

	_, err := tree.GetProof(-1)
	assert.Error(t, err)

	_, err = tree.GetProof(5)
	assert.Error(t, err)
}

func TestVerifyMerkleProof(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
		[]byte("leaf4"),
	}

	tree := NewMerkleTree(leaves)

	for i := 0; i < len(leaves); i++ {
		proof, err := tree.GetProof(i)
		require.NoError(t, err)

		assert.True(t, VerifyMerkleProof(proof), "proof for leaf %d should be valid", i)
	}
}

func TestVerifyMerkleProof_Invalid(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
	}

	tree := NewMerkleTree(leaves)
	proof, err := tree.GetProof(0)
	require.NoError(t, err)

	// Tamper with proof
	proof.LeafHash = []byte("tampered")
	assert.False(t, VerifyMerkleProof(proof))
}

func TestHybridEncrypt(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	recipients := map[string]ed25519.PublicKey{
		"user1": kp1.PublicKey,
		"user2": kp2.PublicKey,
	}

	plaintext := []byte("secret data for multiple recipients")
	encrypted, err := HybridEncrypt(plaintext, recipients)
	require.NoError(t, err)
	assert.NotNil(t, encrypted)
	assert.Len(t, encrypted.Encapsulations, 2)
	assert.NotNil(t, encrypted.EncryptedData)
}

// Benchmarks

func BenchmarkKeyPair_Sign(b *testing.B) {
	kp, _ := GenerateKeyPair()
	message := []byte("benchmark message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kp.Sign(message)
	}
}

func BenchmarkKeyPair_Verify(b *testing.B) {
	kp, _ := GenerateKeyPair()
	message := []byte("benchmark message")
	signature := kp.Sign(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kp.Verify(message, signature)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, AES256KeySize)
	copy(key, "32-byte-key-for-aes-256-encrypt!")
	plaintext := bytes.Repeat([]byte("x"), 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(key, plaintext, nil)
	}
}

func BenchmarkHash(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}
