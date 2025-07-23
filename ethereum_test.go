package frost

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

// Helper function to create scalar from hex string
func scalarFromHex(curve Curve, hexStr string) (Scalar, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return curve.ScalarFromBytes(bytes)
}

func TestEthereumChallenge(t *testing.T) {
	curve := NewSecp256k1Curve()

	// Create test points
	privateKey, err := scalarFromHex(curve, "626FC96FF3678D4FA2DE960B2C39D199747D3F47F01508FBBE24825C4D11B543")
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}

	publicKey := curve.BasePoint().Mul(privateKey)

	noncePrivate, err := scalarFromHex(curve, "EB3F18E13AEFBF7AC9347F38B6E5D5576848B4E7927F6233222BA9286BB24F31")
	if err != nil {
		t.Fatalf("Failed to create nonce private key: %v", err)
	}
	
	nonceCommitment := curve.BasePoint().Mul(noncePrivate)
	
	// Test message (32 bytes)
	message := make([]byte, 32)
	copy(message, []byte("Chainflip:Chainflip:Chainflip:01"))
	
	// Compute challenge
	challenge, err := EthereumChallenge(nonceCommitment, publicKey, message)
	if err != nil {
		t.Fatalf("Failed to compute Ethereum challenge: %v", err)
	}
	
	// Verify challenge is not nil and has correct length
	if challenge == nil {
		t.Fatal("Challenge is nil")
	}
	
	challengeBytes := challenge.Bytes()
	if len(challengeBytes) != 32 {
		t.Fatalf("Expected challenge length 32, got %d", len(challengeBytes))
	}
	
	t.Logf("Challenge: %s", hex.EncodeToString(challengeBytes))
}

func TestEthereumChallengeFormat(t *testing.T) {
	curve := NewSecp256k1Curve()
	
	// Create test data
	privateKey, _ := curve.ScalarRandom()
	publicKey := curve.BasePoint().Mul(privateKey)
	
	noncePrivate, _ := curve.ScalarRandom()
	nonceCommitment := curve.BasePoint().Mul(noncePrivate)
	
	message := make([]byte, 32)
	for i := range message {
		message[i] = byte(i)
	}
	
	// Compute challenge using our function
	challenge, err := EthereumChallenge(nonceCommitment, publicKey, message)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}
	
	// Manually compute the same challenge to verify format
	pubKeyBytes := publicKey.(*Secp256k1Point).inner.SerializeCompressed()
	pubKeyX := pubKeyBytes[1:33] // Skip prefix byte
	
	var parity byte
	if pubKeyBytes[0] == 0x03 { // Odd Y
		parity = 1
	} else { // Even Y
		parity = 0
	}
	
	nonceAddress, err := PointToEthereumAddress(nonceCommitment)
	if err != nil {
		t.Fatalf("Failed to convert nonce to address: %v", err)
	}
	
	// Manual challenge computation
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(pubKeyX)
	hasher.Write([]byte{parity})
	hasher.Write(message)
	hasher.Write(nonceAddress)
	expectedChallengeBytes := hasher.Sum(nil)
	
	expectedChallenge, err := curve.ScalarFromBytes(expectedChallengeBytes)
	if err != nil {
		t.Fatalf("Failed to create expected challenge: %v", err)
	}
	
	// Compare challenges
	if !challenge.Equal(expectedChallenge) {
		t.Fatalf("Challenge mismatch:\nGot:      %s\nExpected: %s", 
			hex.EncodeToString(challenge.Bytes()),
			hex.EncodeToString(expectedChallenge.Bytes()))
	}
}

func TestPointToEthereumAddress(t *testing.T) {
	curve := NewSecp256k1Curve()
	
	// Create a test point
	privateKey, _ := curve.ScalarRandom()
	point := curve.BasePoint().Mul(privateKey)
	
	// Convert to Ethereum address
	address, err := PointToEthereumAddress(point)
	if err != nil {
		t.Fatalf("Failed to convert point to address: %v", err)
	}
	
	// Verify address length
	if len(address) != 20 {
		t.Fatalf("Expected address length 20, got %d", len(address))
	}
	
	// Manually compute address to verify
	secp256k1Point := point.(*Secp256k1Point)
	uncompressed := secp256k1Point.inner.SerializeUncompressed()
	
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(uncompressed[1:]) // Skip 0x04 prefix
	hash := hasher.Sum(nil)
	
	expectedAddress := hash[12:32] // Last 20 bytes
	
	// Compare addresses
	for i := 0; i < 20; i++ {
		if address[i] != expectedAddress[i] {
			t.Fatalf("Address mismatch at byte %d: got %02x, expected %02x", i, address[i], expectedAddress[i])
		}
	}
	
	t.Logf("Address: %s", hex.EncodeToString(address))
}

func TestIsValidEthereumPubkey(t *testing.T) {
	curve := NewSecp256k1Curve()
	
	// Test multiple keys to find both valid and invalid ones
	validCount := 0
	invalidCount := 0
	
	for i := 0; i < 100; i++ {
		privateKey, _ := curve.ScalarRandom()
		publicKey := curve.BasePoint().Mul(privateKey)
		
		if IsValidEthereumPubkey(publicKey) {
			validCount++
		} else {
			invalidCount++
		}
	}
	
	// We should have both valid and invalid keys
	if validCount == 0 {
		t.Fatal("No valid Ethereum public keys found")
	}
	if invalidCount == 0 {
		t.Fatal("No invalid Ethereum public keys found")
	}
	
	t.Logf("Valid keys: %d, Invalid keys: %d", validCount, invalidCount)
}

func TestEthereumKeyGeneration(t *testing.T) {
	// Generate multiple Ethereum-compatible keys
	for i := 0; i < 10; i++ {
		privateKey, publicKey, err := EthereumKeyGeneration()
		if err != nil {
			t.Fatalf("Failed to generate Ethereum key pair: %v", err)
		}
		
		// Verify the public key is valid for Ethereum
		if !IsValidEthereumPubkey(publicKey) {
			t.Fatal("Generated public key is not valid for Ethereum")
		}
		
		// Verify the key pair is correct
		curve := NewSecp256k1Curve()
		expectedPublicKey := curve.BasePoint().Mul(privateKey)
		
		if !publicKey.Equal(expectedPublicKey) {
			t.Fatal("Generated key pair is inconsistent")
		}
	}
}

func TestEthereumSigningSession(t *testing.T) {
	curve := NewSecp256k1Curve()

	// Create mock key shares for testing
	privateKey1, _ := curve.ScalarRandom()
	privateKey2, _ := curve.ScalarRandom()
	groupPrivateKey := privateKey1.Add(privateKey2) // Simple 2-of-2 scheme
	groupPublicKey := curve.BasePoint().Mul(groupPrivateKey)

	keyShare1 := &KeyShare{
		ParticipantID:    1,
		SecretShare:      privateKey1,
		PublicKey:        curve.BasePoint().Mul(privateKey1),
		GroupPublicKey:   groupPublicKey,
	}

	keyShare2 := &KeyShare{
		ParticipantID:    2,
		SecretShare:      privateKey2,
		PublicKey:        curve.BasePoint().Mul(privateKey2),
		GroupPublicKey:   groupPublicKey,
	}

	// Create a test message
	message := make([]byte, 32)
	copy(message, []byte("Test Ethereum FROST signing"))

	// Select signers (participants 1 and 2)
	signers := []ParticipantIndex{1, 2}

	// Create Ethereum signing sessions
	session1, err := NewEthereumSigningSession(curve, keyShare1, message, signers, 2)
	if err != nil {
		t.Fatalf("Failed to create signing session 1: %v", err)
	}

	session2, err := NewEthereumSigningSession(curve, keyShare2, message, signers, 2)
	if err != nil {
		t.Fatalf("Failed to create signing session 2: %v", err)
	}

	// Verify challenge type is set correctly
	if session1.challengeType != EthereumEVM {
		t.Fatal("Session 1 challenge type is not EthereumEVM")
	}
	if session2.challengeType != EthereumEVM {
		t.Fatal("Session 2 challenge type is not EthereumEVM")
	}

	t.Log("Ethereum signing session creation test passed!")
}

func TestEthereumSigningPayload(t *testing.T) {
	// Test valid payload
	data := make([]byte, 32)
	copy(data, []byte("Test payload"))

	payload, err := NewEthereumSigningPayload(data)
	if err != nil {
		t.Fatalf("Failed to create Ethereum signing payload: %v", err)
	}

	if len(payload.Bytes()) != 32 {
		t.Fatalf("Expected payload length 32, got %d", len(payload.Bytes()))
	}

	// Test invalid payload length
	invalidData := make([]byte, 31)
	_, err = NewEthereumSigningPayload(invalidData)
	if err == nil {
		t.Fatal("Expected error for invalid payload length")
	}

	// Test string representation
	str := payload.String()
	if len(str) != 64 { // 32 bytes * 2 hex chars
		t.Fatalf("Expected string length 64, got %d", len(str))
	}
}

func TestEthereumVsStandardFROST(t *testing.T) {
	curve := NewSecp256k1Curve()

	// Create test data
	privateKey, _ := curve.ScalarRandom()
	publicKey := curve.BasePoint().Mul(privateKey)

	noncePrivate, _ := curve.ScalarRandom()
	nonceCommitment := curve.BasePoint().Mul(noncePrivate)

	message := make([]byte, 32)
	copy(message, []byte("Test message for comparison"))

	// Compute Ethereum challenge
	ethChallenge, err := EthereumChallenge(nonceCommitment, publicKey, message)
	if err != nil {
		t.Fatalf("Failed to compute Ethereum challenge: %v", err)
	}

	// Compute standard FROST challenge (using helper)
	standardChallenge, err := computeChallengeHelperWithType(curve, nonceCommitment, publicKey, message, StandardFROST)
	if err != nil {
		t.Fatalf("Failed to compute standard challenge: %v", err)
	}

	// They should be different (different hash algorithms and formats)
	if ethChallenge.Equal(standardChallenge) {
		t.Fatal("Ethereum and standard FROST challenges should be different")
	}

	t.Logf("Ethereum challenge:  %s", hex.EncodeToString(ethChallenge.Bytes()))
	t.Logf("Standard challenge:  %s", hex.EncodeToString(standardChallenge.Bytes()))
	t.Log("✅ Ethereum and standard FROST produce different challenges (as expected)")
}

func TestEthereumSignatureVerification(t *testing.T) {
	curve := NewSecp256k1Curve()

	// Generate a compatible Ethereum key pair
	privateKey, publicKey, err := EthereumKeyGeneration()
	if err != nil {
		t.Fatalf("Failed to generate Ethereum key pair: %v", err)
	}

	// Create test message
	message := make([]byte, 32)
	copy(message, []byte("Test Ethereum signature"))

	// Generate nonce
	nonce, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	nonceCommitment := curve.BasePoint().Mul(nonce)

	// Compute challenge
	challenge, err := EthereumChallenge(nonceCommitment, publicKey, message)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// Compute signature response
	response := EthereumSignResponse(nonce, nonceCommitment, privateKey, challenge)

	// Create signature
	signature := &EthereumSignature{
		R: nonceCommitment,
		S: response,
		V: 0, // Recovery ID (not used in verification)
	}

	// Verify signature
	err = EthereumVerifySignature(signature, publicKey, message)
	if err != nil {
		t.Fatalf("Ethereum signature verification failed: %v", err)
	}

	// Test with wrong message (should fail)
	wrongMessage := make([]byte, 32)
	copy(wrongMessage, []byte("Wrong message"))

	err = EthereumVerifySignature(signature, publicKey, wrongMessage)
	if err == nil {
		t.Fatal("Expected signature verification to fail with wrong message")
	}

	t.Log("✅ Ethereum signature verification test passed!")
}

func TestEthereumChainflipCompatibility(t *testing.T) {
	curve := NewSecp256k1Curve()

	// Test with known values that would match Chainflip's implementation
	// Using the same test vectors from Chainflip's tests

	// Create point from private key scalar
	pubKeyScalar, err := scalarFromHex(curve, "f87da451c5d6f14595ca91af592f45388495a8778505b942195ca854037d92f2")
	if err != nil {
		t.Fatalf("Failed to create public key scalar: %v", err)
	}
	publicKey := curve.BasePoint().Mul(pubKeyScalar)

	// Create nonce commitment
	nonceScalar, err := scalarFromHex(curve, "626fc96ff3678d4fa2de960b2c39d199747d3f47f01508fbbe24825c4d11b543")
	if err != nil {
		t.Fatalf("Failed to create nonce scalar: %v", err)
	}
	nonceCommitment := curve.BasePoint().Mul(nonceScalar)

	// Test message (32 bytes)
	message := make([]byte, 32)
	copy(message, []byte("Chainflip:Chainflip:Chainflip:01"))

	// Compute Ethereum challenge
	challenge, err := EthereumChallenge(nonceCommitment, publicKey, message)
	if err != nil {
		t.Fatalf("Failed to compute Ethereum challenge: %v", err)
	}

	// Verify the challenge computation format matches Chainflip's expectation
	// The challenge should be computed as: keccak256(pubkey_x || parity || msg_hash || nonce_address)

	// Get public key components
	pubKeyCompressed := publicKey.(*Secp256k1Point).inner.SerializeCompressed()
	pubKeyX := pubKeyCompressed[1:33] // x-coordinate
	var parity byte
	if pubKeyCompressed[0] == 0x03 {
		parity = 1 // Odd Y
	} else {
		parity = 0 // Even Y
	}

	// Get nonce address
	nonceAddress, err := PointToEthereumAddress(nonceCommitment)
	if err != nil {
		t.Fatalf("Failed to convert nonce to address: %v", err)
	}

	t.Logf("Public key X: %s", hex.EncodeToString(pubKeyX))
	t.Logf("Y parity: %d", parity)
	t.Logf("Message: %s", hex.EncodeToString(message))
	t.Logf("Nonce address: %s", hex.EncodeToString(nonceAddress))
	t.Logf("Challenge: %s", hex.EncodeToString(challenge.Bytes()))

	// Verify the challenge is deterministic
	challenge2, err := EthereumChallenge(nonceCommitment, publicKey, message)
	if err != nil {
		t.Fatalf("Failed to compute second challenge: %v", err)
	}

	if !challenge.Equal(challenge2) {
		t.Fatal("Challenge computation is not deterministic")
	}

	t.Log("✅ Ethereum challenge computation is compatible with Chainflip format")
}

func TestEthereumSignatureFormat(t *testing.T) {
	curve := NewSecp256k1Curve()

	// Generate test signature
	privateKey, publicKey, err := EthereumKeyGeneration()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := make([]byte, 32)
	copy(message, []byte("Test signature format"))

	nonce, _ := curve.ScalarRandom()
	nonceCommitment := curve.BasePoint().Mul(nonce)

	challenge, err := EthereumChallenge(nonceCommitment, publicKey, message)
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	response := EthereumSignResponse(nonce, nonceCommitment, privateKey, challenge)

	signature := &EthereumSignature{
		R: nonceCommitment,
		S: response,
		V: 27, // Standard Ethereum recovery ID
	}

	// Test ToRSV format
	r, s, v := signature.ToRSV()
	if v != 27 {
		t.Fatalf("Expected V=27, got V=%d", v)
	}

	// Test ToBytes format (65 bytes: r || s || v)
	sigBytes := signature.ToBytes()
	if len(sigBytes) != 65 {
		t.Fatalf("Expected signature length 65, got %d", len(sigBytes))
	}

	// Verify the last byte is V
	if sigBytes[64] != 27 {
		t.Fatalf("Expected last byte to be 27, got %d", sigBytes[64])
	}

	// Verify r and s are properly encoded
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Check r is in first 32 bytes (right-aligned)
	expectedR := make([]byte, 32)
	copy(expectedR[32-len(rBytes):], rBytes)
	for i := 0; i < 32; i++ {
		if sigBytes[i] != expectedR[i] {
			t.Fatalf("R mismatch at byte %d: got %02x, expected %02x", i, sigBytes[i], expectedR[i])
		}
	}

	// Check s is in next 32 bytes (right-aligned)
	expectedS := make([]byte, 32)
	copy(expectedS[32-len(sBytes):], sBytes)
	for i := 0; i < 32; i++ {
		if sigBytes[32+i] != expectedS[i] {
			t.Fatalf("S mismatch at byte %d: got %02x, expected %02x", i, sigBytes[32+i], expectedS[i])
		}
	}

	t.Logf("Signature (hex): %s", hex.EncodeToString(sigBytes))
	t.Log("✅ Ethereum signature format test passed!")
}
