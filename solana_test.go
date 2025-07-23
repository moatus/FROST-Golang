package frost

import (
    "bytes"
    "crypto/rand"
    "crypto/sha512"
    "testing"
)

// TestSolanaChallenge tests the Solana Ed25519 challenge computation
func TestSolanaChallenge(t *testing.T) {
    curve := NewEd25519Curve()
    
    // Create test keys
    privateKey, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate private key: %v", err)
    }
    defer privateKey.Zeroize()
    
    publicKey := curve.BasePoint().Mul(privateKey)
    
    // Create test nonce
    nonce, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate nonce: %v", err)
    }
    defer nonce.Zeroize()
    
    commitment := curve.BasePoint().Mul(nonce)
    
    // Test message
    message := []byte("test message for Solana challenge")
    
    // Compute challenge
    challenge, err := SolanaChallenge(commitment, publicKey, message)
    if err != nil {
        t.Fatalf("Failed to compute Solana challenge: %v", err)
    }
    defer challenge.Zeroize()
    
    // Verify challenge is not zero
    if challenge.IsZero() {
        t.Error("Challenge should not be zero")
    }
    
    // Test deterministic behavior
    challenge2, err := SolanaChallenge(commitment, publicKey, message)
    if err != nil {
        t.Fatalf("Failed to compute second challenge: %v", err)
    }
    defer challenge2.Zeroize()
    
    if !challenge.Equal(challenge2) {
        t.Error("Challenge computation should be deterministic")
    }
}

// TestSolanaChallengeSHA512 verifies that Solana challenge uses SHA512
func TestSolanaChallengeSHA512(t *testing.T) {
    curve := NewEd25519Curve()
    
    // Create test points
    scalar1, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to create scalar 1: %v", err)
    }
    defer scalar1.Zeroize()
    
    scalar2, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to create scalar 2: %v", err)
    }
    defer scalar2.Zeroize()
    
    publicKey := curve.BasePoint().Mul(scalar1)
    commitment := curve.BasePoint().Mul(scalar2)
    message := []byte("test message")
    
    // Compute challenge using our function
    challenge, err := SolanaChallenge(commitment, publicKey, message)
    if err != nil {
        t.Fatalf("Failed to compute challenge: %v", err)
    }
    defer challenge.Zeroize()
    
    // Manually compute expected challenge using SHA512
    hasher := sha512.New()
    hasher.Write(commitment.CompressedBytes())
    hasher.Write(publicKey.CompressedBytes())
    hasher.Write(message)
    expectedBytes := hasher.Sum(nil)
    
    expectedChallenge, err := curve.ScalarFromUniformBytes(expectedBytes)
    if err != nil {
        t.Fatalf("Failed to create expected challenge: %v", err)
    }
    defer expectedChallenge.Zeroize()
    
    // Verify they match
    if !challenge.Equal(expectedChallenge) {
        t.Error("Challenge should match manual SHA512 computation")
    }
}

// TestSolanaSignatureRoundTrip tests signature creation and verification
func TestSolanaSignatureRoundTrip(t *testing.T) {
    curve := NewEd25519Curve()
    
    // Generate key pair
    privateKey, publicKey, err := SolanaKeyGeneration()
    if err != nil {
        t.Fatalf("Failed to generate key pair: %v", err)
    }
    defer privateKey.Zeroize()
    
    // Test message
    message := []byte("Hello Solana FROST!")
    
    // Generate nonce
    nonce, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate nonce: %v", err)
    }
    defer nonce.Zeroize()
    
    commitment := curve.BasePoint().Mul(nonce)
    
    // Compute challenge
    challenge, err := SolanaChallenge(commitment, publicKey, message)
    if err != nil {
        t.Fatalf("Failed to compute challenge: %v", err)
    }
    defer challenge.Zeroize()
    
    // Compute signature response
    response, err := SolanaSignResponse(nonce, privateKey, challenge)
    if err != nil {
        t.Fatalf("Failed to compute signature response: %v", err)
    }
    defer response.Zeroize()
    
    // Create signature
    signature := &SolanaSignature{
        R: commitment,
        S: response,
    }
    
    // Verify signature
    err = VerifySolanaSignature(signature, publicKey, message)
    if err != nil {
        t.Errorf("Signature verification failed: %v", err)
    }
    
    // Test with wrong message
    wrongMessage := []byte("Wrong message")
    err = VerifySolanaSignature(signature, publicKey, wrongMessage)
    if err == nil {
        t.Error("Signature should not verify with wrong message")
    }
}

// TestSolanaSignatureBytes tests signature serialization
func TestSolanaSignatureBytes(t *testing.T) {
    curve := NewEd25519Curve()
    
    // Create test signature
    r, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate R scalar: %v", err)
    }
    defer r.Zeroize()
    
    s, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate S scalar: %v", err)
    }
    defer s.Zeroize()
    
    rPoint := curve.BasePoint().Mul(r)
    
    signature := &SolanaSignature{
        R: rPoint,
        S: s,
    }
    
    // Test serialization
    sigBytes, err := signature.Bytes()
    if err != nil {
        t.Fatalf("Failed to serialize signature: %v", err)
    }
    if len(sigBytes) != 64 {
        t.Errorf("Signature bytes should be 64 bytes, got %d", len(sigBytes))
    }
    
    // Test deserialization
    signature2, err := SolanaSignatureFromBytes(sigBytes)
    if err != nil {
        t.Fatalf("Failed to deserialize signature: %v", err)
    }
    
    // Verify round-trip
    if !signature.R.Equal(signature2.R) {
        t.Error("R point should match after round-trip")
    }
    
    if !signature.S.Equal(signature2.S) {
        t.Error("S scalar should match after round-trip")
    }
}

// TestSolanaKeyGeneration tests key generation
func TestSolanaKeyGeneration(t *testing.T) {
    privateKey, publicKey, err := SolanaKeyGeneration()
    if err != nil {
        t.Fatalf("Failed to generate key pair: %v", err)
    }
    defer privateKey.Zeroize()
    
    // Verify key pair is valid
    if privateKey.IsZero() {
        t.Error("Private key should not be zero")
    }
    
    if publicKey == nil {
        t.Error("Public key should not be nil")
    }
    
    // Verify public key derivation
    curve := NewEd25519Curve()
    expectedPublicKey := curve.BasePoint().Mul(privateKey)
    
    if !publicKey.Equal(expectedPublicKey) {
        t.Error("Public key should match private key * base point")
    }
}

// TestSolanaValidation tests input validation
func TestSolanaValidation(t *testing.T) {
    curve := NewEd25519Curve()
    
    // Test nil points
    _, err := SolanaChallenge(nil, curve.BasePoint(), []byte("test"))
    if err == nil {
        t.Error("Should reject nil R point")
    }
    
    _, err = SolanaChallenge(curve.BasePoint(), nil, []byte("test"))
    if err == nil {
        t.Error("Should reject nil public key")
    }
    
    // Test empty message (valid per Solana Ed25519 spec)
    _, err = SolanaChallenge(curve.BasePoint(), curve.BasePoint(), []byte{})
    if err != nil {
        t.Errorf("Should accept empty message per Solana Ed25519 spec, got error: %v", err)
    }
    
    // Test invalid signature bytes
    _, err = SolanaSignatureFromBytes([]byte{1, 2, 3}) // Too short
    if err == nil {
        t.Error("Should reject short signature bytes")
    }
    
    _, err = SolanaSignatureFromBytes(make([]byte, 100)) // Too long
    if err == nil {
        t.Error("Should reject long signature bytes")
    }
}

// TestSolanaCompatibilityWithChainflip tests compatibility with Chainflip's approach
func TestSolanaCompatibilityWithChainflip(t *testing.T) {
    curve := NewEd25519Curve()

    // Create test data similar to Chainflip's test
    privateKey, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate private key: %v", err)
    }
    defer privateKey.Zeroize()

    publicKey := curve.BasePoint().Mul(privateKey)

    // Test payload (similar to Chainflip's SigningPayload)
    payload := make([]byte, 32)
    rand.Read(payload)

    // Generate nonce
    nonce, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate nonce: %v", err)
    }
    defer nonce.Zeroize()

    nonceCommitment := curve.BasePoint().Mul(nonce)

    // Compute challenge using our implementation
    challenge, err := SolanaChallenge(nonceCommitment, publicKey, payload)
    if err != nil {
        t.Fatalf("Failed to compute challenge: %v", err)
    }
    defer challenge.Zeroize()

    // Compute response
    response, err := SolanaSignResponse(nonce, privateKey, challenge)
    if err != nil {
        t.Fatalf("Failed to compute signature response: %v", err)
    }
    defer response.Zeroize()

    // Create signature
    signature := &SolanaSignature{
        R: nonceCommitment,
        S: response,
    }

    // Verify signature
    err = VerifySolanaSignature(signature, publicKey, payload)
    if err != nil {
        t.Errorf("Signature verification failed: %v", err)
    }

    // Verify the signature format matches Chainflip's expectation (64 bytes)
    sigBytes, err := signature.Bytes()
    if err != nil {
        t.Fatalf("Failed to serialize signature: %v", err)
    }
    if len(sigBytes) != 64 {
        t.Errorf("Signature should be 64 bytes, got %d", len(sigBytes))
    }

    // Verify R and S are 32 bytes each
    if !bytes.Equal(sigBytes[:32], nonceCommitment.CompressedBytes()) {
        t.Error("First 32 bytes should be R point")
    }

    if !bytes.Equal(sigBytes[32:], response.Bytes()) {
        t.Error("Last 32 bytes should be S scalar")
    }
}

// TestSolanaFROSTSigningSession tests the complete Solana FROST signing workflow
func TestSolanaFROSTSigningSession(t *testing.T) {
    curve := NewEd25519Curve()

    // Test parameters
    threshold := 2
    participants := []ParticipantIndex{1, 2, 3}
    message := []byte("Solana FROST test message")
    signers := []ParticipantIndex{1, 2}

    // Generate key shares (simplified for testing)
    keyShares := make(map[ParticipantIndex]*KeyShare)

    // Create mock key shares
    for _, id := range participants {
        privateKey, err := curve.ScalarRandom()
        if err != nil {
            t.Fatalf("Failed to generate private key for participant %d: %v", id, err)
        }
        defer privateKey.Zeroize()

        keyShares[id] = &KeyShare{
            ParticipantID:    id,
            SecretShare:      privateKey,
            PublicKey:        curve.BasePoint().Mul(privateKey), // Simplified
            GroupPublicKey:   curve.BasePoint().Mul(privateKey), // Simplified
        }
    }

    // Create Solana signing sessions for each signer
    sessions := make(map[ParticipantIndex]*SigningSession)
    for _, signerID := range signers {
        session, err := NewSolanaSigningSession(
            curve,
            keyShares[signerID],
            message,
            signers,
            threshold,
        )
        if err != nil {
            t.Fatalf("Failed to create Solana signing session for participant %d: %v", signerID, err)
        }
        sessions[signerID] = session
    }

    // Verify that sessions use Solana challenge type
    for signerID, session := range sessions {
        if session.challengeType != SolanaEd25519 {
            t.Errorf("Participant %d should use SolanaEd25519 challenge type, got %v", signerID, session.challengeType)
        }
    }

    // Test challenge computation with Solana method
    testR := curve.BasePoint().Mul(keyShares[1].SecretShare)
    testPubKey := keyShares[1].GroupPublicKey

    challenge, err := sessions[1].computeChallenge(testR, testPubKey, message)
    if err != nil {
        t.Fatalf("Failed to compute challenge: %v", err)
    }
    defer challenge.Zeroize()

    // Verify it matches direct Solana challenge computation
    expectedChallenge, err := SolanaChallenge(testR, testPubKey, message)
    if err != nil {
        t.Fatalf("Failed to compute expected challenge: %v", err)
    }
    defer expectedChallenge.Zeroize()

    if !challenge.Equal(expectedChallenge) {
        t.Error("Session challenge should match direct Solana challenge computation")
    }

    t.Log("✅ Solana FROST signing session test passed!")
}
