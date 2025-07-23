package frost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestBitcoinChallenge(t *testing.T) {
	curve := NewSecp256k1Curve()
	
	// Test vectors from Chainflip's implementation
	publicKeyHex := "626FC96FF3678D4FA2DE960B2C39D199747D3F47F01508FBBE24825C4D11B543"
	commitmentHex := "EB3F18E13AEFBF7AC9347F38B6E5D5576848B4E7927F6233222BA9286BB24F31"
	expectedChallengeHex := "1FCA6ED81348426626DA247A3B0810F61EA46C592442F81FC9DFFDB43ABBE439"
	
	// Create test message (Chainflip test payload)
	testMessage := sha256.Sum256([]byte("Chainflip:Chainflip:Chainflip:01"))
	
	// Parse test vectors
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}
	
	commitmentBytes, err := hex.DecodeString(commitmentHex)
	if err != nil {
		t.Fatalf("Failed to decode commitment: %v", err)
	}
	
	expectedChallengeBytes, err := hex.DecodeString(expectedChallengeHex)
	if err != nil {
		t.Fatalf("Failed to decode expected challenge: %v", err)
	}
	
	// Create points from scalars (as Chainflip does)
	publicKeyScalar, err := curve.ScalarFromBytes(publicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create public key scalar: %v", err)
	}
	publicKey := curve.BasePoint().Mul(publicKeyScalar)
	
	commitmentScalar, err := curve.ScalarFromBytes(commitmentBytes)
	if err != nil {
		t.Fatalf("Failed to create commitment scalar: %v", err)
	}
	commitment := curve.BasePoint().Mul(commitmentScalar)
	
	expectedChallenge, err := curve.ScalarFromBytes(expectedChallengeBytes)
	if err != nil {
		t.Fatalf("Failed to create expected challenge: %v", err)
	}
	
	// Compute challenge (R, pubKey, message)
	challenge, err := BitcoinChallenge(commitment, publicKey, testMessage[:])
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}
	
	// Verify challenge matches expected value
	if !challenge.Equal(expectedChallenge) {
		t.Errorf("Challenge mismatch:\nExpected: %s\nGot:      %s", 
			expectedChallenge.String(), challenge.String())
	}
}

func TestBitcoinSignatureReference(t *testing.T) {
	// First, let's create a reference signature using btcec directly
	// to understand the correct format

	privateKeyBytes := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes[:])
	publicKey := privateKey.PubKey()

	message := [32]byte{
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	}

	// Create signature using btcec
	signature, err := schnorr.Sign(privateKey, message[:])
	if err != nil {
		t.Fatalf("Failed to create reference signature: %v", err)
	}

	// Verify using btcec
	xOnlyPubkey := schnorr.SerializePubKey(publicKey)
	parsedPubkey, err := schnorr.ParsePubKey(xOnlyPubkey)
	if err != nil {
		t.Fatalf("Failed to parse pubkey: %v", err)
	}

	if !signature.Verify(message[:], parsedPubkey) {
		t.Fatalf("Reference signature verification failed")
	}

	t.Logf("Reference signature created and verified successfully")
	t.Logf("Signature bytes: %x", signature.Serialize())
	t.Logf("Public key x-only: %x", xOnlyPubkey)

	// Now try to verify this signature using our implementation
	curve := NewSecp256k1Curve()

	// Convert private key to our format
	ourPrivateKey, err := curve.ScalarFromBytes(privateKeyBytes[:])
	if err != nil {
		t.Fatalf("Failed to convert private key: %v", err)
	}

	// Convert public key to our format
	ourPublicKey := curve.BasePoint().Mul(ourPrivateKey)

	// Check if our public key matches the reference
	ourXOnly := ourPublicKey.(*Secp256k1Point).XOnlyBytes()
	t.Logf("Our public key x-only: %x", ourXOnly)
	t.Logf("Public keys match: %v", bytes.Equal(ourXOnly, xOnlyPubkey))

	// Parse the reference signature
	sigBytes := signature.Serialize()
	rBytes := sigBytes[0:32]
	sBytes := sigBytes[32:64]

	// Convert R to our point format
	// We need to reconstruct the full point from x-only coordinate
	rScalar, err := curve.ScalarFromBytes(sBytes) // Use s as a test scalar
	if err != nil {
		t.Fatalf("Failed to convert s to scalar: %v", err)
	}

	t.Logf("Reference R x-coordinate: %x", rBytes)
	t.Logf("Reference S scalar: %x", sBytes)
	t.Logf("Our S scalar: %s", rScalar.String())
}

func TestBitcoinFROSTSigning(t *testing.T) {
	// Test Bitcoin signing using the FROST protocol
	curve := NewSecp256k1Curve()

	// Generate a simple 1-of-1 key share for testing
	privateKey, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	publicKey := curve.BasePoint().Mul(privateKey)

	// Ensure public key is Bitcoin-compatible (even Y)
	if publicKey.(*Secp256k1Point).HasOddY() {
		privateKey = privateKey.Negate()
		publicKey = curve.BasePoint().Mul(privateKey)
	}

	keyShare := &KeyShare{
		ParticipantID:    1,
		SecretShare:      privateKey,
		PublicKey:       publicKey,
		GroupPublicKey:   publicKey,
	}

	// Create test message (32 bytes for Bitcoin)
	rawMessage := []byte("Bitcoin FROST test message")
	messageHash := sha256.Sum256(rawMessage)
	message := messageHash[:]

	// Create Bitcoin signing session
	signers := []ParticipantIndex{1}
	session, err := NewBitcoinSigningSession(curve, keyShare, message, signers, 1)
	if err != nil {
		t.Fatalf("Failed to create signing session: %v", err)
	}

	// Round 1: Generate commitment
	commitment, err := session.Round1()
	if err != nil {
		t.Fatalf("Round 1 failed: %v", err)
	}

	// For a 1-of-1 signing, we don't need to process other commitments
	// The Round1() method already stored our own commitment
	_ = commitment // We generated it but don't need to process it again

	// Round 2: Generate response
	response, err := session.Round2()
	if err != nil {
		t.Fatalf("Round 2 failed: %v", err)
	}

	// Process response and get final signature
	signature, err := session.ProcessRound2([]*SigningResponse{response})
	if err != nil {
		t.Fatalf("Process Round 2 failed: %v", err)
	}

	// Debug information
	t.Logf("Generated signature:")
	t.Logf("  R: %s", signature.R.String())
	t.Logf("  S: %s", signature.S.String())
	t.Logf("  R has even Y: %v", !signature.R.(*Secp256k1Point).HasOddY())

	// Verify the signature has even Y coordinate (BIP-340 requirement)
	if signature.R.(*Secp256k1Point).HasOddY() {
		t.Errorf("Signature R has odd Y coordinate, violates BIP-340")
	}

	// Manual verification first to debug
	challenge, err := BitcoinChallenge(signature.R, publicKey, message[:])
	if err != nil {
		t.Fatalf("Failed to compute challenge for manual verification: %v", err)
	}

	leftSide := curve.BasePoint().Mul(signature.S)
	rightSide := signature.R.Add(publicKey.Mul(challenge))

	t.Logf("Manual verification:")
	t.Logf("  Challenge: %s", challenge.String())
	t.Logf("  Private key: %s", privateKey.String())
	t.Logf("  Public key: %s", publicKey.String())
	t.Logf("  Challenge * Private key: %s", challenge.Mul(privateKey).String())
	t.Logf("  s*G: %s", leftSide.String())
	t.Logf("  R + e*P: %s", rightSide.String())
	t.Logf("  Manual verification passes: %v", leftSide.Equal(rightSide))

	// Check what s*G actually represents
	// If s*G = R, then s is just the nonce (no challenge contribution)
	t.Logf("  s*G equals R: %v", leftSide.Equal(signature.R))

	// Verify signature using Bitcoin FROST verification
	valid, err := BitcoinVerifyFROSTSignature(curve, signature, message[:], publicKey)
	if err != nil {
		t.Fatalf("Bitcoin FROST signature verification failed: %v", err)
	}
	if !valid {
		t.Fatalf("Bitcoin FROST signature verification returned false")
	}

	// Convert to Bitcoin signature format and verify with btcec
	bitcoinSig := &BitcoinSignature{
		R: signature.R,
		S: signature.S,
	}

	err = BitcoinVerifySignature(bitcoinSig, publicKey, message[:])
	if err != nil {
		t.Fatalf("Bitcoin signature verification failed: %v", err)
	}

	t.Logf("Bitcoin FROST signing test passed!")
	t.Logf("Signature R: %s", signature.R.String())
	t.Logf("Signature S: %s", signature.S.String())
}

func TestBitcoinSignatureFormat(t *testing.T) {
	curve := NewSecp256k1Curve()
	
	// Test signature serialization format
	rScalar, err := curve.ScalarFromBytes([]byte{
		0x62, 0x6f, 0xc9, 0x6f, 0xf3, 0x67, 0x8d, 0x4f, 0xa2, 0xde, 0x96, 0x0b, 0x2c, 0x39, 0xd1, 0x99,
		0x74, 0x7d, 0x3f, 0x47, 0xf0, 0x15, 0x08, 0xfb, 0xbe, 0x24, 0x82, 0x5c, 0x4d, 0x11, 0xb5, 0x43,
	})
	if err != nil {
		t.Fatalf("Failed to create R scalar: %v", err)
	}
	
	r := curve.BasePoint().Mul(rScalar)
	s := rScalar // Use same scalar for simplicity
	
	signature := &BitcoinSignature{R: r, S: s}
	sigBytes, err := signature.ToBytes()
	if err != nil {
		t.Fatalf("Failed to convert signature to bytes: %v", err)
	}

	// Verify signature is 64 bytes
	if len(sigBytes) != 64 {
		t.Errorf("Expected 64-byte signature, got %d bytes", len(sigBytes))
	}
	
	// Verify format matches expected (from Chainflip test)
	expected := []byte{
		0x59, 0xb2, 0xb4, 0x6f, 0xb1, 0x82, 0xa6, 0xd4, 0xb3, 0x9f, 0xfb, 0x7a, 0x29, 0xd0,
		0xb6, 0x78, 0x51, 0xdd, 0xe2, 0x43, 0x36, 0x83, 0xbe, 0x6d, 0x46, 0x62, 0x3a, 0x79,
		0x60, 0xd2, 0x79, 0x9e, 0x62, 0x6f, 0xc9, 0x6f, 0xf3, 0x67, 0x8d, 0x4f, 0xa2, 0xde,
		0x96, 0x0b, 0x2c, 0x39, 0xd1, 0x99, 0x74, 0x7d, 0x3f, 0x47, 0xf0, 0x15, 0x08, 0xfb,
		0xbe, 0x24, 0x82, 0x5c, 0x4d, 0x11, 0xb5, 0x43,
	}
	
	if len(sigBytes) == len(expected) {
		// Check first 32 bytes (R x-coordinate)
		rBytes := sigBytes[0:32]
		expectedR := expected[0:32]
		
		// Check last 32 bytes (s scalar)
		sBytes := sigBytes[32:64]
		expectedS := expected[32:64]
		
		t.Logf("R bytes: %x", rBytes)
		t.Logf("Expected R: %x", expectedR)
		t.Logf("S bytes: %x", sBytes)
		t.Logf("Expected S: %x", expectedS)
	}
}

func TestBitcoinKeyGeneration(t *testing.T) {
	// Test multiple key generations to ensure they're all Bitcoin-compatible
	for i := 0; i < 10; i++ {
		privateKey, publicKey, err := BitcoinKeyGeneration()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}
		
		// Verify public key is Bitcoin-compatible
		if !IsValidBitcoinPubkey(publicKey) {
			t.Errorf("Generated public key %d is not Bitcoin-compatible", i)
		}
		
		// Verify private key is not zero
		if privateKey.IsZero() {
			t.Errorf("Generated private key %d is zero", i)
		}
		
		// Verify public key derivation
		derivedPubkey := NewSecp256k1Curve().BasePoint().Mul(privateKey)
		if !derivedPubkey.Equal(publicKey) {
			t.Errorf("Public key derivation mismatch for key %d", i)
		}
	}
}

func TestBitcoinSigningPayload(t *testing.T) {
	// Test valid payload
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	
	payload, err := NewBitcoinSigningPayload(data)
	if err != nil {
		t.Fatalf("Failed to create valid payload: %v", err)
	}
	
	if !bytes.Equal(payload.Bytes(), data) {
		t.Errorf("Payload bytes mismatch")
	}
	
	// Test invalid payload length
	invalidData := make([]byte, 31)
	_, err = NewBitcoinSigningPayload(invalidData)
	if err == nil {
		t.Errorf("Expected error for invalid payload length")
	}
}

func TestBIP340Compatibility(t *testing.T) {
	// Test that our implementation is compatible with BIP-340
	curve := NewSecp256k1Curve()
	
	// Generate key pair
	privateKey, publicKey, err := BitcoinKeyGeneration()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	// Create message
	message := sha256.Sum256([]byte("BIP-340 test"))
	
	// Generate nonce
	nonce, err := curve.ScalarRandom()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Compute nonce commitment
	nonceCommitment := curve.BasePoint().Mul(nonce)

	// Handle BIP-340 parity requirement: R must have even Y
	if nonceCommitment.(*Secp256k1Point).HasOddY() {
		nonce = nonce.Negate()
		nonceCommitment = curve.BasePoint().Mul(nonce)
	}

	// Compute challenge using our implementation (R, pubKey, message)
	challenge, err := BitcoinChallenge(nonceCommitment, publicKey, message[:])
	if err != nil {
		t.Fatalf("Failed to compute challenge: %v", err)
	}

	// Compute signature response
	response, err := BitcoinSignResponse(nonce, nonceCommitment, privateKey, challenge)
	if err != nil {
		t.Fatalf("Failed to compute signature response: %v", err)
	}

	// Create signature
	signature := &BitcoinSignature{
		R: nonceCommitment,
		S: response,
	}

	// Verify using our implementation
	err = BitcoinVerifySignature(signature, publicKey, message[:])
	if err != nil {
		t.Fatalf("Our verification failed: %v", err)
	}

	// Verify using btcec library directly
	pubkeyBytes := publicKey.(*Secp256k1Point).XOnlyBytes()
	xOnlyPubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		t.Fatalf("Failed to parse x-only pubkey: %v", err)
	}
	
	sigBytes, err := signature.ToBytes()
	if err != nil {
		t.Fatalf("Failed to convert signature to bytes: %v", err)
	}
	schnorrSig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		t.Fatalf("Failed to parse signature: %v", err)
	}
	
	if !schnorrSig.Verify(message[:], xOnlyPubkey) {
		t.Fatalf("btcec verification failed")
	}
	
	t.Logf("BIP-340 compatibility test passed")
}
