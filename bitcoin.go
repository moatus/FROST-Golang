package frost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Bitcoin BIP-340 constants
var (
	// SHA256("BIP0340/challenge") - pre-computed for efficiency
	BIP340ChallengeTag = [32]byte{
		0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32, 0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3, 0x82,
		0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f, 0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48, 0xd3, 0x7c,
	}

	// Package-level curve instance for performance optimization
	secp256k1Curve = NewSecp256k1Curve()
)

// BitcoinSignature represents a BIP-340 Schnorr signature
type BitcoinSignature struct {
	R Point  // Nonce commitment point
	S Scalar // Signature scalar
}

// ToBytes returns the 64-byte BIP-340 signature format
func (sig *BitcoinSignature) ToBytes() ([]byte, error) {
	result := make([]byte, 64)

	// First 32 bytes: x-coordinate of R
	rPoint, ok := sig.R.(*Secp256k1Point)
	if !ok {
		return nil, fmt.Errorf("signature R point is not a Secp256k1Point")
	}
	rBytes := rPoint.XOnlyBytes()
	copy(result[0:32], rBytes)

	// Next 32 bytes: scalar s
	copy(result[32:64], sig.S.Bytes())

	return result, nil
}

// BitcoinChallenge computes BIP-340 challenge using tagged hashing
func BitcoinChallenge(R Point, pubKey Point, message []byte) (Scalar, error) {
	// NO LENGTH CHECK - message can be arbitrary length per BIP-340 spec

	// BIP-340 tagged hash: SHA256(tag || tag || data)
	hasher := sha256.New()
	hasher.Write(BIP340ChallengeTag[:])
	hasher.Write(BIP340ChallengeTag[:])

	// Add nonce x-coordinate (32 bytes)
	rPoint, ok := R.(*Secp256k1Point)
	if !ok {
		return nil, fmt.Errorf("R point is not a Secp256k1Point")
	}
	rx := rPoint.XOnlyBytes()
	hasher.Write(rx)

	// Add pubkey x-coordinate (32 bytes)
	pubKeyPoint, ok := pubKey.(*Secp256k1Point)
	if !ok {
		return nil, fmt.Errorf("public key point is not a Secp256k1Point")
	}
	px := pubKeyPoint.XOnlyBytes()
	hasher.Write(px)

	// Add message (arbitrary length)
	hasher.Write(message)

	challengeBytes := hasher.Sum(nil)

	// Convert to scalar (ScalarFromBytes now always reduces)
	return secp256k1Curve.ScalarFromBytes(challengeBytes)
}

// BitcoinSignResponse computes signature response with BIP-340 Y-parity handling
// Note: This assumes the nonceCommitment already has even Y coordinate (BIP-340 requirement)
func BitcoinSignResponse(nonce Scalar, nonceCommitment Point, privateKey Scalar, challenge Scalar) (Scalar, error) {
	// BIP-340: s = k + e*d (mod n)
	// The nonce k should be the one that produces the even-Y commitment point
	// If the original nonce produced odd Y, it should have been negated before calling this function

	// Verify that R has even Y (should be ensured by caller)
	noncePoint, ok := nonceCommitment.(*Secp256k1Point)
	if !ok {
		return nil, fmt.Errorf("nonce commitment is not a Secp256k1Point")
	}

	if noncePoint.HasOddY() {
		// This should not happen if the caller properly prepared the nonce
		// But we'll handle it by negating the nonce
		nonce = nonce.Negate()
	}

	// Compute s = k + e*d (mod n)
	return nonce.Add(challenge.Mul(privateKey)), nil
}

// BitcoinVerifyResponse verifies a party's signature response
func BitcoinVerifyResponse(publicKey Point, lambdaI Scalar, commitment Point, groupCommitment Point, challenge Scalar, response Scalar) (bool, error) {
	// Compute expected point: s*G
	leftSide := secp256k1Curve.BasePoint().Mul(response)

	// Compute right side following Chainflip's logic:
	// if group_commitment.is_even_y(): s*G = Y_i * e * λ_i + D_i
	// if group_commitment.is_odd_y(): s*G = Y_i * e * λ_i - D_i
	groupCommitmentPoint, ok := groupCommitment.(*Secp256k1Point)
	if !ok {
		return false, fmt.Errorf("group commitment is not a Secp256k1Point")
	}

	var rightSide Point
	if groupCommitmentPoint.HasOddY() {
		// Odd Y: s*G = Y_i * e * λ_i - D_i
		rightSide = publicKey.Mul(challenge.Mul(lambdaI)).Sub(commitment)
	} else {
		// Even Y: s*G = Y_i * e * λ_i + D_i
		rightSide = publicKey.Mul(challenge.Mul(lambdaI)).Add(commitment)
	}

	return leftSide.Equal(rightSide), nil
}

// BitcoinVerifyFROSTSignature verifies a FROST signature using Bitcoin BIP-340 challenge
func BitcoinVerifyFROSTSignature(curve Curve, signature *Signature, message []byte, groupPubKey Point) (bool, error) {
	// Recompute challenge using Bitcoin challenge computation
	challenge, err := BitcoinChallenge(signature.R, groupPubKey, message)
	if err != nil {
		return false, fmt.Errorf("failed to compute Bitcoin challenge for verification: %w", err)
	}

	// Verify: g^s = R + c * GroupPubKey
	leftSide := curve.BasePoint().Mul(signature.S)
	rightSide := signature.R.Add(groupPubKey.Mul(challenge))

	return leftSide.Equal(rightSide), nil
}

// BitcoinVerifySignature verifies a complete BIP-340 signature
func BitcoinVerifySignature(signature *BitcoinSignature, publicKey Point, message []byte) error {
	// For BIP-340, we need to ensure R has even Y coordinate
	// If our R point has odd Y, the signature is invalid
	rPoint, ok := signature.R.(*Secp256k1Point)
	if !ok {
		return fmt.Errorf("signature R point is not a Secp256k1Point")
	}
	if rPoint.HasOddY() {
		return fmt.Errorf("signature R point has odd Y coordinate")
	}

	// Convert to x-only public key
	pubKeyPoint, ok := publicKey.(*Secp256k1Point)
	if !ok {
		return fmt.Errorf("public key is not a Secp256k1Point")
	}
	pubkeyBytes := pubKeyPoint.XOnlyBytes()
	xOnlyPubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Convert signature to schnorr format
	sigBytes, err := signature.ToBytes()
	if err != nil {
		return fmt.Errorf("failed to convert signature to bytes: %w", err)
	}
	schnorrSig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// Verify using btcec
	if !schnorrSig.Verify(message, xOnlyPubkey) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// IsValidBitcoinPubkey checks if a point is valid for Bitcoin (even Y coordinate)
func IsValidBitcoinPubkey(point Point) bool {
	secp256k1Point, ok := point.(*Secp256k1Point)
	if !ok {
		return false
	}
	return !secp256k1Point.HasOddY()
}

// Extension methods for Secp256k1Point to support Bitcoin operations
func (p *Secp256k1Point) XOnlyBytes() []byte {
	if p.inner == nil {
		return make([]byte, 32) // Zero for identity (though rare in signing)
	}

	// Use btcec v2 API to get x-only bytes
	return schnorr.SerializePubKey(p.inner)
}

func (p *Secp256k1Point) HasOddY() bool {
	if p.inner == nil {
		return false
	}

	// Check if Y coordinate is odd using btcec v2 API
	compressed := p.inner.SerializeCompressed()
	// In compressed format, 0x02 = even Y, 0x03 = odd Y
	return compressed[0] == 0x03
}

// BitcoinKeyGeneration generates a Bitcoin-compatible key pair
func BitcoinKeyGeneration() (Scalar, Point, error) {
	for {
		// Generate random private key
		privateKey, err := secp256k1Curve.ScalarRandom()
		if err != nil {
			return nil, nil, err
		}

		// Compute public key
		publicKey := secp256k1Curve.BasePoint().Mul(privateKey)
		
		// Check if public key is Bitcoin-compatible (even Y)
		if IsValidBitcoinPubkey(publicKey) {
			return privateKey, publicKey, nil
		}
		
		// If odd Y, negate the private key to get even Y
		negatedKey := privateKey.Negate()
		negatedPubkey := secp256k1Curve.BasePoint().Mul(negatedKey)
		
		if IsValidBitcoinPubkey(negatedPubkey) {
			return negatedKey, negatedPubkey, nil
		}
		
		// This should never happen, but continue loop as safety
	}
}

// BitcoinSigningPayload represents a 32-byte Bitcoin signing payload
type BitcoinSigningPayload struct {
	Hash [32]byte
}

func NewBitcoinSigningPayload(data []byte) (*BitcoinSigningPayload, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("bitcoin signing payload must be 32 bytes, got %d", len(data))
	}
	
	var hash [32]byte
	copy(hash[:], data)
	
	return &BitcoinSigningPayload{Hash: hash}, nil
}

func (p *BitcoinSigningPayload) Bytes() []byte {
	return p.Hash[:]
}

func (p *BitcoinSigningPayload) String() string {
	return hex.EncodeToString(p.Hash[:])
}
