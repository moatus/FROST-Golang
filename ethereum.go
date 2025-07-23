package frost

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// Ethereum constants
var (
	// Half of secp256k1 curve order - required by Ethereum Key Manager contract
	secp256k1HalfOrder *big.Int
)

func init() {
	// secp256k1 curve order
	curveOrder, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	// Correct half order calculation: floor(order / 2) without adding 1
	secp256k1HalfOrder = new(big.Int).Div(curveOrder, big.NewInt(2))
}

// EthereumSignature represents an Ethereum-compatible signature
type EthereumSignature struct {
	R Point  // Nonce commitment point
	S Scalar // Signature scalar
	V uint8  // Recovery ID (for Ethereum transactions)
}

// ToRSV returns the signature in Ethereum (r, s, v) format
func (sig *EthereumSignature) ToRSV() (r, s *big.Int, v uint8) {
	// Validate inputs to prevent panics
	if sig.R == nil || sig.S == nil {
		return big.NewInt(0), big.NewInt(0), 0
	}

	// Safe type assertion with comma-ok idiom
	secp256k1Point, ok := sig.R.(*Secp256k1Point)
	if !ok {
		return big.NewInt(0), big.NewInt(0), 0
	}

	// Extract r from the x-coordinate of R point
	rBytes := secp256k1Point.inner.SerializeCompressed()[1:33] // Skip prefix byte
	r = new(big.Int).SetBytes(rBytes)

	// Extract s from scalar
	s = new(big.Int).SetBytes(sig.S.Bytes())

	// Return v (recovery ID)
	v = sig.V

	return r, s, v
}

// ToBytes returns the 65-byte Ethereum signature format (r || s || v)
func (sig *EthereumSignature) ToBytes() []byte {
	result := make([]byte, 65)
	
	r, s, v := sig.ToRSV()
	
	// Pad r and s to exactly 32 bytes each
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	
	// Copy R (right-aligned in first 32 bytes)
	copy(result[32-len(rBytes):32], rBytes)
	// Copy S (right-aligned in next 32 bytes)  
	copy(result[64-len(sBytes):64], sBytes)
	// Copy V (last byte)
	result[64] = v
	
	return result
}

// EthereumChallenge computes the Ethereum EVM-optimized challenge using Keccak256
// Following Chainflip's format: keccak256(pubkey_x || parity || msg_hash || nonce_address)
func EthereumChallenge(R Point, pubKey Point, message []byte) (Scalar, error) {
	if len(message) != 32 {
		return nil, fmt.Errorf("ethereum message must be 32 bytes, got %d", len(message))
	}

	// Get public key x-coordinate (32 bytes) with safe type assertion
	secp256k1PubKey, ok := pubKey.(*Secp256k1Point)
	if !ok {
		return nil, fmt.Errorf("public key must be a Secp256k1Point")
	}
	pubKeyBytes := secp256k1PubKey.inner.SerializeCompressed()
	pubKeyX := pubKeyBytes[1:33] // Skip prefix byte, take x-coordinate
	
	// Get public key Y parity (1 byte: 0 for even, 1 for odd)
	var parity byte
	if pubKeyBytes[0] == 0x03 { // Odd Y
		parity = 1
	} else { // Even Y (0x02)
		parity = 0
	}
	
	// Convert nonce commitment point to Ethereum address (20 bytes)
	nonceAddress, err := PointToEthereumAddress(R)
	if err != nil {
		return nil, fmt.Errorf("failed to convert nonce to ethereum address: %w", err)
	}
	
	// Compute challenge: keccak256(pubkey_x || parity || msg_hash || nonce_address)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(pubKeyX)           // 32 bytes
	hasher.Write([]byte{parity})    // 1 byte
	hasher.Write(message)           // 32 bytes
	hasher.Write(nonceAddress)      // 20 bytes
	
	challengeBytes := hasher.Sum(nil) // 32 bytes
	
	// Convert to scalar
	curve := NewSecp256k1Curve()
	return curve.ScalarFromBytes(challengeBytes)
}

// PointToEthereumAddress converts a secp256k1 point to an Ethereum address
func PointToEthereumAddress(point Point) ([]byte, error) {
	secp256k1Point, ok := point.(*Secp256k1Point)
	if !ok {
		return nil, fmt.Errorf("point must be secp256k1 point")
	}
	
	if secp256k1Point.inner == nil {
		return nil, fmt.Errorf("invalid point")
	}
	
	// Get uncompressed public key (65 bytes: 0x04 || x || y)
	uncompressed := secp256k1Point.inner.SerializeUncompressed()
	if len(uncompressed) != 65 {
		return nil, fmt.Errorf("invalid uncompressed point length")
	}
	
	// Ethereum address = last 20 bytes of keccak256(x || y)
	// Skip the 0x04 prefix byte
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(uncompressed[1:]) // x || y (64 bytes)
	hash := hasher.Sum(nil)
	
	// Return last 20 bytes as Ethereum address
	address := make([]byte, 20)
	copy(address, hash[12:32])
	
	return address, nil
}

// IsValidEthereumPubkey checks if a public key is compatible with Ethereum Key Manager contract
// The x-coordinate must be less than half the secp256k1 curve order
func IsValidEthereumPubkey(point Point) bool {
	secp256k1Point, ok := point.(*Secp256k1Point)
	if !ok {
		return false
	}
	
	if secp256k1Point.inner == nil {
		return false
	}
	
	// Get x-coordinate
	compressed := secp256k1Point.inner.SerializeCompressed()
	x := new(big.Int).SetBytes(compressed[1:33]) // Skip prefix byte
	
	// Check if x < half_order
	return x.Cmp(secp256k1HalfOrder) < 0
}

// EthereumSignResponse computes signature response for Ethereum
func EthereumSignResponse(nonce Scalar, nonceCommitment Point, privateKey Scalar, challenge Scalar) Scalar {
	// Ethereum uses standard Schnorr response: s = k - e*d (mod n)
	// This matches Chainflip's build_response: nonce - challenge * private_key
	return nonce.Sub(challenge.Mul(privateKey))
}

// EthereumVerifyResponse verifies a party's signature response for Ethereum
func EthereumVerifyResponse(publicKey Point, lambdaI Scalar, commitment Point, groupCommitment Point, challenge Scalar, response Scalar) bool {
	// Compute expected point: s*G
	curve := NewSecp256k1Curve()
	leftSide := curve.BasePoint().Mul(response)
	
	// Compute right side: Y_i * e * λ_i + D_i
	// (Ethereum doesn't have the Y-parity adjustment like Bitcoin)
	rightSide := publicKey.Mul(challenge.Mul(lambdaI)).Add(commitment)
	
	return leftSide.Equal(rightSide)
}

// EthereumVerifySignature verifies a complete Ethereum signature
func EthereumVerifySignature(signature *EthereumSignature, publicKey Point, message []byte) error {
	// Recompute challenge
	challenge, err := EthereumChallenge(signature.R, publicKey, message)
	if err != nil {
		return fmt.Errorf("failed to compute challenge: %w", err)
	}

	// Verify: g^s = R - c * PublicKey (since s = k - e*d)
	// Rearranging: g^s + c*P = R
	curve := NewSecp256k1Curve()
	leftSide := curve.BasePoint().Mul(signature.S)
	rightSide := signature.R.Sub(publicKey.Mul(challenge))

	if !leftSide.Equal(rightSide) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// EthereumKeyGeneration generates an Ethereum-compatible key pair
func EthereumKeyGeneration() (Scalar, Point, error) {
	curve := NewSecp256k1Curve()

	// Add maximum attempts limit to prevent infinite looping
	const maxAttempts = 1000

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate random private key
		privateKey, err := curve.ScalarRandom()
		if err != nil {
			return nil, nil, err
		}

		// Compute public key
		publicKey := curve.BasePoint().Mul(privateKey)

		// Check if public key is Ethereum-compatible
		if IsValidEthereumPubkey(publicKey) {
			return privateKey, publicKey, nil
		}

		// If not compatible, try negating the private key
		negatedKey := privateKey.Negate()
		negatedPubkey := curve.BasePoint().Mul(negatedKey)

		if IsValidEthereumPubkey(negatedPubkey) {
			return negatedKey, negatedPubkey, nil
		}

		// Continue loop to try again (should be rare)
	}

	return nil, nil, fmt.Errorf("failed to generate Ethereum-compatible key pair after %d attempts", maxAttempts)
}

// EthereumSigningPayload represents a 32-byte Ethereum signing payload
type EthereumSigningPayload struct {
	Hash [32]byte
}

func NewEthereumSigningPayload(data []byte) (*EthereumSigningPayload, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("ethereum signing payload must be 32 bytes, got %d", len(data))
	}
	
	var hash [32]byte
	copy(hash[:], data)
	
	return &EthereumSigningPayload{Hash: hash}, nil
}

func (p *EthereumSigningPayload) Bytes() []byte {
	return p.Hash[:]
}

func (p *EthereumSigningPayload) String() string {
	return hex.EncodeToString(p.Hash[:])
}
