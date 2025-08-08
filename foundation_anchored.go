package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"github.com/canopy-network/canopy/lib/crypto"
)

// FoundationAnchoredKeyGen generates FROST shares that collectively represent a foundation key
// This enables stable addresses (derived from foundation key) while allowing validator set changes
type FoundationAnchoredKeyGen struct {
	curve            Curve
	threshold        int
	participants     []ParticipantIndex
	foundationKey    Scalar  // The master secret that determines the stable address
	validatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey
	hashAlgorithm    HashAlgorithm
}

// NewFoundationAnchoredKeyGen creates a key generator that maintains address stability
func NewFoundationAnchoredKeyGen(
	curve Curve,
	threshold int,
	participants []ParticipantIndex,
	foundationKey Scalar,
	validatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey,
) *FoundationAnchoredKeyGen {
	return &FoundationAnchoredKeyGen{
		curve:            curve,
		threshold:        threshold,
		participants:     participants,
		foundationKey:    foundationKey,
		validatorBLSKeys: validatorBLSKeys,
		hashAlgorithm:    SHA256_HKDF,
	}
}

// DeriveStableAddress derives the stable wallet address from foundation key only
// This address never changes regardless of validator set composition
func (fakg *FoundationAnchoredKeyGen) DeriveStableAddress() Point {
	// Address is simply G * foundationKey
	// This ensures the same foundation key always produces the same address
	return fakg.curve.BasePoint().Mul(fakg.foundationKey)
}

// GenerateKeyShares creates FROST shares that collectively represent the foundation key
// The shares change when validator set changes, but they always represent the same foundation secret
func (fakg *FoundationAnchoredKeyGen) GenerateKeyShares() (map[ParticipantIndex]*KeyShare, Point, error) {
	keyShares := make(map[ParticipantIndex]*KeyShare)
	
	// Step 1: The group public key is ALWAYS the stable address (foundation key)
	stableAddress := fakg.DeriveStableAddress()
	
	// Step 2: Generate validator-specific entropy for share distribution
	validatorEntropies := make(map[ParticipantIndex]Scalar)
	for _, participantID := range fakg.participants {
		entropy, err := fakg.deriveValidatorEntropy(participantID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive validator entropy for participant %d: %w", participantID, err)
		}
		validatorEntropies[participantID] = entropy
	}
	
	// Step 3: Create a polynomial where the constant term is the foundation key
	// and coefficients are derived from validator entropies
	polynomial, err := fakg.createFoundationPolynomial(validatorEntropies)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create foundation polynomial: %w", err)
	}
	defer polynomial.Zeroize()
	
	// Step 4: Evaluate polynomial at each participant's ID to get their share
	for _, participantID := range fakg.participants {
		participantScalar, err := participantID.ToScalar(fakg.curve)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert participant ID %d to scalar: %w", participantID, err)
		}
		defer participantScalar.Zeroize()
		
		// Evaluate polynomial at this participant's ID
		secretShare := polynomial.Evaluate(participantScalar)
		
		// Compute public key for this share
		publicKey := fakg.curve.BasePoint().Mul(secretShare)
		
		keyShares[participantID] = &KeyShare{
			ParticipantID:  participantID,
			SecretShare:    secretShare,
			PublicKey:      publicKey,
			GroupPublicKey: stableAddress, // Always the same stable address
		}
	}
	
	// Step 5: Generate BLS binding proofs
	proofs, err := fakg.generateBLSBindingProofs(validatorEntropies)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate BLS binding proofs: %w", err)
	}
	
	// Attach proofs to key shares
	for participantID, proof := range proofs {
		if keyShare, exists := keyShares[participantID]; exists {
			keyShare.BLSBindingProof = proof
		}
	}
	
	return keyShares, stableAddress, nil
}

// deriveValidatorEntropy creates validator-specific entropy for polynomial generation
// This changes when validator set changes, but foundation key remains constant
func (fakg *FoundationAnchoredKeyGen) deriveValidatorEntropy(participantID ParticipantIndex) (Scalar, error) {
	blsKey, exists := fakg.validatorBLSKeys[participantID]
	if !exists {
		return nil, fmt.Errorf("no BLS key found for participant %d", participantID)
	}
	
	// Create HKDF for validator entropy derivation
	salt := []byte("FOUNDATION_ANCHORED_ENTROPY_v1:" + fakg.curve.Name())
	
	participantBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
	info := append([]byte("validator_entropy:"), participantBytes...)
	
	// Input: BLS key only (NOT foundation key - that's kept separate)
	ikm := blsKey.Bytes()
	
	// Derive entropy using HKDF
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	entropyBytes := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, entropyBytes); err != nil {
		return nil, fmt.Errorf("HKDF failed for validator entropy: %w", err)
	}
	
	// Convert to scalar
	entropy, err := fakg.curve.ScalarFromUniformBytes(entropyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create scalar from entropy bytes: %w", err)
	}
	
	// Clear entropy bytes
	for i := range entropyBytes {
		entropyBytes[i] = 0
	}
	
	return entropy, nil
}

// createFoundationPolynomial creates a polynomial with foundation key as constant term
func (fakg *FoundationAnchoredKeyGen) createFoundationPolynomial(validatorEntropies map[ParticipantIndex]Scalar) (*Polynomial, error) {
	coefficients := make([]Scalar, fakg.threshold)
	
	// Constant term is the foundation key (this ensures stable address)
	foundationKeyCopy, err := fakg.curve.ScalarFromBytes(fakg.foundationKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to copy foundation key: %w", err)
	}
	coefficients[0] = foundationKeyCopy
	
	// Higher-order coefficients derived from validator entropies
	for i := 1; i < fakg.threshold; i++ {
		coeff, err := fakg.derivePolynomialCoefficient(i, validatorEntropies)
		if err != nil {
			return nil, fmt.Errorf("failed to derive coefficient %d: %w", i, err)
		}
		coefficients[i] = coeff
	}
	
	return &Polynomial{
		curve:        fakg.curve,
		coefficients: coefficients,
	}, nil
}

// derivePolynomialCoefficient derives higher-order polynomial coefficients from validator entropies
func (fakg *FoundationAnchoredKeyGen) derivePolynomialCoefficient(coeffIndex int, validatorEntropies map[ParticipantIndex]Scalar) (Scalar, error) {
	hasher := sha256.New()
	
	// Domain separator
	hasher.Write([]byte("FOUNDATION_ANCHORED_COEFF_v1"))
	hasher.Write([]byte(fakg.curve.Name()))
	
	// Coefficient index
	coeffBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(coeffBytes, uint32(coeffIndex))
	hasher.Write(coeffBytes)
	
	// Mix in all validator entropies (order-independent)
	for _, participantID := range fakg.participants {
		if entropy, exists := validatorEntropies[participantID]; exists {
			participantBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
			hasher.Write(participantBytes)
			hasher.Write(entropy.Bytes())
		}
	}
	
	derivedBytes := hasher.Sum(nil)
	return fakg.curve.ScalarFromUniformBytes(derivedBytes)
}

// generateBLSBindingProofs creates zero-knowledge proofs binding FROST shares to BLS keys
func (fakg *FoundationAnchoredKeyGen) generateBLSBindingProofs(validatorEntropies map[ParticipantIndex]Scalar) (map[ParticipantIndex]*BLSBindingProof, error) {
	proofs := make(map[ParticipantIndex]*BLSBindingProof)
	
	for _, participantID := range fakg.participants {
		entropy, exists := validatorEntropies[participantID]
		if !exists {
			continue
		}
		
		blsKey, exists := fakg.validatorBLSKeys[participantID]
		if !exists {
			continue
		}
		
		// Generate proof that this entropy is bound to this BLS key
		proof, err := fakg.generateBLSBindingProof(participantID, entropy, blsKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate BLS binding proof for participant %d: %w", participantID, err)
		}
		
		proofs[participantID] = proof
	}
	
	return proofs, nil
}

// generateBLSBindingProof creates a single BLS binding proof
func (fakg *FoundationAnchoredKeyGen) generateBLSBindingProof(participantID ParticipantIndex, entropy Scalar, blsKey *crypto.BLS12381PrivateKey) (*BLSBindingProof, error) {
	// Generate proof commitment
	nonce, err := fakg.curve.ScalarRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof nonce: %w", err)
	}
	defer nonce.Zeroize()
	
	proofCommitment := fakg.curve.BasePoint().Mul(nonce)
	entropyCommitment := fakg.curve.BasePoint().Mul(entropy)
	
	// Compute challenge
	challenge, err := fakg.computeProofChallenge(participantID, blsKey.PublicKey().Bytes(), entropyCommitment, proofCommitment)
	if err != nil {
		return nil, fmt.Errorf("failed to compute proof challenge: %w", err)
	}
	defer challenge.Zeroize()
	
	// Compute response: r = nonce + challenge * entropy
	challengeTimesEntropy := challenge.Mul(entropy)
	response := nonce.Add(challengeTimesEntropy)

	// Clean up intermediate values
	challengeTimesEntropy.Zeroize()
	
	// Create copies of challenge and response to avoid zeroization issues
	challengeCopy, err := fakg.curve.ScalarFromBytes(challenge.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to copy challenge: %w", err)
	}

	responseCopy, err := fakg.curve.ScalarFromBytes(response.Bytes())
	if err != nil {
		challengeCopy.Zeroize()
		return nil, fmt.Errorf("failed to copy response: %w", err)
	}

	return &BLSBindingProof{
		ParticipantID:   participantID,
		BLSPublicKey:    blsKey.PublicKey().Bytes(),
		Commitment:      entropyCommitment,
		Challenge:       challengeCopy,
		Response:        responseCopy,
	}, nil
}

// computeProofChallenge computes Fiat-Shamir challenge for BLS binding proof
func (fakg *FoundationAnchoredKeyGen) computeProofChallenge(participantID ParticipantIndex, blsPublicKey []byte, commitment Point, proofCommitment Point) (Scalar, error) {
	salt := []byte("FOUNDATION_ANCHORED_CHALLENGE_v1")
	
	participantBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
	info := append([]byte("challenge:"), participantBytes...)
	
	// Create challenge input
	ikm := append([]byte{}, blsPublicKey...)
	if commitment != nil {
		ikm = append(ikm, commitment.Bytes()...)
	}
	if proofCommitment != nil {
		ikm = append(ikm, proofCommitment.Bytes()...)
	}
	
	// Use HKDF for challenge derivation
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	challengeBytes := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, challengeBytes); err != nil {
		return nil, fmt.Errorf("HKDF failed for challenge computation: %w", err)
	}
	
	challenge, err := fakg.curve.ScalarFromUniformBytes(challengeBytes)
	
	// Clear challenge bytes
	for i := range challengeBytes {
		challengeBytes[i] = 0
	}
	
	return challenge, err
}
