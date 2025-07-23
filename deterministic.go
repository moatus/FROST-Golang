package frost

import (
    "crypto/sha256"
    "encoding/binary"
    "fmt"
    "io"

    "golang.org/x/crypto/hkdf"
)

// DeterministicKeyGen generates FROST key shares from existing validator keys
type DeterministicKeyGen struct {
    curve           Curve
    threshold       int
    participants    []ParticipantIndex
    foundationKey   Scalar  // RPW foundation key
    validatorKeys   map[ParticipantIndex]Scalar // Each validator's DLS key
}

// NewDeterministicKeyGen creates a new deterministic key generator with input validation
func NewDeterministicKeyGen(
    curve Curve,
    threshold int,
    participants []ParticipantIndex,
    foundationKey Scalar,
    validatorKeys map[ParticipantIndex]Scalar,
) (*DeterministicKeyGen, error) {
    // Validate inputs
    if curve == nil {
        return nil, fmt.Errorf("curve cannot be nil")
    }

    if threshold <= 0 {
        return nil, fmt.Errorf("threshold must be positive, got %d", threshold)
    }

    if len(participants) == 0 {
        return nil, fmt.Errorf("participants slice cannot be empty")
    }

    if threshold > len(participants) {
        return nil, fmt.Errorf("threshold %d exceeds participant count %d", threshold, len(participants))
    }

    if foundationKey == nil {
        return nil, fmt.Errorf("foundationKey cannot be nil")
    }

    if validatorKeys == nil {
        return nil, fmt.Errorf("validatorKeys cannot be nil")
    }

    // Validate that all participants have corresponding validator keys
    for _, participantID := range participants {
        if _, exists := validatorKeys[participantID]; !exists {
            return nil, fmt.Errorf("missing validator key for participant %d", participantID)
        }
        if validatorKeys[participantID] == nil {
            return nil, fmt.Errorf("validator key for participant %d cannot be nil", participantID)
        }
    }

    return &DeterministicKeyGen{
        curve:         curve,
        threshold:     threshold,
        participants:  participants,
        foundationKey: foundationKey,
        validatorKeys: validatorKeys,
    }, nil
}

// GenerateKeyShares generates FROST key shares deterministically
func (dkg *DeterministicKeyGen) GenerateKeyShares() (map[ParticipantIndex]*KeyShare, Point, error) {
    keyShares := make(map[ParticipantIndex]*KeyShare)
    
    // Step 1: Generate deterministic polynomial for each participant
    polynomials := make(map[ParticipantIndex]*Polynomial)
    commitments := make(map[ParticipantIndex][]Point)
    
    for _, participantID := range dkg.participants {
        validatorKey, exists := dkg.validatorKeys[participantID]
        if !exists {
            return nil, nil, fmt.Errorf("missing validator key for participant %d", participantID)
        }
        
        // Generate deterministic polynomial from validator key + foundation key
        polynomial, commitment, err := dkg.generateDeterministicPolynomial(participantID, validatorKey)
        if err != nil {
            return nil, nil, fmt.Errorf("failed to generate polynomial for participant %d: %w", participantID, err)
        }
        
        polynomials[participantID] = polynomial
        commitments[participantID] = commitment
    }
    
    // Step 2: Compute shares for each participant
    for _, receiverID := range dkg.participants {
        secretShare := dkg.curve.ScalarZero()

        // Convert receiverID to scalar once for efficiency
        receiverScalar, err := receiverID.ToScalar(dkg.curve)
        if err != nil {
            return nil, nil, fmt.Errorf("failed to convert participant ID: %w", err)
        }

        // Sum evaluations from all polynomials at receiver's ID
        for _, polynomial := range polynomials {
            evaluation := polynomial.Evaluate(receiverScalar)
            secretShare = secretShare.Add(evaluation)

            // Clean up evaluation scalar after use
            evaluation.Zeroize()
        }

        // Clean up receiverScalar after use
        defer receiverScalar.Zeroize()
        
        // Compute public key for this share
        publicKey := dkg.curve.BasePoint().Mul(secretShare)
        
        keyShares[receiverID] = &KeyShare{
            ParticipantID: receiverID,
            SecretShare:   secretShare,
            PublicKey:     publicKey,
            // GroupPublicKey will be set below
        }
    }
    
    // Step 3: Compute group public key (sum of all constant terms)
    groupPublicKey := dkg.curve.PointIdentity()
    for _, commitmentList := range commitments {
        // Add the constant term commitment (index 0)
        groupPublicKey = groupPublicKey.Add(commitmentList[0])
    }
    
    // Set group public key for all shares
    for _, keyShare := range keyShares {
        keyShare.GroupPublicKey = groupPublicKey
    }
    
    // Clean up polynomials
    for _, polynomial := range polynomials {
        polynomial.Zeroize()
    }
    
    return keyShares, groupPublicKey, nil
}

// generateDeterministicPolynomial creates a polynomial from validator key + foundation key
func (dkg *DeterministicKeyGen) generateDeterministicPolynomial(
    participantID ParticipantIndex,
    validatorKey Scalar,
) (*Polynomial, []Point, error) {
    
    // Create deterministic seed from validator key + foundation key + participant ID
    seed := dkg.createDeterministicSeed(participantID, validatorKey)
    defer func() {
        // Clear seed
        for i := range seed {
            seed[i] = 0
        }
    }()
    
    // Generate polynomial coefficients deterministically
    coefficients := make([]Scalar, dkg.threshold)
    commitments := make([]Point, dkg.threshold)
    
    for i := 0; i < dkg.threshold; i++ {
        // Generate coefficient from seed + index
        coeff, err := dkg.scalarFromSeed(seed, uint32(i))
        if err != nil {
            return nil, nil, fmt.Errorf("failed to generate coefficient %d: %w", i, err)
        }
        coefficients[i] = coeff

        // Compute commitment g^coeff
        commitments[i] = dkg.curve.BasePoint().Mul(coeff)
    }
    
    polynomial := &Polynomial{
        curve:        dkg.curve,
        coefficients: coefficients,
    }
    
    return polynomial, commitments, nil
}

// createDeterministicSeed creates a deterministic seed for polynomial generation
func (dkg *DeterministicKeyGen) createDeterministicSeed(
    participantID ParticipantIndex,
    validatorKey Scalar,
) []byte {
    hasher := sha256.New()
    
    // Domain separator
    hasher.Write([]byte("CANOPY_FROST_DETERMINISTIC_v1"))
    
    // Foundation key (ties to specific RPW)
    hasher.Write(dkg.foundationKey.Bytes())
    
    // Validator's DLS key (ties to specific validator)
    hasher.Write(validatorKey.Bytes())
    
    // Participant ID
    participantBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
    hasher.Write(participantBytes)
    
    // Threshold (ensures different thresholds give different keys)
    thresholdBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(thresholdBytes, uint32(dkg.threshold))
    hasher.Write(thresholdBytes)
    
    return hasher.Sum(nil)
}

// scalarFromSeed generates a scalar deterministically from seed + index using HKDF
func (dkg *DeterministicKeyGen) scalarFromSeed(seed []byte, index uint32) (Scalar, error) {
    // Create HKDF salt from domain separator
    salt := []byte("CANOPY_DETERMINISTIC_SCALAR_v1")

    // Create HKDF info from index
    indexBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(indexBytes, index)
    info := append([]byte("index:"), indexBytes...)

    // Use HKDF to derive 64 bytes for uniform scalar generation
    hkdfReader := hkdf.New(sha256.New, seed, salt, info)
    scalarBytes := make([]byte, 64)
    if _, err := io.ReadFull(hkdfReader, scalarBytes); err != nil {
        return nil, fmt.Errorf("failed to derive bytes from HKDF: %w", err)
    }

    scalar, err := dkg.curve.ScalarFromUniformBytes(scalarBytes)

    // Clear scalar bytes from memory
    for i := range scalarBytes {
        scalarBytes[i] = 0
    }

    if err != nil {
        return nil, fmt.Errorf("failed to generate scalar from HKDF output: %w", err)
    }

    return scalar, nil
}

// NewUserControlledKeyGen creates FROST keys controlled by a user's wallet instead of foundation
func NewUserControlledKeyGen(
    curve Curve,
    threshold int,
    participants []ParticipantIndex,
    userWalletAddress []byte,    // User's wallet address
    userPrivateKey Scalar,       // User's private key (for derivation)
    derivationPath []uint32,     // HD path for this FROST wallet
    validatorKeys map[ParticipantIndex]Scalar,
) (*DeterministicKeyGen, error) {
    // Derive user-controlled foundation key
    userFoundationKey, err := deriveUserFoundationKey(curve, userWalletAddress, userPrivateKey, derivationPath)
    if err != nil {
        return nil, fmt.Errorf("failed to derive user foundation key: %w", err)
    }
    // Note: Don't zeroize here - NewDeterministicKeyGen will handle it

    // Create deterministic key generator with user-controlled seed
    return NewDeterministicKeyGen(curve, threshold, participants, userFoundationKey, validatorKeys)
}

// deriveUserFoundationKey derives a foundation key from user's wallet
func deriveUserFoundationKey(curve Curve, userAddress []byte, userPrivateKey Scalar, derivationPath []uint32) (Scalar, error) {
    hasher := sha256.New()

    // Domain separation for user-controlled wallets
    hasher.Write([]byte("FROST_USER_CONTROLLED"))
    hasher.Write([]byte(curve.Name()))

    // User's wallet address (public identifier)
    hasher.Write(userAddress)

    // User's private key (proves ownership)
    hasher.Write(userPrivateKey.Bytes())

    // Derivation path for this specific FROST wallet
    for _, pathElement := range derivationPath {
        pathBytes := make([]byte, 4)
        binary.BigEndian.PutUint32(pathBytes, pathElement)
        hasher.Write(pathBytes)
    }

    derivedBytes := hasher.Sum(nil)
    return curve.ScalarFromUniformBytes(derivedBytes)
}

// NewUserControlledKeyGenFromSeed creates FROST keys from any arbitrary seed
func NewUserControlledKeyGenFromSeed(
    curve Curve,
    threshold int,
    participants []ParticipantIndex,
    userSeed []byte,             // Any seed material (transaction hash, user input, etc.)
    derivationContext string,    // Context string for domain separation
    validatorKeys map[ParticipantIndex]Scalar,
) (*DeterministicKeyGen, error) {
    // Derive foundation key from arbitrary seed
    foundationKey, err := deriveFromArbitrarySeed(curve, userSeed, derivationContext)
    if err != nil {
        return nil, fmt.Errorf("failed to derive foundation key from seed: %w", err)
    }
    // Note: Don't zeroize here - NewDeterministicKeyGen will handle it

    // Create deterministic key generator
    return NewDeterministicKeyGen(curve, threshold, participants, foundationKey, validatorKeys)
}

// deriveFromArbitrarySeed derives a foundation key from any seed material
func deriveFromArbitrarySeed(curve Curve, seed []byte, context string) (Scalar, error) {
    hasher := sha256.New()

    // Domain separation
    hasher.Write([]byte("FROST_ARBITRARY_SEED"))
    hasher.Write([]byte(curve.Name()))
    hasher.Write([]byte(context))

    // User-provided seed
    hasher.Write(seed)

    derivedBytes := hasher.Sum(nil)
    return curve.ScalarFromUniformBytes(derivedBytes)
}

// VerifyDeterministicShares verifies that shares were generated correctly
func (dkg *DeterministicKeyGen) VerifyDeterministicShares(
    keyShares map[ParticipantIndex]*KeyShare,
    groupPublicKey Point,
) error {
    // Regenerate and compare
    expectedShares, expectedGroupKey, err := dkg.GenerateKeyShares()
    if err != nil {
        return fmt.Errorf("failed to regenerate shares for verification: %w", err)
    }
    
    // Verify group public key matches
    if !groupPublicKey.Equal(expectedGroupKey) {
        return fmt.Errorf("group public key mismatch")
    }
    
    // Verify each share matches
    for participantID, keyShare := range keyShares {
        expectedShare, exists := expectedShares[participantID]
        if !exists {
            return fmt.Errorf("missing expected share for participant %d", participantID)
        }
        
        if !keyShare.SecretShare.Equal(expectedShare.SecretShare) {
            return fmt.Errorf("secret share mismatch for participant %d", participantID)
        }
        
        if !keyShare.PublicKey.Equal(expectedShare.PublicKey) {
            return fmt.Errorf("public key mismatch for participant %d", participantID)
        }
    }
    
    // Clean up expected shares
    for _, share := range expectedShares {
        share.SecretShare.Zeroize()
    }
    
    return nil
}