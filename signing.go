package frost

import (
    "crypto/sha256"
    "encoding/binary"
    "fmt"
    "io"

    "github.com/canopy-network/canopy/lib/crypto"
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/hkdf"
    "golang.org/x/crypto/sha3"
)

// ChallengeType defines the type of challenge computation to use
type ChallengeType int

const (
    StandardFROST ChallengeType = iota
    BitcoinBIP340
    EthereumEVM
    SolanaEd25519
)

// SigningSession manages a FROST signing session
type SigningSession struct {
    curve         Curve
    keyShare      *KeyShare
    message       []byte
    signers       []ParticipantIndex
    threshold     int
    challengeType ChallengeType  // Type of challenge computation to use

    // Round 1 state
    nonce         Scalar
    commitment    Point
    commitments   map[ParticipantIndex]*SigningCommitment

    // Round 2 state
    challenge     Scalar
    groupCommitment Point  // Store the adjusted group commitment
    responses     map[ParticipantIndex]*SigningResponse
}

// NewSigningSession creates a new signing session with standard FROST challenge
func NewSigningSession(
    curve Curve,
    keyShare *KeyShare,
    message []byte,
    signers []ParticipantIndex,
    threshold int,
) (*SigningSession, error) {
    return newSigningSessionWithChallengeType(curve, keyShare, message, signers, threshold, StandardFROST)
}

// NewBitcoinSigningSession creates a new signing session with Bitcoin BIP-340 challenge
func NewBitcoinSigningSession(
    curve Curve,
    keyShare *KeyShare,
    message []byte,
    signers []ParticipantIndex,
    threshold int,
) (*SigningSession, error) {
    return newSigningSessionWithChallengeType(curve, keyShare, message, signers, threshold, BitcoinBIP340)
}

// NewEthereumSigningSession creates a new signing session with Ethereum EVM challenge
func NewEthereumSigningSession(
    curve Curve,
    keyShare *KeyShare,
    message []byte,
    signers []ParticipantIndex,
    threshold int,
) (*SigningSession, error) {
    return newSigningSessionWithChallengeType(curve, keyShare, message, signers, threshold, EthereumEVM)
}

// NewSolanaSigningSession creates a new signing session with Solana Ed25519 challenge
func NewSolanaSigningSession(
    curve Curve,
    keyShare *KeyShare,
    message []byte,
    signers []ParticipantIndex,
    threshold int,
) (*SigningSession, error) {
    return newSigningSessionWithChallengeType(curve, keyShare, message, signers, threshold, SolanaEd25519)
}

// newSigningSessionWithChallengeType creates a new signing session with specified challenge type
func newSigningSessionWithChallengeType(
    curve Curve,
    keyShare *KeyShare,
    message []byte,
    signers []ParticipantIndex,
    threshold int,
    challengeType ChallengeType,
) (*SigningSession, error) {
    if len(signers) < threshold {
        return nil, fmt.Errorf("insufficient signers: need %d, got %d", threshold, len(signers))
    }
    
    // Verify our participant ID is in the signers list
    found := false
    for _, signer := range signers {
        if signer == keyShare.ParticipantID {
            found = true
            break
        }
    }
    if !found {
        return nil, fmt.Errorf("our participant ID %d not in signers list", keyShare.ParticipantID)
    }
    
    return &SigningSession{
        curve:         curve,
        keyShare:      keyShare,
        message:       message,
        signers:       signers,
        threshold:     threshold,
        challengeType: challengeType,
        commitments:   make(map[ParticipantIndex]*SigningCommitment),
        responses:     make(map[ParticipantIndex]*SigningResponse),
    }, nil
}

// Round1 generates our signing commitment
func (ss *SigningSession) Round1() (*SigningCommitment, error) {
    // Generate random nonce
    nonce, err := ss.curve.ScalarRandom()
    if err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }
    
    // Commitment is R = g^r
    commitment := ss.curve.BasePoint().Mul(nonce)
    
    ss.nonce = nonce
    ss.commitment = commitment
    
    signingCommitment := &SigningCommitment{
        ParticipantID: ss.keyShare.ParticipantID,
        Commitment:    commitment,
    }
    
    // Store our own commitment
    ss.commitments[ss.keyShare.ParticipantID] = signingCommitment
    
    return signingCommitment, nil
}

// ProcessRound1 processes commitments from other signers with enhanced validation
func (ss *SigningSession) ProcessRound1(commitments []*SigningCommitment) error {
    for _, commitment := range commitments {
        // Check if commitment from this participant already exists
        if _, exists := ss.commitments[commitment.ParticipantID]; exists {
            return fmt.Errorf("commitment from participant %d already exists", commitment.ParticipantID)
        }

        // Verify the commitment is from an expected signer
        found := false
        for _, signer := range ss.signers {
            if signer == commitment.ParticipantID {
                found = true
                break
            }
        }
        if !found {
            return fmt.Errorf("unexpected commitment from participant %d", commitment.ParticipantID)
        }

        // Validate that the commitment point is valid
        if commitment.Commitment == nil {
            return fmt.Errorf("nil commitment from participant %d", commitment.ParticipantID)
        }

        // Verify commitment is not identity (basic sanity check)
        if commitment.Commitment.IsIdentity() {
            return fmt.Errorf("invalid commitment from participant %d", commitment.ParticipantID)
        }

        // Verify the point is on the curve
        if !commitment.Commitment.IsOnCurve() {
            return fmt.Errorf("commitment from participant %d is not on curve", commitment.ParticipantID)
        }

        ss.commitments[commitment.ParticipantID] = commitment
    }
    
    // Verify we have all expected commitments
    if len(ss.commitments) != len(ss.signers) {
        return fmt.Errorf("missing commitments: expected %d, got %d", len(ss.signers), len(ss.commitments))
    }
    
    return nil
}

// Round2 generates our signing response
func (ss *SigningSession) Round2() (*SigningResponse, error) {
    if len(ss.commitments) != len(ss.signers) {
        return nil, fmt.Errorf("round 1 not completed")
    }
    
    // Compute group commitment R = sum of all individual commitments
    groupCommitment := ss.curve.PointIdentity()
    for _, commitment := range ss.commitments {
        groupCommitment = groupCommitment.Add(commitment.Commitment)
    }

    // Handle BIP-340 parity requirement for secp256k1
    negate := false
    if ss.curve.Name() == "secp256k1" && groupCommitment.(*Secp256k1Point).HasOddY() {
        negate = true
        groupCommitment = groupCommitment.Negate() // Now even Y
    }

    // Store the adjusted group commitment for use in ProcessRound2
    ss.groupCommitment = groupCommitment

    // Compute challenge c = H(R || GroupPubKey || message)
    challenge, err := ss.computeChallenge(groupCommitment, ss.keyShare.GroupPublicKey, ss.message)
    if err != nil {
        return nil, fmt.Errorf("failed to compute challenge: %w", err)
    }
    ss.challenge = challenge

    // Compute Lagrange coefficient for our participant
    lagrangeCoeff, err := ss.computeLagrangeCoefficient(ss.keyShare.ParticipantID)
    if err != nil {
        return nil, fmt.Errorf("failed to compute Lagrange coefficient: %w", err)
    }

    // Compute response: s_i = r_i + c * λ_i * x_i (or -r_i + c * λ_i * x_i if negate)
    // where r_i is our nonce, λ_i is Lagrange coefficient, x_i is our secret share
    clx := challenge.Mul(lagrangeCoeff).Mul(ss.keyShare.SecretShare)
    var response Scalar
    if negate {
        // If we negated the group commitment, negate our nonce in the response
        response = ss.nonce.Negate().Add(clx)
    } else {
        // Normal case: s_i = r_i + c * λ_i * x_i
        response = ss.nonce.Add(clx)
    }
    
    signingResponse := &SigningResponse{
        ParticipantID: ss.keyShare.ParticipantID,
        Response:      response,
    }
    
    ss.responses[ss.keyShare.ParticipantID] = signingResponse
    
    return signingResponse, nil
}

// ProcessRound2 processes responses and generates final signature with validation
func (ss *SigningSession) ProcessRound2(responses []*SigningResponse) (*Signature, error) {
    // Store all responses with validation
    for _, response := range responses {
        // Validate participant is expected
        found := false
        for _, signer := range ss.signers {
            if signer == response.ParticipantID {
                found = true
                break
            }
        }
        if !found {
            return nil, fmt.Errorf("unexpected response from participant %d", response.ParticipantID)
        }

        ss.responses[response.ParticipantID] = response
    }

    // Verify we have all expected responses
    if len(ss.responses) != len(ss.signers) {
        return nil, fmt.Errorf("missing responses: expected %d, got %d", len(ss.signers), len(ss.responses))
    }

    // Use the stored group commitment from Round2 (already adjusted for parity)
    groupCommitment := ss.groupCommitment
    if groupCommitment == nil {
        return nil, fmt.Errorf("group commitment not available - Round2 not completed")
    }

    // Compute final signature scalar s = sum of all responses
    finalS := ss.curve.ScalarZero()
    for _, response := range ss.responses {
        finalS = finalS.Add(response.Response)
    }

    signature := &Signature{
        R: groupCommitment, // Now even if adjusted
        S: finalS,
    }
    
    // Verify the generated signature
    valid, err := ss.verifySignature(signature)
    if err != nil {
        return nil, fmt.Errorf("failed to verify signature: %w", err)
    }
    if !valid {
        return nil, fmt.Errorf("generated signature is invalid")
    }
    
    return signature, nil
}

// computeChallenge computes the Fiat-Shamir challenge with proper error handling
func (ss *SigningSession) computeChallenge(R, groupPubKey Point, message []byte) (Scalar, error) {
    return computeChallengeHelperWithType(ss.curve, R, groupPubKey, message, ss.challengeType)
}

// computeLagrangeCoefficient computes the Lagrange coefficient for participant with error handling
func (ss *SigningSession) computeLagrangeCoefficient(participantID ParticipantIndex) (Scalar, error) {
    // λ_i = ∏(j≠i) j/(j-i) for j in signers
    numerator := ss.curve.ScalarOne()
    denominator := ss.curve.ScalarOne()

    participantScalar, err := participantID.ToScalar(ss.curve)
    if err != nil {
        return nil, fmt.Errorf("failed to convert participant ID to scalar: %w", err)
    }

    for _, signerID := range ss.signers {
        if signerID == participantID {
            continue
        }

        signerScalar, err := signerID.ToScalar(ss.curve)
        if err != nil {
            return nil, fmt.Errorf("failed to convert signer ID to scalar: %w", err)
        }

        // numerator *= j
        numerator = numerator.Mul(signerScalar)

        // denominator *= (j - i)
        diff := signerScalar.Sub(participantScalar)

        // Check for zero denominator to prevent division by zero
        if diff.IsZero() {
            return nil, fmt.Errorf("division by zero in Lagrange coefficient computation")
        }

        denominator = denominator.Mul(diff)
    }

    // Check for zero denominator before inversion
    if denominator.IsZero() {
        return nil, fmt.Errorf("zero denominator in Lagrange coefficient computation")
    }

    // Return numerator / denominator
    denominatorInv, err := denominator.Invert()
    if err != nil {
        return nil, fmt.Errorf("failed to invert denominator: %w", err)
    }

    return numerator.Mul(denominatorInv), nil
}

// verifySignature verifies the generated signature with proper error handling
func (ss *SigningSession) verifySignature(sig *Signature) (bool, error) {
    // Recompute challenge using the same challenge type as used during signing
    challenge, err := computeChallengeHelperWithType(ss.curve, sig.R, ss.keyShare.GroupPublicKey, ss.message, ss.challengeType)
    if err != nil {
        return false, fmt.Errorf("failed to compute challenge for verification: %w", err)
    }

    // Verify: g^s = R + c * GroupPubKey
    leftSide := ss.curve.BasePoint().Mul(sig.S)
    rightSide := sig.R.Add(ss.keyShare.GroupPublicKey.Mul(challenge))

    return leftSide.Equal(rightSide), nil
}

// VerifySignature verifies a FROST signature (static method) with proper error handling
func VerifySignature(curve Curve, signature *Signature, message []byte, groupPubKey Point) (bool, error) {
    // Recompute challenge using helper function
    challenge, err := computeChallengeHelper(curve, signature.R, groupPubKey, message)
    if err != nil {
        return false, fmt.Errorf("failed to compute challenge for verification: %w", err)
    }

    // Verify: g^s = R + c * GroupPubKey
    leftSide := curve.BasePoint().Mul(signature.S)
    rightSide := signature.R.Add(groupPubKey.Mul(challenge))

    return leftSide.Equal(rightSide), nil
}

// computeGroupCommitment computes the group commitment from individual commitments
func (ss *SigningSession) computeGroupCommitment() (Point, error) {
    if len(ss.commitments) == 0 {
        return nil, fmt.Errorf("no commitments available")
    }

    groupCommitment := ss.curve.PointIdentity()
    for _, commitment := range ss.commitments {
        if commitment == nil || commitment.Commitment == nil {
            return nil, fmt.Errorf("nil commitment found")
        }
        groupCommitment = groupCommitment.Add(commitment.Commitment)
    }

    return groupCommitment, nil
}

// computeChallengeHelper is a helper function for challenge computation used by verification methods
func computeChallengeHelper(curve Curve, R, groupPubKey Point, message []byte) (Scalar, error) {
    // Default to standard FROST for static verification
    return computeChallengeHelperWithType(curve, R, groupPubKey, message, StandardFROST)
}

// computeChallengeHelperWithType computes challenge with specified type
func computeChallengeHelperWithType(curve Curve, R, groupPubKey Point, message []byte, challengeType ChallengeType) (Scalar, error) {
    switch challengeType {
    case BitcoinBIP340:
        return BitcoinChallenge(R, groupPubKey, message)
    case EthereumEVM:
        return EthereumChallenge(R, groupPubKey, message)
    case SolanaEd25519:
        return SolanaChallenge(R, groupPubKey, message)
    case StandardFROST:
        fallthrough
    default:
        // Standard FROST challenge computation
        hasher := sha256.New()

        // Add R (group commitment)
        hasher.Write(R.CompressedBytes())

        // Add group public key
        hasher.Write(groupPubKey.CompressedBytes())

        // Add message
        hasher.Write(message)

        challengeBytes := hasher.Sum(nil)

        // Convert to scalar with proper error handling
        challenge, err := curve.ScalarFromUniformBytes(challengeBytes)
        if err != nil {
            return nil, fmt.Errorf("failed to derive challenge scalar: %w", err)
        }

        return challenge, nil
    }
}

// VerifyBLSBinding verifies that a FROST key share is properly bound to a BLS key
// This function validates that a FROST public key was correctly derived from a BLS key
// using the same HKDF process as BLS-anchored key generation.
//
// Parameters:
//   - curve: The elliptic curve being used
//   - blsKeyBytes: The BLS public key bytes
//   - frostPublicKey: The FROST public key to verify
//   - bindingProof: A *BLSBindingProof containing the zero-knowledge proof
//
// Returns an error if verification fails, nil if successful.
func VerifyBLSBinding(curve Curve, blsKeyBytes []byte, frostPublicKey Point, bindingProof interface{}) error {
    // Type check the binding proof
    proof, ok := bindingProof.(*BLSBindingProof)
    if !ok {
        return fmt.Errorf("bindingProof must be of type *BLSBindingProof, got %T", bindingProof)
    }

    // Validate inputs
    if len(blsKeyBytes) == 0 {
        return fmt.Errorf("BLS key bytes cannot be empty")
    }
    if frostPublicKey == nil {
        return fmt.Errorf("FROST public key cannot be nil")
    }
    if proof == nil {
        return fmt.Errorf("binding proof cannot be nil")
    }

    // Verify the BLS public key matches the proof
    if len(proof.BLSPublicKey) != len(blsKeyBytes) {
        return fmt.Errorf("BLS key length mismatch: proof has %d bytes, provided %d bytes",
            len(proof.BLSPublicKey), len(blsKeyBytes))
    }

    // Compare BLS public keys byte by byte
    for i, b := range blsKeyBytes {
        if proof.BLSPublicKey[i] != b {
            return fmt.Errorf("BLS public key mismatch at byte %d", i)
        }
    }

    // Verify the Schnorr proof: g^s = R + c * commitment
    // where commitment should be the FROST public key if properly derived
    leftSide := curve.BasePoint().Mul(proof.Response)
    rightSide := proof.Commitment.Add(frostPublicKey.Mul(proof.Challenge))

    if !leftSide.Equal(rightSide) {
        return fmt.Errorf("BLS binding proof verification failed: Schnorr proof invalid")
    }

    // Verify the challenge was computed correctly
    // We need to recompute the challenge using the same algorithm
    expectedChallenge, err := computeBLSBindingChallenge(
        curve,
        proof.ParticipantID,
        proof.BLSPublicKey,
        frostPublicKey,
        proof.Commitment,
        SHA256_HKDF, // Default to compatible algorithm
    )
    if err != nil {
        return fmt.Errorf("failed to compute expected challenge: %w", err)
    }

    if !proof.Challenge.Equal(expectedChallenge) {
        return fmt.Errorf("BLS binding proof verification failed: challenge mismatch")
    }

    return nil
}

// computeBLSBindingChallenge computes the Fiat-Shamir challenge for BLS binding proof
// This is a standalone version of the challenge computation used in BLSAnchoredKeyGen
func computeBLSBindingChallenge(
    curve Curve,
    participantID ParticipantIndex,
    blsPublicKey []byte,
    commitment Point,
    proofCommitment Point,
    hashAlgorithm HashAlgorithm,
) (Scalar, error) {
    switch hashAlgorithm {
    case SHA256_HKDF:
        return computeBLSBindingChallengeHKDF(curve, participantID, blsPublicKey, commitment, proofCommitment)
    case BLAKE2B:
        return computeBLSBindingChallengeBlake2b(curve, participantID, blsPublicKey, commitment, proofCommitment)
    case SHAKE256:
        return computeBLSBindingChallengeShake256(curve, participantID, blsPublicKey, commitment, proofCommitment)
    default:
        return nil, fmt.Errorf("unsupported hash algorithm: %d", hashAlgorithm)
    }
}

// computeBLSBindingChallengeHKDF computes challenge using SHA256+HKDF (compatible)
func computeBLSBindingChallengeHKDF(
    curve Curve,
    participantID ParticipantIndex,
    blsPublicKey []byte,
    commitment Point,
    proofCommitment Point,
) (Scalar, error) {
    // Create HKDF salt from domain separator
    salt := []byte("CANOPY_BLS_BINDING_CHALLENGE_v1")

    // Create HKDF info from participant ID
    participantBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
    info := append([]byte("challenge:"), participantBytes...)

    // Create HKDF input key material from all challenge components
    ikm := append([]byte{}, blsPublicKey...)

    if commitment != nil {
        ikm = append(ikm, commitment.Bytes()...)
    }

    if proofCommitment != nil {
        ikm = append(ikm, proofCommitment.Bytes()...)
    }

    // Generate challenge bytes using HKDF
    hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
    challengeBytes := make([]byte, 64) // 64 bytes for uniform scalar generation
    if _, err := io.ReadFull(hkdfReader, challengeBytes); err != nil {
        return nil, fmt.Errorf("HKDF challenge generation failed: %w", err)
    }

    // Convert to scalar
    challenge, err := curve.ScalarFromUniformBytes(challengeBytes)

    // Clear challenge bytes from memory
    for i := range challengeBytes {
        challengeBytes[i] = 0
    }

    if err != nil {
        return nil, fmt.Errorf("challenge scalar conversion failed: %w", err)
    }

    if challenge == nil {
        return nil, fmt.Errorf("challenge scalar conversion returned nil")
    }

    return challenge, nil
}

// computeBLSBindingChallengeBlake2b computes challenge using Blake2b (better performance)
func computeBLSBindingChallengeBlake2b(
    curve Curve,
    participantID ParticipantIndex,
    blsPublicKey []byte,
    commitment Point,
    proofCommitment Point,
) (Scalar, error) {
    // Create Blake2b hasher with 64-byte output for uniform scalar generation
    hasher, err := blake2b.New(64, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create Blake2b hasher: %w", err)
    }

    // Domain separator for challenge computation
    hasher.Write([]byte("CANOPY_BLS_BINDING_CHALLENGE_BLAKE2B_v1"))

    // Participant ID
    participantBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
    hasher.Write(participantBytes)

    // BLS public key
    hasher.Write(blsPublicKey)

    // Commitment point
    if commitment != nil {
        hasher.Write(commitment.Bytes())
    }

    // Proof commitment point
    if proofCommitment != nil {
        hasher.Write(proofCommitment.Bytes())
    }

    challengeBytes := hasher.Sum(nil)

    challenge, err := curve.ScalarFromUniformBytes(challengeBytes)

    // Clear challenge bytes from memory
    for i := range challengeBytes {
        challengeBytes[i] = 0
    }

    if err != nil {
        return nil, fmt.Errorf("challenge scalar conversion failed: %w", err)
    }

    if challenge == nil {
        return nil, fmt.Errorf("challenge scalar conversion returned nil")
    }

    return challenge, nil
}

// computeBLSBindingChallengeShake256 computes challenge using SHAKE256 (best for key derivation)
func computeBLSBindingChallengeShake256(
    curve Curve,
    participantID ParticipantIndex,
    blsPublicKey []byte,
    commitment Point,
    proofCommitment Point,
) (Scalar, error) {
    // Create SHAKE256 hasher (Extendable Output Function)
    shake := sha3.NewShake256()

    // Domain separator for challenge computation
    shake.Write([]byte("CANOPY_BLS_BINDING_CHALLENGE_SHAKE256_v1"))

    // Participant ID
    participantBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
    shake.Write(participantBytes)

    // BLS public key
    shake.Write(blsPublicKey)

    // Commitment point
    if commitment != nil {
        shake.Write(commitment.Bytes())
    }

    // Proof commitment point
    if proofCommitment != nil {
        shake.Write(proofCommitment.Bytes())
    }

    // Generate challenge bytes
    challengeBytes := make([]byte, 64) // 64 bytes for uniform scalar generation
    shake.Read(challengeBytes)

    challenge, err := curve.ScalarFromUniformBytes(challengeBytes)

    // Clear challenge bytes from memory
    for i := range challengeBytes {
        challengeBytes[i] = 0
    }

    if err != nil {
        return nil, fmt.Errorf("challenge scalar conversion failed: %w", err)
    }

    if challenge == nil {
        return nil, fmt.Errorf("challenge scalar conversion returned nil")
    }

    return challenge, nil
}

// VerifyBLSBindingWithAlgorithm verifies BLS binding with a specific hash algorithm
// This allows users to specify which hash algorithm was used during key generation
func VerifyBLSBindingWithAlgorithm(
    curve Curve,
    blsKeyBytes []byte,
    frostPublicKey Point,
    bindingProof *BLSBindingProof,
    hashAlgorithm HashAlgorithm,
) error {
    // Validate inputs
    if len(blsKeyBytes) == 0 {
        return fmt.Errorf("BLS key bytes cannot be empty")
    }
    if frostPublicKey == nil {
        return fmt.Errorf("FROST public key cannot be nil")
    }
    if bindingProof == nil {
        return fmt.Errorf("binding proof cannot be nil")
    }

    // Verify the BLS public key matches the proof
    if len(bindingProof.BLSPublicKey) != len(blsKeyBytes) {
        return fmt.Errorf("BLS key length mismatch: proof has %d bytes, provided %d bytes",
            len(bindingProof.BLSPublicKey), len(blsKeyBytes))
    }

    // Compare BLS public keys byte by byte
    for i, b := range blsKeyBytes {
        if bindingProof.BLSPublicKey[i] != b {
            return fmt.Errorf("BLS public key mismatch at byte %d", i)
        }
    }

    // Verify the Schnorr proof: g^s = R + c * commitment
    leftSide := curve.BasePoint().Mul(bindingProof.Response)
    rightSide := bindingProof.Commitment.Add(frostPublicKey.Mul(bindingProof.Challenge))

    if !leftSide.Equal(rightSide) {
        return fmt.Errorf("BLS binding proof verification failed: Schnorr proof invalid")
    }

    // Verify the challenge was computed correctly with the specified algorithm
    expectedChallenge, err := computeBLSBindingChallenge(
        curve,
        bindingProof.ParticipantID,
        bindingProof.BLSPublicKey,
        frostPublicKey,
        bindingProof.Commitment,
        hashAlgorithm,
    )
    if err != nil {
        return fmt.Errorf("failed to compute expected challenge: %w", err)
    }

    if !bindingProof.Challenge.Equal(expectedChallenge) {
        return fmt.Errorf("BLS binding proof verification failed: challenge mismatch")
    }

    return nil
}

// GenerateCommitment is a compatibility method that calls Round1
func (ss *SigningSession) GenerateCommitment(participantID ParticipantIndex, keyShare *KeyShare) (*SigningCommitment, error) {
    return ss.Round1()
}

// GenerateBLSValidatedCommitment generates a commitment with BLS validation
// This function generates a FROST signing commitment while verifying that the key share
// is properly bound to the provided BLS key through a zero-knowledge proof.
//
// Parameters:
//   - participantID: The ID of the participant generating the commitment
//   - keyShare: The FROST key share (must include BLS binding proof)
//   - blsKey: The BLS private key (must be *crypto.BLS12381PrivateKey)
//
// Returns a SigningCommitment if successful, or an error if BLS validation fails.
func (ss *SigningSession) GenerateBLSValidatedCommitment(participantID ParticipantIndex, keyShare *KeyShare, blsKey interface{}) (*SigningCommitment, error) {
    // Validate inputs
    if keyShare == nil {
        return nil, fmt.Errorf("key share cannot be nil")
    }
    if blsKey == nil {
        return nil, fmt.Errorf("BLS key cannot be nil")
    }

    // Type check the BLS key
    blsPrivKey, ok := blsKey.(*crypto.BLS12381PrivateKey)
    if !ok {
        return nil, fmt.Errorf("blsKey must be of type *crypto.BLS12381PrivateKey, got %T", blsKey)
    }

    // Get BLS public key bytes for validation
    blsPubKey := blsPrivKey.PublicKey()
    if blsPubKey == nil {
        return nil, fmt.Errorf("BLS public key is nil")
    }
    blsPubKeyBytes := blsPubKey.Bytes()

    // Verify BLS binding if key share has binding proof
    if keyShare.BLSBindingProof != nil {
        // Use VSS commitment if available, otherwise fall back to individual public key
        commitmentToVerify := keyShare.VSSCommitment
        if commitmentToVerify == nil {
            commitmentToVerify = keyShare.PublicKey
        }

        err := VerifyBLSBindingWithAlgorithm(
            ss.curve,
            blsPubKeyBytes,
            commitmentToVerify,
            keyShare.BLSBindingProof,
            SHA256_HKDF, // Default algorithm - could be made configurable
        )
        if err != nil {
            return nil, fmt.Errorf("BLS binding validation failed: %w", err)
        }
    } else {
        // If no binding proof is available, we can't validate BLS binding
        // This might be acceptable in some scenarios, but we should warn
        return nil, fmt.Errorf("key share does not contain BLS binding proof - cannot validate BLS binding")
    }

    // BLS validation passed, now generate the regular FROST commitment
    // The session already has the keyShare, but we need to ensure it matches
    if ss.keyShare.ParticipantID != participantID {
        return nil, fmt.Errorf("participant ID mismatch: session has %d, provided %d",
            ss.keyShare.ParticipantID, participantID)
    }

    // Generate the commitment using the standard FROST protocol
    return ss.Round1()
}

// GenerateResponse is a compatibility method that calls Round2
func (ss *SigningSession) GenerateResponse(participantID ParticipantIndex, keyShare *KeyShare, commitments map[ParticipantIndex]*SigningCommitment) (*SigningResponse, error) {
    // Add commitments to session
    for pid, commitment := range commitments {
        ss.commitments[pid] = commitment
    }
    return ss.Round2()
}

// GenerateBLSValidatedResponse generates a response with BLS validation
// This function generates a FROST signing response while verifying that the key share
// is properly bound to the provided BLS key through a zero-knowledge proof.
//
// Parameters:
//   - participantID: The ID of the participant generating the response
//   - keyShare: The FROST key share (must include BLS binding proof)
//   - blsKey: The BLS private key (must be *crypto.BLS12381PrivateKey)
//   - commitments: Map of participant commitments from Round 1
//
// Returns a SigningResponse if successful, or an error if BLS validation fails.
func (ss *SigningSession) GenerateBLSValidatedResponse(participantID ParticipantIndex, keyShare *KeyShare, blsKey interface{}, commitments map[ParticipantIndex]*SigningCommitment) (*SigningResponse, error) {
    // Validate inputs
    if keyShare == nil {
        return nil, fmt.Errorf("key share cannot be nil")
    }
    if blsKey == nil {
        return nil, fmt.Errorf("BLS key cannot be nil")
    }
    if commitments == nil {
        return nil, fmt.Errorf("commitments cannot be nil")
    }

    // Type check the BLS key
    blsPrivKey, ok := blsKey.(*crypto.BLS12381PrivateKey)
    if !ok {
        return nil, fmt.Errorf("blsKey must be of type *crypto.BLS12381PrivateKey, got %T", blsKey)
    }

    // Get BLS public key bytes for validation
    blsPubKey := blsPrivKey.PublicKey()
    if blsPubKey == nil {
        return nil, fmt.Errorf("BLS public key is nil")
    }
    blsPubKeyBytes := blsPubKey.Bytes()

    // Verify BLS binding if key share has binding proof
    if keyShare.BLSBindingProof != nil {
        // Use VSS commitment if available, otherwise fall back to individual public key
        commitmentToVerify := keyShare.VSSCommitment
        if commitmentToVerify == nil {
            commitmentToVerify = keyShare.PublicKey
        }

        err := VerifyBLSBindingWithAlgorithm(
            ss.curve,
            blsPubKeyBytes,
            commitmentToVerify,
            keyShare.BLSBindingProof,
            SHA256_HKDF, // Default algorithm - could be made configurable
        )
        if err != nil {
            return nil, fmt.Errorf("BLS binding validation failed: %w", err)
        }
    } else {
        // If no binding proof is available, we can't validate BLS binding
        return nil, fmt.Errorf("key share does not contain BLS binding proof - cannot validate BLS binding")
    }

    // BLS validation passed, now generate the regular FROST response
    // The session already has the keyShare, but we need to ensure it matches
    if ss.keyShare.ParticipantID != participantID {
        return nil, fmt.Errorf("participant ID mismatch: session has %d, provided %d",
            ss.keyShare.ParticipantID, participantID)
    }

    // Add commitments to session
    for pid, commitment := range commitments {
        ss.commitments[pid] = commitment
    }

    // Generate the response using the standard FROST protocol
    return ss.Round2()
}

// AggregateSignature aggregates signature shares into a final signature
func (ss *SigningSession) AggregateSignature(signatureShares map[ParticipantIndex]Scalar) (*Signature, error) {
    // Validate that we have at least the threshold number of signature shares
    if len(signatureShares) < ss.threshold {
        return nil, fmt.Errorf("insufficient signature shares: need at least %d, got %d", ss.threshold, len(signatureShares))
    }

    // Convert signature shares to responses slice
    responses := make([]*SigningResponse, 0, len(signatureShares))
    for pid, share := range signatureShares {
        responses = append(responses, &SigningResponse{
            ParticipantID: pid,
            Response:      share,
        })
    }

    return ss.ProcessRound2(responses)
}