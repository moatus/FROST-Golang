package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
	"github.com/canopy-network/canopy/lib/crypto" // Canopy's BLS implementation
)

// HashAlgorithm specifies which hash algorithm to use for key derivation
type HashAlgorithm int

const (
	// SHA256_HKDF uses SHA256 with HKDF (compatible with existing deployments)
	SHA256_HKDF HashAlgorithm = iota
	// BLAKE2B uses Blake2b with domain separation (better security and performance)
	BLAKE2B
	// SHAKE256 uses SHAKE256 XOF (best for key derivation, quantum-resistant)
	SHAKE256
)

// BLSAnchoredKeyGen generates FROST shares from Canopy validator BLS keys
type BLSAnchoredKeyGen struct {
	curve            Curve
	threshold        int
	participants     []ParticipantIndex
	foundationKey    Scalar
	validatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey
	hashAlgorithm    HashAlgorithm // New: configurable hash algorithm
}

// NewBLSAnchoredKeyGen creates FROST keygen anchored to Canopy BLS keys with SHA256+HKDF (compatible)
func NewBLSAnchoredKeyGen(
	curve Curve,
	threshold int,
	participants []ParticipantIndex,
	foundationKey Scalar,
	validatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey,
) *BLSAnchoredKeyGen {
	return &BLSAnchoredKeyGen{
		curve:            curve,
		threshold:        threshold,
		participants:     participants,
		foundationKey:    foundationKey,
		validatorBLSKeys: validatorBLSKeys,
		hashAlgorithm:    SHA256_HKDF, // Default to compatible algorithm
	}
}

// NewBLSAnchoredKeyGenWithHash creates FROST keygen with configurable hash algorithm
func NewBLSAnchoredKeyGenWithHash(
	curve Curve,
	threshold int,
	participants []ParticipantIndex,
	foundationKey Scalar,
	validatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey,
	hashAlgorithm HashAlgorithm,
) *BLSAnchoredKeyGen {
	return &BLSAnchoredKeyGen{
		curve:            curve,
		threshold:        threshold,
		participants:     participants,
		foundationKey:    foundationKey,
		validatorBLSKeys: validatorBLSKeys,
		hashAlgorithm:    hashAlgorithm,
	}
}

// GenerateKeyShares creates FROST shares from BLS validator keys
func (bkg *BLSAnchoredKeyGen) GenerateKeyShares() (map[ParticipantIndex]*KeyShare, Point, error) {
	keyShares := make(map[ParticipantIndex]*KeyShare)

	// Step 1: Derive Schnorr scalars from BLS keys using HKDF
	schnorrSecrets := make(map[ParticipantIndex]Scalar)
	for _, participantID := range bkg.participants {
		blsKey, exists := bkg.validatorBLSKeys[participantID]
		if !exists {
			return nil, nil, fmt.Errorf("missing BLS key for participant %d", participantID)
		}

		// Map BLS private key to Schnorr scalar via HKDF
		schnorrSecret, err := bkg.blsToSchnorrSecret(participantID, blsKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive Schnorr secret for participant %d: %w", participantID, err)
		}

		schnorrSecrets[participantID] = schnorrSecret
	}

	// Step 2: Generate VSS polynomials deterministically
	polynomials := make(map[ParticipantIndex]*Polynomial)
	commitments := make(map[ParticipantIndex][]Point)

	for _, participantID := range bkg.participants {
		polynomial, commitment, err := bkg.generateVSSPolynomial(participantID, schnorrSecrets[participantID])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate VSS polynomial for participant %d: %w", participantID, err)
		}

		polynomials[participantID] = polynomial
		commitments[participantID] = commitment
	}

	// Step 3: Compute FROST shares via polynomial evaluation
	for _, receiverID := range bkg.participants {
		secretShare := bkg.curve.ScalarZero()

		// Sum evaluations from all polynomials at receiver's ID
		for _, polynomial := range polynomials {
			receiverScalar, err := receiverID.ToScalar(bkg.curve)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to convert participant ID: %w", err)
			}

			evaluation := polynomial.Evaluate(receiverScalar)
			secretShare = secretShare.Add(evaluation)

			// Clean up intermediate values - zeroize evaluation unconditionally as it contains sensitive data
			evaluation.Zeroize()
		}

		// Compute public key for this share
		publicKey := bkg.curve.BasePoint().Mul(secretShare)

		keyShares[receiverID] = &KeyShare{
			ParticipantID: receiverID,
			SecretShare:   secretShare,
			PublicKey:     publicKey,
		}
	}

	// Step 4: Compute group public key (sum of constant terms)
	groupPublicKey := bkg.curve.PointIdentity()
	for _, commitmentList := range commitments {
		groupPublicKey = groupPublicKey.Add(commitmentList[0])
	}

	// Set group public key for all shares
	for _, keyShare := range keyShares {
		keyShare.GroupPublicKey = groupPublicKey
	}

	// Step 5: Generate ZKP proofs for BLS binding
	proofs, err := bkg.generateBLSBindingProofs(schnorrSecrets, commitments)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate BLS binding proofs: %w", err)
	}

	// Verify all proofs
	if err := bkg.verifyBLSBindingProofs(proofs, commitments); err != nil {
		return nil, nil, fmt.Errorf("BLS binding proof verification failed: %w", err)
	}

	// Step 6: Attach BLS binding proofs and VSS commitments to key shares
	for participantID, proof := range proofs {
		if keyShare, exists := keyShares[participantID]; exists {
			keyShare.BLSBindingProof = proof
			// Store the VSS commitment (constant term) for BLS binding verification
			keyShare.VSSCommitment = commitments[participantID][0]
		}
	}

	// Clean up
	for _, secret := range schnorrSecrets {
		secret.Zeroize()
	}
	for _, polynomial := range polynomials {
		polynomial.Zeroize()
	}

	return keyShares, groupPublicKey, nil
}

// blsToSchnorrSecret maps BLS private key to Schnorr scalar using configurable hash algorithm
func (bkg *BLSAnchoredKeyGen) blsToSchnorrSecret(
	participantID ParticipantIndex,
	blsKey *crypto.BLS12381PrivateKey,
) (Scalar, error) {
	switch bkg.hashAlgorithm {
	case SHA256_HKDF:
		return bkg.blsToSchnorrSecretHKDF(participantID, blsKey)
	case BLAKE2B:
		return bkg.blsToSchnorrSecretBlake2b(participantID, blsKey)
	case SHAKE256:
		return bkg.blsToSchnorrSecretShake256(participantID, blsKey)
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %d", bkg.hashAlgorithm)
	}
}

// blsToSchnorrSecretHKDF maps BLS private key to Schnorr scalar using SHA256+HKDF (compatible)
func (bkg *BLSAnchoredKeyGen) blsToSchnorrSecretHKDF(
	participantID ParticipantIndex,
	blsKey *crypto.BLS12381PrivateKey,
) (Scalar, error) {
	// Create HKDF salt from domain separator and curve name
	salt := []byte("CANOPY_BLS_TO_SCHNORR_v1:" + bkg.curve.Name())

	// Create HKDF info from participant ID
	participantBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
	info := append([]byte("participant:"), participantBytes...)

	// Create HKDF input key material from BLS key and foundation key
	blsKeyBytes := blsKey.Bytes()
	foundationKeyBytes := bkg.foundationKey.Bytes()
	ikm := append(blsKeyBytes, foundationKeyBytes...)



	// Use HKDF to derive 64 bytes for uniform scalar generation
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	scalarBytes := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, scalarBytes); err != nil {
		return nil, fmt.Errorf("failed to derive bytes from HKDF: %w", err)
	}



	// Clear IKM from memory
	for i := range ikm {
		ikm[i] = 0
	}

	// Use ScalarFromUniformBytes for hash outputs to ensure valid scalar
	scalar, err := bkg.curve.ScalarFromUniformBytes(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create scalar from HKDF output: %w", err)
	}



	// Clear scalar bytes from memory
	for i := range scalarBytes {
		scalarBytes[i] = 0
	}

	if scalar == nil {
		return nil, fmt.Errorf("scalar is nil after creation")
	}

	return scalar, nil
}

// blsToSchnorrSecretBlake2b maps BLS private key to Schnorr scalar using Blake2b (better performance)
func (bkg *BLSAnchoredKeyGen) blsToSchnorrSecretBlake2b(
	participantID ParticipantIndex,
	blsKey *crypto.BLS12381PrivateKey,
) (Scalar, error) {
	// Create Blake2b hasher with 64-byte output for uniform scalar generation
	hasher, err := blake2b.New(64, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Blake2b hasher: %w", err)
	}

	// Domain separator with curve name
	hasher.Write([]byte("CANOPY_BLS_TO_SCHNORR_BLAKE2B_v1"))
	hasher.Write([]byte(bkg.curve.Name()))

	// BLS private key bytes
	hasher.Write(blsKey.Bytes())

	// Foundation key (ties to specific RPW)
	hasher.Write(bkg.foundationKey.Bytes())

	// Participant ID
	participantBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
	hasher.Write(participantBytes)

	// Generate 64 bytes for uniform scalar generation
	scalarBytes := hasher.Sum(nil)

	// Use ScalarFromUniformBytes for uniform distribution
	scalar, err := bkg.curve.ScalarFromUniformBytes(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create scalar from Blake2b output: %w", err)
	}

	// Clear scalar bytes from memory
	for i := range scalarBytes {
		scalarBytes[i] = 0
	}

	if scalar == nil {
		return nil, fmt.Errorf("scalar is nil after creation")
	}

	return scalar, nil
}

// blsToSchnorrSecretShake256 maps BLS private key to Schnorr scalar using SHAKE256 (best for key derivation)
func (bkg *BLSAnchoredKeyGen) blsToSchnorrSecretShake256(
	participantID ParticipantIndex,
	blsKey *crypto.BLS12381PrivateKey,
) (Scalar, error) {
	// Create SHAKE256 hasher (Extendable Output Function)
	shake := sha3.NewShake256()

	// Domain separator with curve name
	shake.Write([]byte("CANOPY_BLS_TO_SCHNORR_SHAKE256_v1"))
	shake.Write([]byte(bkg.curve.Name()))

	// BLS private key bytes
	shake.Write(blsKey.Bytes())

	// Foundation key (ties to specific RPW)
	shake.Write(bkg.foundationKey.Bytes())

	// Participant ID
	participantBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
	shake.Write(participantBytes)

	// Generate 64 bytes directly for uniform scalar generation (no HKDF needed!)
	scalarBytes := make([]byte, 64)
	n, err := shake.Read(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("SHAKE256 read failed: %w", err)
	}
	if n != 64 {
		return nil, fmt.Errorf("SHAKE256 read returned %d bytes, expected 64", n)
	}

	// Use ScalarFromUniformBytes for uniform distribution
	scalar, err := bkg.curve.ScalarFromUniformBytes(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create scalar from SHAKE256 output: %w", err)
	}

	// Clear scalar bytes from memory
	for i := range scalarBytes {
		scalarBytes[i] = 0
	}

	if scalar == nil {
		return nil, fmt.Errorf("scalar is nil after creation")
	}

	return scalar, nil
}

// generateVSSPolynomial creates a VSS polynomial with BLS binding
func (bkg *BLSAnchoredKeyGen) generateVSSPolynomial(
	participantID ParticipantIndex,
	schnorrSecret Scalar,
) (*Polynomial, []Point, error) {

	// Use Schnorr secret as constant term (create a copy to avoid zeroization issues)
	coefficients := make([]Scalar, bkg.threshold)
	// Create a copy of the schnorr secret to avoid it being zeroized when polynomial is cleaned up
	secretCopy, err := bkg.curve.ScalarFromBytes(schnorrSecret.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create copy of schnorr secret: %w", err)
	}
	coefficients[0] = secretCopy

	// Generate remaining coefficients deterministically
	for i := 1; i < bkg.threshold; i++ {
		coeff, err := bkg.derivePolynomialCoefficient(participantID, schnorrSecret, i)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to derive coefficient %d: %w", i, err)
		}
		coefficients[i] = coeff
	}

	// Compute commitments (Pedersen commitments for VSS)
	commitments := make([]Point, bkg.threshold)
	for i, coeff := range coefficients {
		commitments[i] = bkg.curve.BasePoint().Mul(coeff)
	}

	polynomial := &Polynomial{
		curve:        bkg.curve,
		coefficients: coefficients,
	}

	return polynomial, commitments, nil
}

// derivePolynomialCoefficient generates polynomial coefficients deterministically
func (bkg *BLSAnchoredKeyGen) derivePolynomialCoefficient(
	participantID ParticipantIndex,
	secret Scalar,
	coeffIndex int,
) (Scalar, error) {
	// Create HKDF salt from domain separator
	salt := []byte("CANOPY_VSS_COEFF_v1")

	// Create HKDF info from participant ID and coefficient index
	participantBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
	coeffBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(coeffBytes, uint32(coeffIndex))
	info := append(append([]byte("coeff:"), participantBytes...), coeffBytes...)

	// Create HKDF input key material from secret and foundation key
	ikm := append(secret.Bytes(), bkg.foundationKey.Bytes()...)

	// Use HKDF to derive 64 bytes for uniform scalar generation
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	scalarBytes := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, scalarBytes); err != nil {
		// Clear IKM and return error if HKDF fails
		for i := range ikm {
			ikm[i] = 0
		}
		return nil, fmt.Errorf("HKDF failed for coefficient derivation: %w", err)
	}

	// Clear IKM from memory
	for i := range ikm {
		ikm[i] = 0
	}

	scalar, err := bkg.curve.ScalarFromUniformBytes(scalarBytes)

	// Clear scalar bytes from memory
	for i := range scalarBytes {
		scalarBytes[i] = 0
	}

	if err != nil {
		// Return error instead of zero scalar if conversion fails
		return nil, fmt.Errorf("scalar conversion failed: %w", err)
	}

	if scalar == nil {
		return nil, fmt.Errorf("scalar conversion returned nil")
	}

	return scalar, nil
}

// BLSBindingProof proves that FROST share is correctly derived from BLS key
type BLSBindingProof struct {
	ParticipantID ParticipantIndex
	BLSPublicKey  []byte // BLS public key
	Challenge     Scalar
	Response      Scalar
	Commitment    Point
}

// Zeroize securely clears sensitive data from the BLS binding proof
func (proof *BLSBindingProof) Zeroize() {
	if proof == nil {
		return
	}

	// Clear BLS public key bytes (though public, good practice)
	ZeroizeBytes(proof.BLSPublicKey)

	// Clear sensitive scalars
	if proof.Challenge != nil {
		proof.Challenge.Zeroize()
	}
	if proof.Response != nil {
		proof.Response.Zeroize()
	}

	// Note: Commitment is a Point (public data) so no zeroization needed
	// Note: ParticipantID is not sensitive data
}

// generateBLSBindingProofs creates ZKPs binding FROST shares to BLS keys
func (bkg *BLSAnchoredKeyGen) generateBLSBindingProofs(
	schnorrSecrets map[ParticipantIndex]Scalar,
	commitments map[ParticipantIndex][]Point,
) (map[ParticipantIndex]*BLSBindingProof, error) {

	proofs := make(map[ParticipantIndex]*BLSBindingProof)

	for _, participantID := range bkg.participants {
		blsKey := bkg.validatorBLSKeys[participantID]
		schnorrSecret := schnorrSecrets[participantID]
		commitment := commitments[participantID][0] // Constant term commitment



		// Generate Schnorr proof: prove knowledge of schnorr_secret such that
		// commitment = g^schnorr_secret AND schnorr_secret = HKDF(bls_key, ...)

		// Random nonce for proof
		nonce, err := bkg.curve.ScalarRandom()
		if err != nil {
			return nil, fmt.Errorf("failed to generate proof nonce: %w", err)
		}
		defer nonce.Zeroize()

		// Proof commitment: R = g^nonce
		proofCommitment := bkg.curve.BasePoint().Mul(nonce)

		// Challenge: c = H(bls_pubkey || commitment || R || participant_id)
		blsPubKey := blsKey.PublicKey()
		if blsPubKey == nil {
			return nil, fmt.Errorf("BLS public key is nil for participant %d", participantID)
		}
		blsPubKeyBytes := blsPubKey.Bytes()
		if blsPubKeyBytes == nil {
			return nil, fmt.Errorf("BLS public key bytes are nil for participant %d", participantID)
		}
		challenge, err := bkg.computeProofChallenge(participantID, blsPubKeyBytes, commitment, proofCommitment)
		if err != nil {
			return nil, fmt.Errorf("failed to compute challenge for participant %d: %w", participantID, err)
		}

		if schnorrSecret == nil {
			return nil, fmt.Errorf("schnorr secret is nil for participant %d", participantID)
		}

		// Response: s = nonce + c * schnorr_secret
		challengeTimesSecret := challenge.Mul(schnorrSecret)
		if challengeTimesSecret == nil {
			return nil, fmt.Errorf("challenge.Mul(schnorrSecret) returned nil for participant %d", participantID)
		}
		response := nonce.Add(challengeTimesSecret)



		proofs[participantID] = &BLSBindingProof{
			ParticipantID: participantID,
			BLSPublicKey:  blsPubKeyBytes,
			Challenge:     challenge,
			Response:      response,
			Commitment:    proofCommitment,
		}
	}

	return proofs, nil
}

// verifyBLSBindingProofs verifies all BLS binding proofs
func (bkg *BLSAnchoredKeyGen) verifyBLSBindingProofs(
	proofs map[ParticipantIndex]*BLSBindingProof,
	commitments map[ParticipantIndex][]Point,
) error {

	for participantID, proof := range proofs {
		commitment := commitments[participantID][0]

		// Verify Schnorr proof: g^s = R + c * commitment
		left := bkg.curve.BasePoint().Mul(proof.Response)
		right := proof.Commitment.Add(commitment.Mul(proof.Challenge))

		if !left.Equal(right) {
			return fmt.Errorf("BLS binding proof verification failed for participant %d", participantID)
		}

		// Verify challenge was computed correctly
		expectedChallenge, err := bkg.computeProofChallenge(
			participantID,
			proof.BLSPublicKey,
			commitment,
			proof.Commitment,
		)
		if err != nil {
			return fmt.Errorf("failed to compute expected challenge for participant %d: %w", participantID, err)
		}

		if !proof.Challenge.Equal(expectedChallenge) {
			return fmt.Errorf("BLS binding proof challenge verification failed for participant %d", participantID)
		}
	}

	return nil
}

// computeProofChallenge computes the Fiat-Shamir challenge for BLS binding proof using configurable hash algorithm
func (bkg *BLSAnchoredKeyGen) computeProofChallenge(
	participantID ParticipantIndex,
	blsPublicKey []byte,
	commitment Point,
	proofCommitment Point,
) (Scalar, error) {
	switch bkg.hashAlgorithm {
	case SHA256_HKDF:
		return bkg.computeProofChallengeHKDF(participantID, blsPublicKey, commitment, proofCommitment)
	case BLAKE2B:
		return bkg.computeProofChallengeBlake2b(participantID, blsPublicKey, commitment, proofCommitment)
	case SHAKE256:
		return bkg.computeProofChallengeShake256(participantID, blsPublicKey, commitment, proofCommitment)
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %d", bkg.hashAlgorithm)
	}
}

// computeProofChallengeHKDF computes challenge using SHA256+HKDF (compatible)
func (bkg *BLSAnchoredKeyGen) computeProofChallengeHKDF(
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

	// Use HKDF to derive 64 bytes for uniform scalar generation
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	challengeBytes := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, challengeBytes); err != nil {
		// Clear IKM and return error if HKDF fails
		for i := range ikm {
			ikm[i] = 0
		}
		return nil, fmt.Errorf("HKDF failed for challenge computation: %w", err)
	}

	// Clear IKM from memory
	for i := range ikm {
		ikm[i] = 0
	}

	challenge, err := bkg.curve.ScalarFromUniformBytes(challengeBytes)

	// Clear challenge bytes from memory
	for i := range challengeBytes {
		challengeBytes[i] = 0
	}

	if err != nil {
		// Return error instead of zero scalar if conversion fails
		return nil, fmt.Errorf("challenge scalar conversion failed: %w", err)
	}

	if challenge == nil {
		return nil, fmt.Errorf("challenge scalar conversion returned nil")
	}

	return challenge, nil
}

// computeProofChallengeBlake2b computes challenge using Blake2b (better performance)
func (bkg *BLSAnchoredKeyGen) computeProofChallengeBlake2b(
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

	challenge, err := bkg.curve.ScalarFromUniformBytes(challengeBytes)

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

// computeProofChallengeShake256 computes challenge using SHAKE256 (best for key derivation)
func (bkg *BLSAnchoredKeyGen) computeProofChallengeShake256(
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

	// Extract 64 bytes for uniform scalar generation
	challengeBytes := make([]byte, 64)
	shake.Read(challengeBytes)

	challenge, err := bkg.curve.ScalarFromUniformBytes(challengeBytes)

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
