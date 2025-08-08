package frost

import (
	"fmt"

	"github.com/canopy-network/canopy/lib/crypto"
)

// StableAddressManager manages FROST wallets with stable addresses
type StableAddressManager struct {
	curve         Curve
	foundationKey Scalar
}

// NewStableAddressManager creates a manager for stable FROST addresses
func NewStableAddressManager(curve Curve, foundationKey Scalar) *StableAddressManager {
	return &StableAddressManager{
		curve:         curve,
		foundationKey: foundationKey,
	}
}

// GetStableAddress returns the stable wallet address derived from the foundation key
// This address never changes regardless of validator set composition
func (sam *StableAddressManager) GetStableAddress() Point {
	return sam.curve.BasePoint().Mul(sam.foundationKey)
}

// GenerateFROSTShares generates FROST threshold shares for the current validator set
// The shares change when validators change, but they always represent the same stable address
func (sam *StableAddressManager) GenerateFROSTShares(
	threshold int,
	participants []ParticipantIndex,
	validatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey,
) (map[ParticipantIndex]*KeyShare, error) {
	
	fakg := NewFoundationAnchoredKeyGen(
		sam.curve,
		threshold,
		participants,
		sam.foundationKey,
		validatorBLSKeys,
	)
	
	shares, _, err := fakg.GenerateKeyShares()
	if err != nil {
		return nil, fmt.Errorf("failed to generate FROST shares: %w", err)
	}
	
	return shares, nil
}

// ValidateAddressConsistency verifies that generated shares represent the correct stable address
func (sam *StableAddressManager) ValidateAddressConsistency(shares map[ParticipantIndex]*KeyShare) error {
	expectedAddress := sam.GetStableAddress()
	
	for participantID, share := range shares {
		if !share.GroupPublicKey.Equal(expectedAddress) {
			return fmt.Errorf("participant %d has incorrect group public key", participantID)
		}
	}
	
	return nil
}

// StableWalletConfig represents a complete stable wallet configuration
type StableWalletConfig struct {
	StableAddress    Point
	Threshold        int
	Participants     []ParticipantIndex
	Shares          map[ParticipantIndex]*KeyShare
	ValidatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey
}

// CreateStableWallet creates a complete stable wallet configuration
func CreateStableWallet(
	curve Curve,
	foundationKey Scalar,
	threshold int,
	participants []ParticipantIndex,
	validatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey,
) (*StableWalletConfig, error) {
	
	manager := NewStableAddressManager(curve, foundationKey)
	
	shares, err := manager.GenerateFROSTShares(threshold, participants, validatorBLSKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to generate FROST shares: %w", err)
	}
	
	stableAddress := manager.GetStableAddress()
	
	return &StableWalletConfig{
		StableAddress:    stableAddress,
		Threshold:        threshold,
		Participants:     participants,
		Shares:          shares,
		ValidatorBLSKeys: validatorBLSKeys,
	}, nil
}

// UpdateValidatorSet updates the validator set while preserving the stable address
func (config *StableWalletConfig) UpdateValidatorSet(
	curve Curve,
	foundationKey Scalar,
	newThreshold int,
	newParticipants []ParticipantIndex,
	newValidatorBLSKeys map[ParticipantIndex]*crypto.BLS12381PrivateKey,
) error {
	
	manager := NewStableAddressManager(curve, foundationKey)
	
	// Verify the stable address hasn't changed
	expectedAddress := manager.GetStableAddress()
	if !config.StableAddress.Equal(expectedAddress) {
		return fmt.Errorf("foundation key mismatch: stable address would change")
	}
	
	// Generate new shares for the new validator set
	newShares, err := manager.GenerateFROSTShares(newThreshold, newParticipants, newValidatorBLSKeys)
	if err != nil {
		return fmt.Errorf("failed to generate new FROST shares: %w", err)
	}
	
	// Update configuration
	config.Threshold = newThreshold
	config.Participants = newParticipants
	config.Shares = newShares
	config.ValidatorBLSKeys = newValidatorBLSKeys
	
	return nil
}

// SignMessage performs threshold signing with the stable wallet
func (config *StableWalletConfig) SignMessage(
	curve Curve,
	message []byte,
	signerIDs []ParticipantIndex,
) (*Signature, error) {

	if len(signerIDs) < config.Threshold {
		return nil, fmt.Errorf("insufficient signers: need %d, got %d", config.Threshold, len(signerIDs))
	}

	// Verify all signers have shares
	for _, signerID := range signerIDs {
		if _, exists := config.Shares[signerID]; !exists {
			return nil, fmt.Errorf("no share found for signer %d", signerID)
		}
	}

	// Create signing sessions
	sessions := make([]*SigningSession, len(signerIDs))
	for i, signerID := range signerIDs {
		session, err := NewSigningSession(curve, config.Shares[signerID], message, signerIDs, config.Threshold)
		if err != nil {
			return nil, fmt.Errorf("failed to create signing session for participant %d: %w", signerID, err)
		}
		sessions[i] = session
	}

	// Round 1: Generate commitments
	commitments := make([]*SigningCommitment, len(sessions))
	for i, session := range sessions {
		commitment, err := session.Round1()
		if err != nil {
			return nil, fmt.Errorf("round 1 failed for participant %d: %w", signerIDs[i], err)
		}
		commitments[i] = commitment
	}

	// Process commitments for each session
	for i, session := range sessions {
		otherCommitments := make([]*SigningCommitment, 0, len(commitments)-1)
		for j, commitment := range commitments {
			if j != i {
				otherCommitments = append(otherCommitments, commitment)
			}
		}

		err := session.ProcessRound1(otherCommitments)
		if err != nil {
			return nil, fmt.Errorf("failed to process round 1 for participant %d: %w", signerIDs[i], err)
		}
	}

	// Round 2: Generate signature responses
	responses := make([]*SigningResponse, len(sessions))
	for i, session := range sessions {
		response, err := session.Round2()
		if err != nil {
			return nil, fmt.Errorf("round 2 failed for participant %d: %w", signerIDs[i], err)
		}
		responses[i] = response
	}

	// Process responses to generate final signature
	signature, err := sessions[0].ProcessRound2(responses)
	if err != nil {
		return nil, fmt.Errorf("failed to process round 2: %w", err)
	}

	return signature, nil
}

// VerifySignature verifies a signature against the stable address
func (config *StableWalletConfig) VerifySignature(curve Curve, signature *Signature, message []byte) (bool, error) {
	return VerifySignature(curve, signature, message, config.StableAddress)
}

// GetAddressForChain returns the stable address formatted for a specific blockchain
func (config *StableWalletConfig) GetAddressForChain(chain string) (string, error) {
	switch chain {
	case "bitcoin":
		// Convert to Bitcoin address format
		return formatBitcoinAddress(config.StableAddress)
	case "ethereum":
		// Convert to Ethereum address format
		return formatEthereumAddress(config.StableAddress)
	case "solana":
		// Convert to Solana address format
		return formatSolanaAddress(config.StableAddress)
	default:
		return "", fmt.Errorf("unsupported chain: %s", chain)
	}
}

// Helper functions for chain-specific address formatting
func formatBitcoinAddress(pubKey Point) (string, error) {
	// Simplified - in practice would use proper Bitcoin address encoding
	return fmt.Sprintf("bc1q%x", pubKey.CompressedBytes()[:20]), nil
}

func formatEthereumAddress(pubKey Point) (string, error) {
	// Simplified - in practice would use proper Ethereum address derivation
	return fmt.Sprintf("0x%x", pubKey.CompressedBytes()[:20]), nil
}

func formatSolanaAddress(pubKey Point) (string, error) {
	// Simplified - in practice would use proper Solana address encoding
	bytes := pubKey.CompressedBytes()
	if len(bytes) < 32 {
		// Pad to 32 bytes if needed
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		bytes = padded
	}
	return fmt.Sprintf("%x", bytes[:32]), nil
}

// DeriveFoundationKeyFromRPW derives a foundation key from RPW path
// This is a utility function for creating foundation keys from RPW derivation
func DeriveFoundationKeyFromRPW(curve Curve, rpwSeed []byte, derivationPath []uint32) (Scalar, error) {
	// This would integrate with your existing RPW system
	// For now, this is a simplified implementation
	return deriveFromArbitrarySeed(curve, rpwSeed, "RPW_FOUNDATION")
}

// Example usage documentation
/*
Example Usage:

// 1. Create foundation key from RPW
foundationKey, err := DeriveFoundationKeyFromRPW(curve, rpwSeed, []uint32{0x80000000, 0x80000001})

// 2. Create stable wallet
wallet, err := CreateStableWallet(curve, foundationKey, threshold, participants, validatorBLSKeys)

// 3. Get stable address (never changes)
stableAddress := wallet.StableAddress

// 4. When validator set changes, update shares but keep same address
err = wallet.UpdateValidatorSet(curve, foundationKey, newThreshold, newParticipants, newValidatorBLSKeys)

// 5. Sign messages with threshold signatures
signature, err := wallet.SignMessage(curve, message, signerIDs)

// 6. Verify signatures
valid, err := wallet.VerifySignature(curve, signature, message)
*/
