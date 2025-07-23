package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

// TestHDWalletSigning tests hierarchical deterministic wallet functionality
// Tests signing for root address and derived addresses (like 5th address)
func TestHDWalletSigning(t *testing.T) {
	curve := NewEd25519Curve()
	threshold := 2
	participants := []ParticipantIndex{1, 2, 3}

	t.Run("RootAndDerivedAddressSigning", func(t *testing.T) {
		// Create master seed for HD wallet
		masterSeed := []byte("test_master_seed_for_hd_wallet_testing")
		
		// Test 1: Root address (path: m)
		t.Run("RootAddressSigning", func(t *testing.T) {
			rootPath := []uint32{} // Empty path = root
			testHDAddressSigning(t, curve, threshold, participants, masterSeed, rootPath, "root")
		})

		// Test 2: First derived address (path: m/0)
		t.Run("FirstDerivedAddressSigning", func(t *testing.T) {
			firstPath := []uint32{0}
			testHDAddressSigning(t, curve, threshold, participants, masterSeed, firstPath, "m/0")
		})

		// Test 3: Fifth derived address (path: m/4) - 0-indexed
		t.Run("FifthDerivedAddressSigning", func(t *testing.T) {
			fifthPath := []uint32{4}
			testHDAddressSigning(t, curve, threshold, participants, masterSeed, fifthPath, "m/4 (5th address)")
		})

		// Test 4: Hardened derivation (path: m/0')
		t.Run("HardenedDerivedAddressSigning", func(t *testing.T) {
			hardenedPath := []uint32{0x80000000} // Hardened derivation
			testHDAddressSigning(t, curve, threshold, participants, masterSeed, hardenedPath, "m/0' (hardened)")
		})

		// Test 5: Deep derivation path (path: m/44'/0'/0'/0/5)
		t.Run("DeepDerivedAddressSigning", func(t *testing.T) {
			deepPath := []uint32{
				44 + 0x80000000, // m/44' (purpose - hardened)
				0 + 0x80000000,  // m/44'/0' (coin type - hardened)  
				0 + 0x80000000,  // m/44'/0'/0' (account - hardened)
				0,               // m/44'/0'/0'/0 (change - not hardened)
				5,               // m/44'/0'/0'/0/5 (address index - not hardened)
			}
			testHDAddressSigning(t, curve, threshold, participants, masterSeed, deepPath, "m/44'/0'/0'/0/5 (BIP44 6th address)")
		})
	})

	t.Run("DeterministicDerivation", func(t *testing.T) {
		// Test that same path always produces same keys
		masterSeed := []byte("deterministic_test_seed")
		path := []uint32{0, 1, 2}

		// Generate keys twice with same parameters
		keys1 := deriveHDKeys(t, curve, threshold, participants, masterSeed, path)
		keys2 := deriveHDKeys(t, curve, threshold, participants, masterSeed, path)

		// Verify deterministic property
		if !keys1.groupPublicKey.Equal(keys2.groupPublicKey) {
			t.Error("HD derivation should be deterministic - group public keys differ")
		}

		for participantID := range keys1.keyShares {
			share1 := keys1.keyShares[participantID]
			share2 := keys2.keyShares[participantID]

			if !share1.SecretShare.Equal(share2.SecretShare) {
				t.Errorf("HD derivation should be deterministic - secret shares differ for participant %d", participantID)
			}
		}

		t.Log("✅ HD derivation is deterministic")
	})

	t.Run("DifferentPathsDifferentKeys", func(t *testing.T) {
		// Test that different paths produce different keys
		masterSeed := []byte("different_paths_test_seed")
		
		path1 := []uint32{0}
		path2 := []uint32{1}

		keys1 := deriveHDKeys(t, curve, threshold, participants, masterSeed, path1)
		keys2 := deriveHDKeys(t, curve, threshold, participants, masterSeed, path2)

		// Verify different paths produce different keys
		if keys1.groupPublicKey.Equal(keys2.groupPublicKey) {
			t.Error("Different HD paths should produce different group public keys")
		}

		t.Log("✅ Different HD paths produce different keys")
	})
}

// HDKeys holds the derived keys for a specific path
type HDKeys struct {
	keyShares      map[ParticipantIndex]*KeyShare
	groupPublicKey Point
	derivationPath []uint32
}

// deriveHDKeys derives FROST keys for a specific HD path
func deriveHDKeys(t *testing.T, curve Curve, threshold int, participants []ParticipantIndex, masterSeed []byte, path []uint32) *HDKeys {
	// Create foundation key from master seed and path
	foundationKey, err := deriveFoundationKey(curve, masterSeed, path)
	if err != nil {
		t.Fatalf("Failed to derive foundation key: %v", err)
	}
	defer foundationKey.Zeroize()

	// Create mock validator keys (in practice, these would be real BLS keys)
	validatorKeys := make(map[ParticipantIndex]Scalar)
	for _, participantID := range participants {
		// Create deterministic validator key based on participant ID and path
		validatorKey, err := deriveValidatorKey(curve, masterSeed, path, participantID)
		if err != nil {
			t.Fatalf("Failed to derive validator key for participant %d: %v", participantID, err)
		}
		validatorKeys[participantID] = validatorKey
	}

	// Create deterministic key generator
	dkg, err := NewDeterministicKeyGen(curve, threshold, participants, foundationKey, validatorKeys)
	if err != nil {
		t.Fatalf("Failed to create deterministic key generator: %v", err)
	}

	// Generate key shares
	keyShares, groupPubKey, err := dkg.GenerateKeyShares()
	if err != nil {
		t.Fatalf("Failed to generate key shares: %v", err)
	}

	// Clean up validator keys
	for _, key := range validatorKeys {
		key.Zeroize()
	}

	return &HDKeys{
		keyShares:      keyShares,
		groupPublicKey: groupPubKey,
		derivationPath: path,
	}
}

// testHDAddressSigning tests signing functionality for a specific HD address
func testHDAddressSigning(t *testing.T, curve Curve, threshold int, participants []ParticipantIndex, masterSeed []byte, path []uint32, pathDescription string) {
	t.Logf("Testing HD wallet signing for %s", pathDescription)

	// Derive keys for this path
	hdKeys := deriveHDKeys(t, curve, threshold, participants, masterSeed, path)

	// Test message to sign
	message := []byte(fmt.Sprintf("Test message for HD path: %s", pathDescription))

	// Select signers (use threshold number of participants)
	signers := participants[:threshold]

	// Create signing sessions
	signingSessions := make([]*SigningSession, len(signers))
	for i, participantID := range signers {
		keyShare := hdKeys.keyShares[participantID]
		session, err := NewSigningSession(curve, keyShare, message, signers, threshold)
		if err != nil {
			t.Fatalf("Failed to create signing session for participant %d: %v", participantID, err)
		}
		signingSessions[i] = session
	}

	// Round 1: Generate commitments
	commitments := make([]*SigningCommitment, len(signers))
	for i, session := range signingSessions {
		commitment, err := session.Round1()
		if err != nil {
			t.Fatalf("Round1 failed for signer %d: %v", i, err)
		}
		commitments[i] = commitment
	}

	// Process Round 1: Share commitments between all sessions
	for i, session := range signingSessions {
		// Create a list of commitments from other participants (excluding own)
		otherCommitments := make([]*SigningCommitment, 0, len(commitments)-1)
		for j, commitment := range commitments {
			if i != j { // Don't include own commitment
				otherCommitments = append(otherCommitments, commitment)
			}
		}

		err := session.ProcessRound1(otherCommitments)
		if err != nil {
			t.Fatalf("ProcessRound1 failed for session %d: %v", i, err)
		}
	}

	// Round 2: Generate responses
	responses := make([]*SigningResponse, len(signers))
	for i, session := range signingSessions {
		response, err := session.Round2()
		if err != nil {
			t.Fatalf("Round2 failed for signer %d: %v", i, err)
		}
		responses[i] = response
	}

	// Process Round 2: Generate final signature
	signature, err := signingSessions[0].ProcessRound2(responses)
	if err != nil {
		t.Fatalf("Failed to process round 2: %v", err)
	}

	// Verify signature
	valid, err := VerifySignature(curve, signature, message, hdKeys.groupPublicKey)
	if err != nil {
		t.Fatalf("Signature verification error for %s: %v", pathDescription, err)
	}
	if !valid {
		t.Fatalf("Signature verification failed for %s", pathDescription)
	}

	t.Logf("✅ Successfully signed and verified message for %s", pathDescription)
	t.Logf("   Group public key: %x", hdKeys.groupPublicKey.CompressedBytes()[:8]) // Show first 8 bytes
	t.Logf("   Signature R: %x", signature.R.CompressedBytes()[:8])
	t.Logf("   Signature S: %x", signature.S.Bytes()[:8])
}

// deriveFoundationKey derives a foundation key from master seed and path
func deriveFoundationKey(curve Curve, masterSeed []byte, path []uint32) (Scalar, error) {
	hasher := sha256.New()
	hasher.Write(masterSeed)
	hasher.Write([]byte("FROST_HD_FOUNDATION"))

	// Add derivation path
	for _, pathElement := range path {
		pathBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(pathBytes, pathElement)
		hasher.Write(pathBytes)
	}

	// Add curve identifier for domain separation
	hasher.Write([]byte(curve.Name()))

	derivedBytes := hasher.Sum(nil)
	scalar, err := curve.ScalarFromUniformBytes(derivedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive foundation key: %w", err)
	}
	return scalar, nil
}

// deriveValidatorKey derives a validator key from master seed, path, and participant ID
func deriveValidatorKey(curve Curve, masterSeed []byte, path []uint32, participantID ParticipantIndex) (Scalar, error) {
	hasher := sha256.New()
	hasher.Write(masterSeed)
	hasher.Write([]byte("FROST_HD_VALIDATOR"))

	// Add participant ID
	participantBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(participantBytes, uint32(participantID))
	hasher.Write(participantBytes)

	// Add derivation path
	for _, pathElement := range path {
		pathBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(pathBytes, pathElement)
		hasher.Write(pathBytes)
	}

	// Add curve identifier for domain separation
	hasher.Write([]byte(curve.Name()))

	derivedBytes := hasher.Sum(nil)
	scalar, err := curve.ScalarFromUniformBytes(derivedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive validator key: %w", err)
	}
	return scalar, nil
}

// TestUserControlledFROSTWallets tests creating FROST wallets controlled by user wallets
func TestUserControlledFROSTWallets(t *testing.T) {
	curve := NewEd25519Curve()
	threshold := 2
	participants := []ParticipantIndex{1, 2, 3}

	t.Run("UserControlledWalletCreation", func(t *testing.T) {
		// Simulate user's wallet
		userPrivateKey, _ := curve.ScalarRandom()
		userPublicKey := curve.BasePoint().Mul(userPrivateKey)
		userAddress := userPublicKey.CompressedBytes()[:20] // Simulate address

		// Create mock validator keys
		validatorKeys := make(map[ParticipantIndex]Scalar)
		for _, participantID := range participants {
			validatorKey, _ := curve.ScalarRandom()
			validatorKeys[participantID] = validatorKey
		}

		// Test 1: Create FROST wallet controlled by user
		t.Run("CreateUserControlledWallet", func(t *testing.T) {
			derivationPath := []uint32{0, 1} // User's first FROST wallet

			// Create user-controlled FROST wallet
			dkg, err := NewUserControlledKeyGen(
				curve,
				threshold,
				participants,
				userAddress,
				userPrivateKey,
				derivationPath,
				validatorKeys,
			)
			if err != nil {
				t.Fatalf("Failed to create user-controlled key generator: %v", err)
			}

			// Generate key shares
			keyShares, groupPubKey, err := dkg.GenerateKeyShares()
			if err != nil {
				t.Fatalf("Failed to generate key shares: %v", err)
			}

			// Test signing with user-controlled wallet
			message := []byte("User-controlled FROST wallet test")
			testUserControlledSigning(t, curve, threshold, participants[:threshold], keyShares, groupPubKey, message)

			t.Logf("✅ Successfully created and tested user-controlled FROST wallet")
			t.Logf("   User address: %x", userAddress)
			t.Logf("   FROST group key: %x", groupPubKey.CompressedBytes()[:8])
		})

		// Test 2: Multiple FROST wallets for same user
		t.Run("MultipleWalletsForSameUser", func(t *testing.T) {
			// Create two different FROST wallets for the same user
			path1 := []uint32{0, 1} // First wallet
			path2 := []uint32{0, 2} // Second wallet

			dkg1, _ := NewUserControlledKeyGen(curve, threshold, participants, userAddress, userPrivateKey, path1, validatorKeys)
			dkg2, _ := NewUserControlledKeyGen(curve, threshold, participants, userAddress, userPrivateKey, path2, validatorKeys)

			_, groupPubKey1, _ := dkg1.GenerateKeyShares()
			_, groupPubKey2, _ := dkg2.GenerateKeyShares()

			// Verify different paths create different wallets
			if groupPubKey1.Equal(groupPubKey2) {
				t.Error("Different derivation paths should create different FROST wallets")
			}

			t.Logf("✅ Same user can have multiple distinct FROST wallets")
			t.Logf("   Wallet 1 group key: %x", groupPubKey1.CompressedBytes()[:8])
			t.Logf("   Wallet 2 group key: %x", groupPubKey2.CompressedBytes()[:8])
		})

		// Test 3: Different users create different wallets
		t.Run("DifferentUsersCreateDifferentWallets", func(t *testing.T) {
			// Create second user
			user2PrivateKey, _ := curve.ScalarRandom()
			user2PublicKey := curve.BasePoint().Mul(user2PrivateKey)
			user2Address := user2PublicKey.CompressedBytes()[:20]

			derivationPath := []uint32{0, 1} // Same path for both users

			// Create FROST wallets for both users
			dkg1, _ := NewUserControlledKeyGen(curve, threshold, participants, userAddress, userPrivateKey, derivationPath, validatorKeys)
			dkg2, _ := NewUserControlledKeyGen(curve, threshold, participants, user2Address, user2PrivateKey, derivationPath, validatorKeys)

			_, groupPubKey1, _ := dkg1.GenerateKeyShares()
			_, groupPubKey2, _ := dkg2.GenerateKeyShares()

			// Verify different users create different wallets (even with same path)
			if groupPubKey1.Equal(groupPubKey2) {
				t.Error("Different users should create different FROST wallets")
			}

			t.Logf("✅ Different users create distinct FROST wallets")
		})

		// Clean up
		userPrivateKey.Zeroize()
		for _, key := range validatorKeys {
			key.Zeroize()
		}
	})

	t.Run("ArbitrarySeedWalletCreation", func(t *testing.T) {
		// Test creating FROST wallet from transaction hash or other arbitrary data
		transactionHash := []byte("0x1234567890abcdef1234567890abcdef12345678")
		context := "FROST_WALLET_FROM_TX"

		// Create mock validator keys
		validatorKeys := make(map[ParticipantIndex]Scalar)
		for _, participantID := range participants {
			validatorKey, _ := curve.ScalarRandom()
			validatorKeys[participantID] = validatorKey
		}

		// Create FROST wallet from transaction hash
		dkg, err := NewUserControlledKeyGenFromSeed(
			curve,
			threshold,
			participants,
			transactionHash,
			context,
			validatorKeys,
		)
		if err != nil {
			t.Fatalf("Failed to create key generator from seed: %v", err)
		}

		keyShares, groupPubKey, err := dkg.GenerateKeyShares()
		if err != nil {
			t.Fatalf("Failed to generate key shares: %v", err)
		}

		// Test signing
		message := []byte("FROST wallet from transaction hash")
		testUserControlledSigning(t, curve, threshold, participants[:threshold], keyShares, groupPubKey, message)

		t.Logf("✅ Successfully created FROST wallet from arbitrary seed")
		t.Logf("   Seed (tx hash): %x", transactionHash)
		t.Logf("   FROST group key: %x", groupPubKey.CompressedBytes()[:8])

		// Clean up
		for _, key := range validatorKeys {
			key.Zeroize()
		}
	})
}

// testUserControlledSigning tests signing with user-controlled FROST wallet
func testUserControlledSigning(t *testing.T, curve Curve, threshold int, signers []ParticipantIndex, keyShares map[ParticipantIndex]*KeyShare, groupPubKey Point, message []byte) {
	// Create signing sessions
	signingSessions := make([]*SigningSession, len(signers))
	for i, participantID := range signers {
		keyShare := keyShares[participantID]
		session, err := NewSigningSession(curve, keyShare, message, signers, threshold)
		if err != nil {
			t.Fatalf("Failed to create signing session: %v", err)
		}
		signingSessions[i] = session
	}

	// Round 1: Generate commitments
	commitments := make([]*SigningCommitment, len(signers))
	for i, session := range signingSessions {
		commitment, err := session.Round1()
		if err != nil {
			t.Fatalf("Round1 failed: %v", err)
		}
		commitments[i] = commitment
	}

	// Process Round 1: Share commitments
	for i, session := range signingSessions {
		otherCommitments := make([]*SigningCommitment, 0, len(commitments)-1)
		for j, commitment := range commitments {
			if i != j {
				otherCommitments = append(otherCommitments, commitment)
			}
		}
		err := session.ProcessRound1(otherCommitments)
		if err != nil {
			t.Fatalf("ProcessRound1 failed: %v", err)
		}
	}

	// Round 2: Generate responses
	responses := make([]*SigningResponse, len(signers))
	for i, session := range signingSessions {
		response, err := session.Round2()
		if err != nil {
			t.Fatalf("Round2 failed: %v", err)
		}
		responses[i] = response
	}

	// Generate final signature
	signature, err := signingSessions[0].ProcessRound2(responses)
	if err != nil {
		t.Fatalf("Failed to process round 2: %v", err)
	}

	// Verify signature
	valid, err := VerifySignature(curve, signature, message, groupPubKey)
	if err != nil {
		t.Fatalf("Signature verification error: %v", err)
	}
	if !valid {
		t.Fatalf("Signature verification failed")
	}
}
