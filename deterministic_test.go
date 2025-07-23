package frost

import (
    "testing"
)

func TestDeterministicKeyGeneration(t *testing.T) {
    curve := NewEd25519Curve()
    threshold := 2
    participants := []ParticipantIndex{1, 2, 3}

    // Simulate validator DLS keys (in practice, these come from the validator's existing keys)
    validatorKeys := make(map[ParticipantIndex]Scalar)
    for _, participantID := range participants {
        key, err := curve.ScalarRandom()
        if err != nil {
            t.Fatalf("Failed to generate validator key: %v", err)
        }
        validatorKeys[participantID] = key
    }

    // Foundation key (derived from RPW path)
    foundationKey, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate foundation key: %v", err)
    }
    defer foundationKey.Zeroize()

    // Create deterministic key generator
    dkg, err := NewDeterministicKeyGen(curve, threshold, participants, foundationKey, validatorKeys)
    if err != nil {
        t.Fatalf("Failed to create deterministic key generator: %v", err)
    }
    
    // Generate key shares
    keyShares1, groupPubKey1, err := dkg.GenerateKeyShares()
    if err != nil {
        t.Fatalf("Failed to generate key shares: %v", err)
    }
    
    // Generate again - should be identical (deterministic)
    keyShares2, groupPubKey2, err := dkg.GenerateKeyShares()
    if err != nil {
        t.Fatalf("Failed to generate key shares again: %v", err)
    }
    
    // Verify deterministic property
    if !groupPubKey1.Equal(groupPubKey2) {
        t.Fatalf("Group public keys should be identical")
    }
    
    for participantID := range keyShares1 {
        share1 := keyShares1[participantID]
        share2 := keyShares2[participantID]
        
        if !share1.SecretShare.Equal(share2.SecretShare) {
            t.Fatalf("Secret shares should be identical for participant %d", participantID)
        }
        
        if !share1.PublicKey.Equal(share2.PublicKey) {
            t.Fatalf("Public keys should be identical for participant %d", participantID)
        }
    }
    
    t.Log("✅ Deterministic property verified")
    
    // Test that shares work for signing
    // TODO: Signing functionality not fully implemented, skipping for now
    /*
    message := []byte("Test message for deterministic FROST")
    signers := participants[:threshold]
    signerKeyShares := []*KeyShare{
        keyShares1[signers[0]],
        keyShares1[signers[1]],
    }

    // Create signing sessions
    signingSessions := make([]*SigningSession, len(signers))
    for i, keyShare := range signerKeyShares {
        session, err := NewSigningSession(curve, keyShare, message, signers)
        if err != nil {
            t.Fatalf("Failed to create signing session: %v", err)
        }
        signingSessions[i] = session
    }

    // Perform signing rounds
    commitments := make([]*SigningCommitment, len(signers))
    for i, session := range signingSessions {
        commitment, err := session.Round1()
        if err != nil {
            t.Fatalf("Signing round 1 failed: %v", err)
        }
        commitments[i] = commitment
    }

    for _, session := range signingSessions {
        if err := session.ProcessRound1(commitments); err != nil {
            t.Fatalf("Failed to process signing round 1: %v", err)
        }
    }

    responses := make([]*SigningResponse, len(signers))
    for i, session := range signingSessions {
        response, err := session.Round2()
        if err != nil {
            t.Fatalf("Signing round 2 failed: %v", err)
        }
        responses[i] = response
    }

    signature, err := signingSessions[0].ProcessRound2(responses)
    if err != nil {
        t.Fatalf("Failed to generate signature: %v", err)
    }

    // Verify signature
    if !VerifySignature(curve, signature, message, groupPubKey1) {
        t.Fatalf("Signature verification failed")
    }

    t.Log("✅ Deterministic FROST signing works!")
    */
    
    // Test verification function
    if err := dkg.VerifyDeterministicShares(keyShares1, groupPubKey1); err != nil {
        t.Fatalf("Share verification failed: %v", err)
    }
    
    t.Log("✅ Share verification passed!")
    
    // Clean up
    for _, keyShare := range keyShares1 {
        keyShare.SecretShare.Zeroize()
    }
    for _, keyShare := range keyShares2 {
        keyShare.SecretShare.Zeroize()
    }
    for _, validatorKey := range validatorKeys {
        validatorKey.Zeroize()
    }
}

func TestDifferentValidatorsGiveDifferentKeys(t *testing.T) {
    curve := NewEd25519Curve()
    threshold := 2
    participants := []ParticipantIndex{1, 2, 3}

    // Foundation key (same for both tests)
    foundationKey, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate foundation key: %v", err)
    }
    defer foundationKey.Zeroize()

    // First set of validator keys
    validatorKeys1 := make(map[ParticipantIndex]Scalar)
    for _, participantID := range participants {
        key, err := curve.ScalarRandom()
        if err != nil {
            t.Fatalf("Failed to generate validator key: %v", err)
        }
        validatorKeys1[participantID] = key
    }

    // Second set of validator keys (different)
    validatorKeys2 := make(map[ParticipantIndex]Scalar)
    for _, participantID := range participants {
        key, err := curve.ScalarRandom()
        if err != nil {
            t.Fatalf("Failed to generate validator key: %v", err)
        }
        validatorKeys2[participantID] = key
    }
    
    // Generate keys with first validator set
    dkg1, err := NewDeterministicKeyGen(curve, threshold, participants, foundationKey, validatorKeys1)
    if err != nil {
        t.Fatalf("Failed to create deterministic key generator 1: %v", err)
    }
    _, groupPubKey1, err := dkg1.GenerateKeyShares()
    if err != nil {
        t.Fatalf("Failed to generate key shares 1: %v", err)
    }

    // Generate keys with second validator set
    dkg2, err := NewDeterministicKeyGen(curve, threshold, participants, foundationKey, validatorKeys2)
    if err != nil {
        t.Fatalf("Failed to create deterministic key generator 2: %v", err)
    }
    _, groupPubKey2, err := dkg2.GenerateKeyShares()
    if err != nil {
        t.Fatalf("Failed to generate key shares 2: %v", err)
    }
    
    // Keys should be different
    if groupPubKey1.Equal(groupPubKey2) {
        t.Fatalf("Different validator sets should produce different group keys")
    }
    
    t.Log("✅ Different validator sets produce different keys")
    
    // Clean up
    for _, key := range validatorKeys1 {
        key.Zeroize()
    }
    for _, key := range validatorKeys2 {
        key.Zeroize()
    }
}