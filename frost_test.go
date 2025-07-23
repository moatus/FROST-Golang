package frost

import (
    "testing"
)

func TestFROSTKeygen(t *testing.T) {
    // Test parameters
    curve := NewEd25519Curve()
    threshold := 2
    participants := []ParticipantIndex{1, 2, 3}

    // Step 1: Distributed Key Generation
    t.Log("Starting distributed key generation...")

    // Create keygen sessions for each participant
    sessions := make([]*KeygenSession, len(participants))
    for i, participantID := range participants {
        session, err := NewKeygenSession(curve, participantID, participants, threshold)
        if err != nil {
            t.Fatalf("Failed to create keygen session for participant %d: %v", participantID, err)
        }
        sessions[i] = session
    }

    // Round 1: Generate commitments
    round1Data := make([]*KeygenRound1, len(participants))
    for i, session := range sessions {
        data, err := session.Round1()
        if err != nil {
            t.Fatalf("Round 1 failed for participant %d: %v", participants[i], err)
        }
        round1Data[i] = data

        // Verify that polynomial was created
        if session.polynomial == nil {
            t.Fatalf("Polynomial not created in Round1 for participant %d", participants[i])
        }
    }

    // Process round 1 data (each participant processes others' data)
    for i, session := range sessions {
        // Create data slice excluding this participant's own data
        otherParticipantsData := make([]*KeygenRound1, 0, len(participants)-1)
        for j, data := range round1Data {
            if j != i {
                otherParticipantsData = append(otherParticipantsData, data)
            }
        }

        if err := session.ProcessRound1(otherParticipantsData); err != nil {
            t.Fatalf("Failed to process round 1 data for participant %d: %v", participants[i], err)
        }
    }

    // Round 2: Generate shares
    round2Data := make([]*KeygenRound2, len(participants))
    for i, session := range sessions {
        data, err := session.Round2()
        if err != nil {
            t.Fatalf("Round 2 failed for participant %d: %v", participants[i], err)
        }
        round2Data[i] = data
    }

    // Finalize key generation (each participant processes others' round2 data)
    keygenResults := make([]*KeygenResult, len(participants))
    for i, session := range sessions {
        // Create data slice excluding this participant's own data
        otherParticipantsRound2Data := make([]*KeygenRound2, 0, len(participants)-1)
        for j, data := range round2Data {
            if j != i {
                otherParticipantsRound2Data = append(otherParticipantsRound2Data, data)
            }
        }

        result, err := session.ProcessRound2(otherParticipantsRound2Data)
        if err != nil {
            t.Fatalf("Failed to finalize keygen for participant %d: %v", participants[i], err)
        }
        keygenResults[i] = result
    }

    // Verify all participants have the same group public key
    groupPubKey := keygenResults[0].GroupPublicKey
    for i := 1; i < len(keygenResults); i++ {
        if !keygenResults[i].GroupPublicKey.Equal(groupPubKey) {
            t.Fatalf("Group public keys don't match between participants %d and %d", 0, i)
        }
    }

    // Verify each participant has a different secret share
    for i := 0; i < len(keygenResults); i++ {
        for j := i + 1; j < len(keygenResults); j++ {
            if keygenResults[i].KeyShare.SecretShare.Equal(keygenResults[j].KeyShare.SecretShare) {
                t.Fatalf("Participants %d and %d have the same secret share", i, j)
            }
        }
    }

    // Verify threshold and participant count
    for i, result := range keygenResults {
        if result.Threshold != threshold {
            t.Fatalf("Participant %d has wrong threshold: expected %d, got %d", i, threshold, result.Threshold)
        }
        if len(result.Participants) != len(participants) {
            t.Fatalf("Participant %d has wrong participant count: expected %d, got %d", i, len(participants), len(result.Participants))
        }
    }

    t.Log("Key generation completed successfully!")
    t.Log("✅ All participants have the same group public key")
    t.Log("✅ All participants have different secret shares")
    t.Log("✅ Threshold and participant counts are correct")
}

func TestFROSTValidations(t *testing.T) {
    // Test the validation fixes we implemented
    curve := NewEd25519Curve()
    threshold := 2
    participants := []ParticipantIndex{1, 2, 3}

    t.Run("DuplicateParticipants", func(t *testing.T) {
        duplicateParticipants := []ParticipantIndex{1, 2, 2} // Duplicate participant 2
        _, err := NewKeygenSession(curve, 1, duplicateParticipants, threshold)
        if err == nil {
            t.Fatalf("Expected error for duplicate participants, got nil")
        }
        t.Logf("✅ Correctly rejected duplicate participants: %v", err)
    })

    t.Run("ParticipantNotInList", func(t *testing.T) {
        _, err := NewKeygenSession(curve, 4, participants, threshold) // 4 is not in [1,2,3]
        if err == nil {
            t.Fatalf("Expected error for participant not in list, got nil")
        }
        t.Logf("✅ Correctly rejected participant not in list: %v", err)
    })

    t.Run("RoundOrderEnforcement", func(t *testing.T) {
        session, err := NewKeygenSession(curve, 1, participants, threshold)
        if err != nil {
            t.Fatalf("Failed to create session: %v", err)
        }

        // Try to call ProcessRound1 before Round1
        err = session.ProcessRound1([]*KeygenRound1{})
        if err == nil {
            t.Fatalf("Expected error for calling ProcessRound1 before Round1")
        }
        t.Logf("✅ Correctly enforced Round1 before ProcessRound1: %v", err)

        // Now do Round1
        _, err = session.Round1()
        if err != nil {
            t.Fatalf("Round1 failed: %v", err)
        }

        // Try to call Round2 before ProcessRound1
        _, err = session.Round2()
        if err == nil {
            t.Fatalf("Expected error for calling Round2 before ProcessRound1")
        }
        t.Logf("✅ Correctly enforced ProcessRound1 before Round2: %v", err)
    })

    t.Run("MultipleRoundProcessing", func(t *testing.T) {
        session, err := NewKeygenSession(curve, 1, participants, threshold)
        if err != nil {
            t.Fatalf("Failed to create session: %v", err)
        }

        // Do Round1
        _, err = session.Round1()
        if err != nil {
            t.Fatalf("Round1 failed: %v", err)
        }

        // Create mock round1 data from other participants (2 and 3)
        mockRound1Data := make([]*KeygenRound1, 2)
        for i, participantID := range []ParticipantIndex{2, 3} {
            // Create a mock session for this participant to generate valid data
            mockSession, err := NewKeygenSession(curve, participantID, participants, threshold)
            if err != nil {
                t.Fatalf("Failed to create mock session: %v", err)
            }
            mockData, err := mockSession.Round1()
            if err != nil {
                t.Fatalf("Failed to generate mock Round1 data: %v", err)
            }
            mockRound1Data[i] = mockData
        }

        // Process Round1 once
        err = session.ProcessRound1(mockRound1Data)
        if err != nil {
            t.Fatalf("ProcessRound1 failed: %v", err)
        }

        // Try to process Round1 again
        err = session.ProcessRound1(mockRound1Data)
        if err == nil {
            t.Fatalf("Expected error for processing Round1 multiple times")
        }
        t.Logf("✅ Correctly prevented multiple Round1 processing: %v", err)
    })

    t.Log("All validation tests passed!")
}