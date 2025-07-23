package frost

// No imports needed - types are now in the same package

// ParticipantIndex represents a participant identifier
type ParticipantIndex uint32

// KeyShare represents a participant's share in FROST
type KeyShare struct {
    ParticipantID ParticipantIndex
    SecretShare   Scalar
    PublicKey     Point
    GroupPublicKey Point
}

// Zeroize securely clears the secret share
func (ks *KeyShare) Zeroize() {
    if ks.SecretShare != nil {
        ks.SecretShare.Zeroize()
    }
}

// Signature represents a FROST threshold signature
type Signature struct {
    R Point  // Commitment point
    S Scalar // Signature scalar
}

// SigningCommitment represents a participant's commitment in round 1
type SigningCommitment struct {
    ParticipantID ParticipantIndex
    Commitment    Point
}

// SigningResponse represents a participant's response in round 2
type SigningResponse struct {
    ParticipantID ParticipantIndex
    Response      Scalar
}
