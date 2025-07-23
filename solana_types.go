package frost

import (
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "fmt"
)

// SolanaAddress represents a 32-byte Solana public key
type SolanaAddress [32]byte

// NewSolanaAddress creates a SolanaAddress from bytes
func NewSolanaAddress(data []byte) (*SolanaAddress, error) {
    if len(data) != 32 {
        return nil, fmt.Errorf("Solana address must be 32 bytes, got %d", len(data))
    }
    
    var addr SolanaAddress
    copy(addr[:], data)
    return &addr, nil
}

// NewSolanaAddressFromHex creates a SolanaAddress from hex string
func NewSolanaAddressFromHex(s string) (*SolanaAddress, error) {
    data, err := hex.DecodeString(s)
    if err != nil {
        return nil, fmt.Errorf("invalid hex string: %w", err)
    }
    return NewSolanaAddress(data)
}

// String returns the hex representation
func (addr SolanaAddress) String() string {
    return hex.EncodeToString(addr[:])
}

// Bytes returns the raw bytes
func (addr SolanaAddress) Bytes() []byte {
    return addr[:]
}

// Equal checks if two addresses are equal
func (addr SolanaAddress) Equal(other SolanaAddress) bool {
    return addr == other
}

// IsZero checks if the address is all zeros
func (addr SolanaAddress) IsZero() bool {
    for _, b := range addr {
        if b != 0 {
            return false
        }
    }
    return true
}

// AccountMeta represents account metadata for Solana instructions
type AccountMeta struct {
    PublicKey  SolanaAddress
    IsSigner   bool
    IsWritable bool
}

// NewAccountMeta creates a new AccountMeta
func NewAccountMeta(pubkey SolanaAddress, isSigner, isWritable bool) *AccountMeta {
    return &AccountMeta{
        PublicKey:  pubkey,
        IsSigner:   isSigner,
        IsWritable: isWritable,
    }
}

// SolanaInstruction represents a Solana program instruction
type SolanaInstruction struct {
    ProgramID SolanaAddress
    Accounts  []*AccountMeta
    Data      []byte
}

// NewSolanaInstruction creates a new instruction
func NewSolanaInstruction(programID SolanaAddress, accounts []*AccountMeta, data []byte) *SolanaInstruction {
    return &SolanaInstruction{
        ProgramID: programID,
        Accounts:  accounts,
        Data:      data,
    }
}

// SolanaMessage represents a Solana transaction message
type SolanaMessage struct {
    Header          MessageHeader
    AccountKeys     []SolanaAddress
    RecentBlockhash SolanaAddress // 32-byte hash
    Instructions    []CompiledInstruction
}

// MessageHeader contains message metadata
type MessageHeader struct {
    NumRequiredSignatures       uint8
    NumReadonlySignedAccounts   uint8
    NumReadonlyUnsignedAccounts uint8
}

// CompiledInstruction represents an instruction with account indices
type CompiledInstruction struct {
    ProgramIDIndex uint8
    AccountIndices []uint8
    Data           []byte
}

// SolanaTransaction represents a complete Solana transaction
type SolanaTransaction struct {
    Message    *SolanaMessage
    Signatures []SolanaSignature
}

// NewSolanaTransaction creates a new transaction
func NewSolanaTransaction(message *SolanaMessage) *SolanaTransaction {
    return &SolanaTransaction{
        Message:    message,
        Signatures: make([]SolanaSignature, message.Header.NumRequiredSignatures),
    }
}

// Serialize serializes the transaction for network transmission
func (tx *SolanaTransaction) Serialize() ([]byte, error) {
    var result []byte
    
    // Serialize signatures
    result = append(result, byte(len(tx.Signatures)))
    for _, sig := range tx.Signatures {
        sigBytes, err := sig.Bytes()
        if err != nil {
            return nil, fmt.Errorf("failed to serialize signature: %w", err)
        }
        result = append(result, sigBytes...)
    }
    
    // Serialize message
    messageBytes, err := tx.Message.Serialize()
    if err != nil {
        return nil, fmt.Errorf("failed to serialize message: %w", err)
    }
    result = append(result, messageBytes...)
    
    return result, nil
}

// Serialize serializes the message
func (msg *SolanaMessage) Serialize() ([]byte, error) {
    var result []byte

    // Validate counts to prevent overflow (single bytes can only hold 0-255)
    if msg.Header.NumRequiredSignatures > 255 {
        return nil, fmt.Errorf("NumRequiredSignatures %d exceeds maximum value 255", msg.Header.NumRequiredSignatures)
    }
    if msg.Header.NumReadonlySignedAccounts > 255 {
        return nil, fmt.Errorf("NumReadonlySignedAccounts %d exceeds maximum value 255", msg.Header.NumReadonlySignedAccounts)
    }
    if msg.Header.NumReadonlyUnsignedAccounts > 255 {
        return nil, fmt.Errorf("NumReadonlyUnsignedAccounts %d exceeds maximum value 255", msg.Header.NumReadonlyUnsignedAccounts)
    }
    if len(msg.AccountKeys) > 255 {
        return nil, fmt.Errorf("AccountKeys length %d exceeds maximum value 255", len(msg.AccountKeys))
    }
    if len(msg.Instructions) > 255 {
        return nil, fmt.Errorf("Instructions length %d exceeds maximum value 255", len(msg.Instructions))
    }

    // Header
    result = append(result, msg.Header.NumRequiredSignatures)
    result = append(result, msg.Header.NumReadonlySignedAccounts)
    result = append(result, msg.Header.NumReadonlyUnsignedAccounts)

    // Account keys
    result = append(result, byte(len(msg.AccountKeys)))
    for _, key := range msg.AccountKeys {
        result = append(result, key.Bytes()...)
    }
    
    // Recent blockhash
    result = append(result, msg.RecentBlockhash.Bytes()...)
    
    // Instructions
    result = append(result, byte(len(msg.Instructions)))
    for _, instruction := range msg.Instructions {
        result = append(result, instruction.ProgramIDIndex)
        
        // Account indices
        result = append(result, byte(len(instruction.AccountIndices)))
        result = append(result, instruction.AccountIndices...)
        
        // Data
        dataLen := make([]byte, 4)
        binary.LittleEndian.PutUint32(dataLen, uint32(len(instruction.Data)))
        result = append(result, dataLen...)
        result = append(result, instruction.Data...)
    }
    
    return result, nil
}

// Hash returns the message hash for signing
func (msg *SolanaMessage) Hash() ([]byte, error) {
    serialized, err := msg.Serialize()
    if err != nil {
        // Return error instead of nil to allow proper error handling
        return nil, fmt.Errorf("failed to serialize message for hashing: %w", err)
    }

    hash := sha256.Sum256(serialized)
    return hash[:], nil
}

// IsSigned checks if the transaction is fully signed
func (tx *SolanaTransaction) IsSigned() bool {
    requiredSigs := int(tx.Message.Header.NumRequiredSignatures)
    if len(tx.Signatures) != requiredSigs {
        return false
    }
    
    for _, sig := range tx.Signatures {
        if sig.IsZero() {
            return false
        }
    }
    
    return true
}

// IsZero checks if a signature is zero (empty)
func (sig *SolanaSignature) IsZero() bool {
    if sig.R == nil && sig.S == nil {
        return true
    }

    if sig.R != nil && !sig.R.IsIdentity() {
        return false
    }

    if sig.S != nil && !sig.S.IsZero() {
        return false
    }

    return true
}

// GetSignerAccounts returns accounts that need to sign this transaction
func (tx *SolanaTransaction) GetSignerAccounts() []SolanaAddress {
    numSigners := int(tx.Message.Header.NumRequiredSignatures)
    if numSigners > len(tx.Message.AccountKeys) {
        return nil
    }
    
    return tx.Message.AccountKeys[:numSigners]
}

// AddSignature adds a signature at the specified index
func (tx *SolanaTransaction) AddSignature(index int, signature SolanaSignature) error {
    if index < 0 || index >= len(tx.Signatures) {
        return fmt.Errorf("signature index %d out of range [0, %d)", index, len(tx.Signatures))
    }
    
    tx.Signatures[index] = signature
    return nil
}

// GetFeePayerIndex returns the index of the fee payer (always 0)
func (tx *SolanaTransaction) GetFeePayerIndex() int {
    return 0
}

// GetFeePayer returns the fee payer address
func (tx *SolanaTransaction) GetFeePayer() SolanaAddress {
    if len(tx.Message.AccountKeys) == 0 {
        return SolanaAddress{}
    }
    return tx.Message.AccountKeys[0]
}

// EstimateSize estimates the serialized size of the transaction
func (tx *SolanaTransaction) EstimateSize() int {
    size := 1 // signature count
    size += len(tx.Signatures) * 64 // signatures (64 bytes each)
    
    // Message size estimation
    size += 3 // header
    size += 1 // account keys count
    size += len(tx.Message.AccountKeys) * 32 // account keys
    size += 32 // recent blockhash
    size += 1 // instructions count
    
    for _, instruction := range tx.Message.Instructions {
        size += 1 // program ID index
        size += 1 // account indices count
        size += len(instruction.AccountIndices) // account indices
        size += 4 // data length
        size += len(instruction.Data) // data
    }
    
    return size
}

// Clone creates a deep copy of the transaction
func (tx *SolanaTransaction) Clone() *SolanaTransaction {
    clone := &SolanaTransaction{
        Message:    tx.Message.Clone(),
        Signatures: make([]SolanaSignature, len(tx.Signatures)),
    }
    
    copy(clone.Signatures, tx.Signatures)
    return clone
}

// Clone creates a deep copy of the message
func (msg *SolanaMessage) Clone() *SolanaMessage {
    clone := &SolanaMessage{
        Header:          msg.Header,
        AccountKeys:     make([]SolanaAddress, len(msg.AccountKeys)),
        RecentBlockhash: msg.RecentBlockhash,
        Instructions:    make([]CompiledInstruction, len(msg.Instructions)),
    }
    
    copy(clone.AccountKeys, msg.AccountKeys)
    
    for i, instruction := range msg.Instructions {
        clone.Instructions[i] = CompiledInstruction{
            ProgramIDIndex: instruction.ProgramIDIndex,
            AccountIndices: make([]uint8, len(instruction.AccountIndices)),
            Data:           make([]byte, len(instruction.Data)),
        }
        copy(clone.Instructions[i].AccountIndices, instruction.AccountIndices)
        copy(clone.Instructions[i].Data, instruction.Data)
    }
    
    return clone
}
