package frost

import (
    "encoding/binary"
    "fmt"
)

// Well-known Solana program addresses
var (
    SystemProgramID = SolanaAddress{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    TokenProgramID  = SolanaAddress{6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169}
    AssociatedTokenProgramID = SolanaAddress{140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89}
)

// SolanaTransactionBuilder helps build Solana transactions
type SolanaTransactionBuilder struct {
    instructions    []*SolanaInstruction
    signers         []SolanaAddress
    feePayer        SolanaAddress
    recentBlockhash SolanaAddress
}

// NewSolanaTransactionBuilder creates a new transaction builder
func NewSolanaTransactionBuilder() *SolanaTransactionBuilder {
    return &SolanaTransactionBuilder{
        instructions: make([]*SolanaInstruction, 0),
        signers:      make([]SolanaAddress, 0),
    }
}

// SetFeePayer sets the transaction fee payer
func (builder *SolanaTransactionBuilder) SetFeePayer(feePayer SolanaAddress) *SolanaTransactionBuilder {
    builder.feePayer = feePayer
    return builder
}

// SetRecentBlockhash sets the recent blockhash
func (builder *SolanaTransactionBuilder) SetRecentBlockhash(blockhash SolanaAddress) *SolanaTransactionBuilder {
    builder.recentBlockhash = blockhash
    return builder
}

// AddInstruction adds an instruction to the transaction
func (builder *SolanaTransactionBuilder) AddInstruction(instruction *SolanaInstruction) *SolanaTransactionBuilder {
    builder.instructions = append(builder.instructions, instruction)
    
    // Collect signers from instruction accounts
    for _, account := range instruction.Accounts {
        if account.IsSigner && !builder.containsSigner(account.PublicKey) {
            builder.signers = append(builder.signers, account.PublicKey)
        }
    }
    
    return builder
}

// containsSigner checks if a signer is already in the list
func (builder *SolanaTransactionBuilder) containsSigner(signer SolanaAddress) bool {
    for _, s := range builder.signers {
        if s.Equal(signer) {
            return true
        }
    }
    return false
}

// Build creates the final transaction
func (builder *SolanaTransactionBuilder) Build() (*SolanaTransaction, error) {
    if builder.feePayer.IsZero() {
        return nil, fmt.Errorf("fee payer must be set")
    }
    
    if builder.recentBlockhash.IsZero() {
        return nil, fmt.Errorf("recent blockhash must be set")
    }
    
    if len(builder.instructions) == 0 {
        return nil, fmt.Errorf("at least one instruction is required")
    }
    
    // Collect all unique accounts
    accountMap := make(map[SolanaAddress]bool)
    var allAccounts []SolanaAddress
    
    // Fee payer is always first and a signer
    accountMap[builder.feePayer] = true
    allAccounts = append(allAccounts, builder.feePayer)
    
    // Add other signers (excluding fee payer)
    for _, signer := range builder.signers {
        if !signer.Equal(builder.feePayer) && !accountMap[signer] {
            accountMap[signer] = true
            allAccounts = append(allAccounts, signer)
        }
    }
    
    // Add non-signer accounts
    for _, instruction := range builder.instructions {
        // Add program ID
        if !accountMap[instruction.ProgramID] {
            accountMap[instruction.ProgramID] = true
            allAccounts = append(allAccounts, instruction.ProgramID)
        }
        
        // Add instruction accounts
        for _, account := range instruction.Accounts {
            if !account.IsSigner && !accountMap[account.PublicKey] {
                accountMap[account.PublicKey] = true
                allAccounts = append(allAccounts, account.PublicKey)
            }
        }
    }
    
    // Create account index map
    accountIndexMap := make(map[SolanaAddress]uint8)
    for i, account := range allAccounts {
        accountIndexMap[account] = uint8(i)
    }
    
    // Count account types
    numSigners := len(builder.signers)
    if !builder.containsSigner(builder.feePayer) {
        numSigners++ // Fee payer is always a signer
    }
    
    // Compile instructions
    var compiledInstructions []CompiledInstruction
    for _, instruction := range builder.instructions {
        programIndex, exists := accountIndexMap[instruction.ProgramID]
        if !exists {
            return nil, fmt.Errorf("program ID not found in account list")
        }
        
        var accountIndices []uint8
        for _, account := range instruction.Accounts {
            index, exists := accountIndexMap[account.PublicKey]
            if !exists {
                return nil, fmt.Errorf("account not found in account list")
            }
            accountIndices = append(accountIndices, index)
        }
        
        compiledInstructions = append(compiledInstructions, CompiledInstruction{
            ProgramIDIndex: programIndex,
            AccountIndices: accountIndices,
            Data:           instruction.Data,
        })
    }
    
    // Calculate readonly account counts
    numReadonlySignedAccounts := uint8(0)
    numReadonlyUnsignedAccounts := uint8(0)

    for i, account := range allAccounts {
        isSigner := i < numSigners
        isWritable := false

        // Check if account is writable by examining all instructions
        for _, instruction := range compiledInstructions {
            for _, accountIndex := range instruction.AccountIndices {
                if accountIndex == uint8(i) {
                    // Check if this account is marked as writable in any instruction
                    // For now, we'll assume accounts in instructions are writable unless proven otherwise
                    // This is a simplified heuristic - in practice, you'd need instruction-specific logic
                    isWritable = true
                    break
                }
            }
            if isWritable {
                break
            }
        }

        if !isWritable {
            if isSigner {
                numReadonlySignedAccounts++
            } else {
                numReadonlyUnsignedAccounts++
            }
        }

        _ = account // Suppress unused variable warning
    }

    // Create message
    message := &SolanaMessage{
        Header: MessageHeader{
            NumRequiredSignatures:       uint8(numSigners),
            NumReadonlySignedAccounts:   numReadonlySignedAccounts,
            NumReadonlyUnsignedAccounts: numReadonlyUnsignedAccounts,
        },
        AccountKeys:     allAccounts,
        RecentBlockhash: builder.recentBlockhash,
        Instructions:    compiledInstructions,
    }
    
    return NewSolanaTransaction(message), nil
}

// CreateTransferInstruction creates a SOL transfer instruction
func CreateTransferInstruction(from, to SolanaAddress, lamports uint64) *SolanaInstruction {
    // System program transfer instruction
    // Instruction data: [2, 0, 0, 0] + lamports (8 bytes little endian)
    data := make([]byte, 12)
    binary.LittleEndian.PutUint32(data[0:4], 2) // Transfer instruction
    binary.LittleEndian.PutUint64(data[4:12], lamports)
    
    accounts := []*AccountMeta{
        NewAccountMeta(from, true, true),   // From account (signer, writable)
        NewAccountMeta(to, false, true),    // To account (writable)
    }
    
    return NewSolanaInstruction(SystemProgramID, accounts, data)
}

// CreateAccountInstruction creates a new account instruction
func CreateAccountInstruction(from, newAccount SolanaAddress, lamports uint64, space uint64, owner SolanaAddress) *SolanaInstruction {
    // System program create account instruction
    data := make([]byte, 52)
    binary.LittleEndian.PutUint32(data[0:4], 0) // CreateAccount instruction
    binary.LittleEndian.PutUint64(data[4:12], lamports)
    binary.LittleEndian.PutUint64(data[12:20], space)
    copy(data[20:52], owner.Bytes())
    
    accounts := []*AccountMeta{
        NewAccountMeta(from, true, true),       // Funding account (signer, writable)
        NewAccountMeta(newAccount, true, true), // New account (signer, writable)
    }
    
    return NewSolanaInstruction(SystemProgramID, accounts, data)
}

// CreateTokenTransferInstruction creates an SPL token transfer instruction
func CreateTokenTransferInstruction(source, destination, authority SolanaAddress, amount uint64) *SolanaInstruction {
    // SPL Token transfer instruction
    data := make([]byte, 9)
    data[0] = 3 // Transfer instruction
    binary.LittleEndian.PutUint64(data[1:9], amount)
    
    accounts := []*AccountMeta{
        NewAccountMeta(source, false, true),      // Source token account (writable)
        NewAccountMeta(destination, false, true), // Destination token account (writable)
        NewAccountMeta(authority, true, false),   // Authority (signer)
    }
    
    return NewSolanaInstruction(TokenProgramID, accounts, data)
}

// CreateAssociatedTokenAccountInstruction creates an associated token account
func CreateAssociatedTokenAccountInstruction(payer, associatedTokenAddress, owner, mint SolanaAddress) *SolanaInstruction {
    // Associated Token Program create instruction (no instruction data needed)
    accounts := []*AccountMeta{
        NewAccountMeta(payer, true, true),                    // Payer (signer, writable)
        NewAccountMeta(associatedTokenAddress, false, true),  // Associated token account (writable)
        NewAccountMeta(owner, false, false),                  // Owner
        NewAccountMeta(mint, false, false),                   // Mint
        NewAccountMeta(SystemProgramID, false, false),        // System program
        NewAccountMeta(TokenProgramID, false, false),         // Token program
    }
    
    return NewSolanaInstruction(AssociatedTokenProgramID, accounts, []byte{})
}

// CreateCustomProgramInstruction creates a custom program instruction
func CreateCustomProgramInstruction(programID SolanaAddress, accounts []*AccountMeta, data []byte) *SolanaInstruction {
    return NewSolanaInstruction(programID, accounts, data)
}

// Helper methods for common transaction types

// BuildTransferTransaction builds a simple SOL transfer transaction
func BuildTransferTransaction(from, to SolanaAddress, lamports uint64, recentBlockhash SolanaAddress) (*SolanaTransaction, error) {
    builder := NewSolanaTransactionBuilder()
    
    transferInstruction := CreateTransferInstruction(from, to, lamports)
    
    return builder.
        SetFeePayer(from).
        SetRecentBlockhash(recentBlockhash).
        AddInstruction(transferInstruction).
        Build()
}

// BuildTokenTransferTransaction builds an SPL token transfer transaction
func BuildTokenTransferTransaction(
    sourceTokenAccount, destinationTokenAccount, authority SolanaAddress,
    amount uint64,
    recentBlockhash SolanaAddress,
) (*SolanaTransaction, error) {
    builder := NewSolanaTransactionBuilder()
    
    transferInstruction := CreateTokenTransferInstruction(
        sourceTokenAccount,
        destinationTokenAccount,
        authority,
        amount,
    )
    
    return builder.
        SetFeePayer(authority).
        SetRecentBlockhash(recentBlockhash).
        AddInstruction(transferInstruction).
        Build()
}

// BuildCreateAccountTransaction builds a create account transaction
func BuildCreateAccountTransaction(
    from, newAccount SolanaAddress,
    lamports, space uint64,
    owner, recentBlockhash SolanaAddress,
) (*SolanaTransaction, error) {
    builder := NewSolanaTransactionBuilder()
    
    createInstruction := CreateAccountInstruction(from, newAccount, lamports, space, owner)
    
    return builder.
        SetFeePayer(from).
        SetRecentBlockhash(recentBlockhash).
        AddInstruction(createInstruction).
        Build()
}
