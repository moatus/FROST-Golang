package frost

import (
    "crypto/sha256"
    "encoding/binary"
    "fmt"
)

// SystemProgram provides methods for interacting with Solana's System Program
type SystemProgram struct{}

// NewSystemProgram creates a new SystemProgram instance
func NewSystemProgram() *SystemProgram {
    return &SystemProgram{}
}

// Transfer creates a SOL transfer instruction
func (sp *SystemProgram) Transfer(from, to SolanaAddress, lamports uint64) *SolanaInstruction {
    return CreateTransferInstruction(from, to, lamports)
}

// CreateAccount creates a new account instruction
func (sp *SystemProgram) CreateAccount(from, newAccount SolanaAddress, lamports, space uint64, owner SolanaAddress) *SolanaInstruction {
    return CreateAccountInstruction(from, newAccount, lamports, space, owner)
}

// Allocate creates an allocate instruction
func (sp *SystemProgram) Allocate(account SolanaAddress, space uint64) *SolanaInstruction {
    data := make([]byte, 12)
    binary.LittleEndian.PutUint32(data[0:4], 8) // Allocate instruction
    binary.LittleEndian.PutUint64(data[4:12], space)
    
    accounts := []*AccountMeta{
        NewAccountMeta(account, true, true), // Account to allocate (signer, writable)
    }
    
    return NewSolanaInstruction(SystemProgramID, accounts, data)
}

// Assign creates an assign instruction
func (sp *SystemProgram) Assign(account, owner SolanaAddress) *SolanaInstruction {
    data := make([]byte, 36)
    binary.LittleEndian.PutUint32(data[0:4], 1) // Assign instruction
    copy(data[4:36], owner.Bytes())
    
    accounts := []*AccountMeta{
        NewAccountMeta(account, true, true), // Account to assign (signer, writable)
    }
    
    return NewSolanaInstruction(SystemProgramID, accounts, data)
}

// TokenProgram provides methods for interacting with SPL Token Program
type TokenProgram struct{}

// NewTokenProgram creates a new TokenProgram instance
func NewTokenProgram() *TokenProgram {
    return &TokenProgram{}
}

// Transfer creates a token transfer instruction
func (tp *TokenProgram) Transfer(source, destination, authority SolanaAddress, amount uint64) *SolanaInstruction {
    return CreateTokenTransferInstruction(source, destination, authority, amount)
}

// InitializeMint creates an initialize mint instruction
func (tp *TokenProgram) InitializeMint(mint, mintAuthority, freezeAuthority SolanaAddress, decimals uint8) *SolanaInstruction {
    data := make([]byte, 67)
    data[0] = 0 // InitializeMint instruction
    data[1] = decimals
    copy(data[2:34], mintAuthority.Bytes())
    
    // Freeze authority (optional)
    if !freezeAuthority.IsZero() {
        data[34] = 1 // COption::Some
        copy(data[35:67], freezeAuthority.Bytes())
    } else {
        data[34] = 0 // COption::None
    }
    
    accounts := []*AccountMeta{
        NewAccountMeta(mint, false, true),                                    // Mint account (writable)
        NewAccountMeta(SolanaAddress{6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161, 253, 68, 227, 219, 217, 138, 0, 0, 0, 0}, false, false), // Rent sysvar
    }
    
    return NewSolanaInstruction(TokenProgramID, accounts, data)
}

// InitializeAccount creates an initialize token account instruction
func (tp *TokenProgram) InitializeAccount(account, mint, owner SolanaAddress) *SolanaInstruction {
    data := []byte{1} // InitializeAccount instruction
    
    accounts := []*AccountMeta{
        NewAccountMeta(account, false, true),                                 // Token account (writable)
        NewAccountMeta(mint, false, false),                                   // Mint
        NewAccountMeta(owner, false, false),                                  // Owner
        NewAccountMeta(SolanaAddress{6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161, 253, 68, 227, 219, 217, 138, 0, 0, 0, 0}, false, false), // Rent sysvar
    }
    
    return NewSolanaInstruction(TokenProgramID, accounts, data)
}

// MintTo creates a mint to instruction
func (tp *TokenProgram) MintTo(mint, destination, authority SolanaAddress, amount uint64) *SolanaInstruction {
    data := make([]byte, 9)
    data[0] = 7 // MintTo instruction
    binary.LittleEndian.PutUint64(data[1:9], amount)
    
    accounts := []*AccountMeta{
        NewAccountMeta(mint, false, true),        // Mint (writable)
        NewAccountMeta(destination, false, true), // Destination account (writable)
        NewAccountMeta(authority, true, false),   // Mint authority (signer)
    }
    
    return NewSolanaInstruction(TokenProgramID, accounts, data)
}

// Burn creates a burn instruction
func (tp *TokenProgram) Burn(account, mint, authority SolanaAddress, amount uint64) *SolanaInstruction {
    data := make([]byte, 9)
    data[0] = 8 // Burn instruction
    binary.LittleEndian.PutUint64(data[1:9], amount)
    
    accounts := []*AccountMeta{
        NewAccountMeta(account, false, true),   // Token account (writable)
        NewAccountMeta(mint, false, true),      // Mint (writable)
        NewAccountMeta(authority, true, false), // Authority (signer)
    }
    
    return NewSolanaInstruction(TokenProgramID, accounts, data)
}

// AssociatedTokenProgram provides methods for associated token accounts
type AssociatedTokenProgram struct{}

// NewAssociatedTokenProgram creates a new AssociatedTokenProgram instance
func NewAssociatedTokenProgram() *AssociatedTokenProgram {
    return &AssociatedTokenProgram{}
}

// CreateAssociatedTokenAccount creates an associated token account instruction
func (atp *AssociatedTokenProgram) CreateAssociatedTokenAccount(payer, associatedTokenAddress, owner, mint SolanaAddress) *SolanaInstruction {
    return CreateAssociatedTokenAccountInstruction(payer, associatedTokenAddress, owner, mint)
}

// DeriveAssociatedTokenAddress derives the associated token account address
func (atp *AssociatedTokenProgram) DeriveAssociatedTokenAddress(owner, mint SolanaAddress) (SolanaAddress, error) {
    // This is a simplified version - in practice, you'd use the full PDA derivation
    seeds := [][]byte{
        owner.Bytes(),
        TokenProgramID.Bytes(),
        mint.Bytes(),
    }
    
    return atp.findProgramAddress(seeds, AssociatedTokenProgramID)
}

// findProgramAddress finds a program derived address
func (atp *AssociatedTokenProgram) findProgramAddress(seeds [][]byte, programID SolanaAddress) (SolanaAddress, error) {
    // Simplified PDA derivation - in practice, this would be more complex
    hasher := sha256.New()
    for _, seed := range seeds {
        hasher.Write(seed)
    }
    hasher.Write(programID.Bytes())
    hasher.Write([]byte("ProgramDerivedAddress"))
    
    hash := hasher.Sum(nil)
    var addr SolanaAddress
    copy(addr[:], hash[:32])
    
    return addr, nil
}

// CustomProgram provides a generic interface for custom program interactions
type CustomProgram struct {
    ProgramID SolanaAddress
}

// NewCustomProgram creates a new CustomProgram instance
func NewCustomProgram(programID SolanaAddress) *CustomProgram {
    return &CustomProgram{
        ProgramID: programID,
    }
}

// CreateInstruction creates a custom program instruction
func (cp *CustomProgram) CreateInstruction(accounts []*AccountMeta, data []byte) *SolanaInstruction {
    return NewSolanaInstruction(cp.ProgramID, accounts, data)
}

// Call creates a generic program call instruction
func (cp *CustomProgram) Call(method string, accounts []*AccountMeta, args []byte) *SolanaInstruction {
    // Create instruction data with method selector
    methodHash := sha256.Sum256([]byte(method))
    data := make([]byte, 8+len(args))
    copy(data[:8], methodHash[:8]) // Use first 8 bytes as method selector
    copy(data[8:], args)
    
    return NewSolanaInstruction(cp.ProgramID, accounts, data)
}

// ProgramManager manages multiple program interfaces
type ProgramManager struct {
    SystemProgram          *SystemProgram
    TokenProgram           *TokenProgram
    AssociatedTokenProgram *AssociatedTokenProgram
    customPrograms         map[string]*CustomProgram
}

// NewProgramManager creates a new ProgramManager
func NewProgramManager() *ProgramManager {
    return &ProgramManager{
        SystemProgram:          NewSystemProgram(),
        TokenProgram:           NewTokenProgram(),
        AssociatedTokenProgram: NewAssociatedTokenProgram(),
        customPrograms:         make(map[string]*CustomProgram),
    }
}

// AddCustomProgram adds a custom program to the manager
func (pm *ProgramManager) AddCustomProgram(name string, programID SolanaAddress) {
    pm.customPrograms[name] = NewCustomProgram(programID)
}

// GetCustomProgram retrieves a custom program by name
func (pm *ProgramManager) GetCustomProgram(name string) (*CustomProgram, error) {
    program, exists := pm.customPrograms[name]
    if !exists {
        return nil, fmt.Errorf("custom program '%s' not found", name)
    }
    return program, nil
}

// CreateMultiSigTransaction creates a transaction with multiple instructions
func (pm *ProgramManager) CreateMultiSigTransaction(
    instructions []*SolanaInstruction,
    feePayer SolanaAddress,
    recentBlockhash SolanaAddress,
) (*SolanaTransaction, error) {
    builder := NewSolanaTransactionBuilder()
    builder.SetFeePayer(feePayer).SetRecentBlockhash(recentBlockhash)
    
    for _, instruction := range instructions {
        builder.AddInstruction(instruction)
    }
    
    return builder.Build()
}

// Common program addresses and constants
var (
    // Rent sysvar address
    RentSysvarID = SolanaAddress{6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161, 253, 68, 227, 219, 217, 138, 0, 0, 0, 0}
    
    // Clock sysvar address
    ClockSysvarID = SolanaAddress{6, 167, 213, 23, 25, 44, 86, 142, 224, 138, 132, 95, 115, 210, 151, 136, 207, 3, 92, 8, 205, 85, 86, 157, 90, 249, 121, 197, 0, 0, 0, 0}
    
    // Common token amounts
    LAMPORTS_PER_SOL = uint64(1_000_000_000)
)

// Helper functions for common operations

// SOLToLamports converts SOL to lamports
func SOLToLamports(sol float64) uint64 {
    return uint64(sol * float64(LAMPORTS_PER_SOL))
}

// LamportsToSOL converts lamports to SOL
func LamportsToSOL(lamports uint64) float64 {
    return float64(lamports) / float64(LAMPORTS_PER_SOL)
}

// IsSystemProgram checks if an address is the system program
func IsSystemProgram(address SolanaAddress) bool {
    return address.Equal(SystemProgramID)
}

// IsTokenProgram checks if an address is the token program
func IsTokenProgram(address SolanaAddress) bool {
    return address.Equal(TokenProgramID)
}

// IsAssociatedTokenProgram checks if an address is the associated token program
func IsAssociatedTokenProgram(address SolanaAddress) bool {
    return address.Equal(AssociatedTokenProgramID)
}
