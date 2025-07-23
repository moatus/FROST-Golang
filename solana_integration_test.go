package frost

import (
    "crypto/rand"
    "testing"
)

// TestSolanaTransactionBuilding tests complete transaction building
func TestSolanaTransactionBuilding(t *testing.T) {
    // Create test addresses
    from := createTestAddress(t)
    to := createTestAddress(t)
    recentBlockhash := createTestAddress(t)
    
    // Build transfer transaction
    tx, err := BuildTransferTransaction(from, to, SOLToLamports(1.5), recentBlockhash)
    if err != nil {
        t.Fatalf("Failed to build transfer transaction: %v", err)
    }
    
    // Validate transaction structure
    if tx.Message == nil {
        t.Fatal("Transaction message should not be nil")
    }
    
    if len(tx.Message.Instructions) != 1 {
        t.Errorf("Expected 1 instruction, got %d", len(tx.Message.Instructions))
    }
    
    if len(tx.Message.AccountKeys) < 2 {
        t.Errorf("Expected at least 2 accounts, got %d", len(tx.Message.AccountKeys))
    }
    
    // Verify fee payer is first account
    if !tx.Message.AccountKeys[0].Equal(from) {
        t.Error("Fee payer should be first account")
    }
    
    // Verify recent blockhash
    if !tx.Message.RecentBlockhash.Equal(recentBlockhash) {
        t.Error("Recent blockhash should match")
    }
    
    t.Log("✅ Transaction building test passed")
}

// TestSolanaTransactionSigning tests complete transaction signing
func TestSolanaTransactionSigning(t *testing.T) {
    curve := NewEd25519Curve()
    
    // Generate key pair
    privateKey, publicKey, err := SolanaKeyGeneration()
    if err != nil {
        t.Fatalf("Failed to generate key pair: %v", err)
    }
    defer privateKey.Zeroize()
    
    // Create addresses
    from := addressFromPoint(publicKey)
    to := createTestAddress(t)
    recentBlockhash := createTestAddress(t)
    
    // Build transaction
    tx, err := BuildTransferTransaction(from, to, SOLToLamports(0.1), recentBlockhash)
    if err != nil {
        t.Fatalf("Failed to build transaction: %v", err)
    }
    
    // Get message hash
    messageHash, err := tx.Message.Hash()
    if err != nil {
        t.Fatalf("Failed to compute message hash: %v", err)
    }
    if messageHash == nil {
        t.Fatal("Message hash should not be nil")
    }
    
    // Generate nonce for signing
    nonce, err := curve.ScalarRandom()
    if err != nil {
        t.Fatalf("Failed to generate nonce: %v", err)
    }
    defer nonce.Zeroize()
    
    commitment := curve.BasePoint().Mul(nonce)
    
    // Compute Solana challenge
    challenge, err := SolanaChallenge(commitment, publicKey, messageHash)
    if err != nil {
        t.Fatalf("Failed to compute challenge: %v", err)
    }
    defer challenge.Zeroize()
    
    // Compute signature response
    response, err := SolanaSignResponse(nonce, privateKey, challenge)
    if err != nil {
        t.Fatalf("Failed to compute signature response: %v", err)
    }
    defer response.Zeroize()
    
    // Create signature
    signature := SolanaSignature{
        R: commitment,
        S: response,
    }
    
    // Add signature to transaction
    err = tx.AddSignature(0, signature)
    if err != nil {
        t.Fatalf("Failed to add signature: %v", err)
    }
    
    // Verify transaction is signed
    if !tx.IsSigned() {
        t.Error("Transaction should be signed")
    }
    
    // Verify signature
    err = VerifySolanaSignature(&signature, publicKey, messageHash)
    if err != nil {
        t.Errorf("Signature verification failed: %v", err)
    }
    
    t.Log("✅ Transaction signing test passed")
}

// TestSolanaTokenTransactions tests SPL token transaction building
func TestSolanaTokenTransactions(t *testing.T) {
    // Create test addresses
    sourceTokenAccount := createTestAddress(t)
    destinationTokenAccount := createTestAddress(t)
    authority := createTestAddress(t)
    recentBlockhash := createTestAddress(t)
    
    // Build token transfer transaction
    tx, err := BuildTokenTransferTransaction(
        sourceTokenAccount,
        destinationTokenAccount,
        authority,
        1000000, // 1 token with 6 decimals
        recentBlockhash,
    )
    if err != nil {
        t.Fatalf("Failed to build token transfer transaction: %v", err)
    }
    
    // Validate transaction
    if len(tx.Message.Instructions) != 1 {
        t.Errorf("Expected 1 instruction, got %d", len(tx.Message.Instructions))
    }
    
    // Verify instruction is for token program
    instruction := tx.Message.Instructions[0]
    programIndex := instruction.ProgramIDIndex
    if int(programIndex) >= len(tx.Message.AccountKeys) {
        t.Fatal("Invalid program index")
    }
    
    programID := tx.Message.AccountKeys[programIndex]
    if !programID.Equal(TokenProgramID) {
        t.Error("Instruction should be for token program")
    }
    
    // Verify instruction data (should start with transfer instruction code)
    if len(instruction.Data) == 0 || instruction.Data[0] != 3 {
        t.Error("Instruction should be token transfer (code 3)")
    }
    
    t.Log("✅ Token transaction test passed")
}

// TestSolanaCustomPrograms tests custom program interactions
func TestSolanaCustomPrograms(t *testing.T) {
    // Create custom program
    customProgramID := createTestAddress(t)
    customProgram := NewCustomProgram(customProgramID)
    
    // Create test accounts
    account1 := createTestAddress(t)
    account2 := createTestAddress(t)
    
    accounts := []*AccountMeta{
        NewAccountMeta(account1, true, true),   // Signer, writable
        NewAccountMeta(account2, false, false), // Readonly
    }
    
    // Create custom instruction
    instructionData := []byte{1, 2, 3, 4, 5} // Custom data
    instruction := customProgram.CreateInstruction(accounts, instructionData)
    
    // Verify instruction
    if !instruction.ProgramID.Equal(customProgramID) {
        t.Error("Instruction should have correct program ID")
    }
    
    if len(instruction.Accounts) != 2 {
        t.Errorf("Expected 2 accounts, got %d", len(instruction.Accounts))
    }
    
    if len(instruction.Data) != 5 {
        t.Errorf("Expected 5 bytes of data, got %d", len(instruction.Data))
    }
    
    // Test method call
    methodInstruction := customProgram.Call("transfer", accounts, []byte{100, 200})
    
    // Verify method call instruction
    if len(methodInstruction.Data) < 8 {
        t.Error("Method call should have at least 8 bytes (method selector)")
    }
    
    t.Log("✅ Custom program test passed")
}

// TestSolanaAddressOperations tests address operations
func TestSolanaAddressOperations(t *testing.T) {
    // Test address creation from bytes
    testBytes := make([]byte, 32)
    rand.Read(testBytes)
    
    addr, err := NewSolanaAddress(testBytes)
    if err != nil {
        t.Fatalf("Failed to create address: %v", err)
    }
    
    // Test bytes round-trip
    if !equalBytes(addr.Bytes(), testBytes) {
        t.Error("Address bytes should match original")
    }
    
    // Test string representation
    addrStr := addr.String()
    if len(addrStr) == 0 {
        t.Error("Address string should not be empty")
    }
    
    // Test address from hex
    addr2, err := NewSolanaAddressFromHex(addrStr)
    if err != nil {
        t.Fatalf("Failed to create address from hex: %v", err)
    }

    if !addr.Equal(*addr2) {
        t.Error("Addresses should be equal after hex round-trip")
    }
    
    // Test zero address
    zeroAddr := SolanaAddress{}
    if !zeroAddr.IsZero() {
        t.Error("Zero address should be detected as zero")
    }
    
    if addr.IsZero() {
        t.Error("Non-zero address should not be detected as zero")
    }
    
    t.Log("✅ Address operations test passed")
}

// TestSolanaTransactionSerialization tests transaction serialization
func TestSolanaTransactionSerialization(t *testing.T) {
    // Create test transaction
    from := createTestAddress(t)
    to := createTestAddress(t)
    recentBlockhash := createTestAddress(t)
    
    tx, err := BuildTransferTransaction(from, to, SOLToLamports(1.0), recentBlockhash)
    if err != nil {
        t.Fatalf("Failed to build transaction: %v", err)
    }
    
    // Add dummy signature with valid R and S components
    curve := NewEd25519Curve()
    dummyR := curve.BasePoint()
    dummyS, _ := curve.ScalarRandom()
    dummySignature := SolanaSignature{
        R: dummyR,
        S: dummyS,
    }
    err = tx.AddSignature(0, dummySignature)
    if err != nil {
        t.Fatalf("Failed to add signature: %v", err)
    }
    
    // Serialize transaction
    serialized, err := tx.Serialize()
    if err != nil {
        t.Fatalf("Failed to serialize transaction: %v", err)
    }
    
    if len(serialized) == 0 {
        t.Error("Serialized transaction should not be empty")
    }
    
    // Verify serialization includes signature count
    if serialized[0] != 1 {
        t.Errorf("Expected 1 signature, got %d", serialized[0])
    }
    
    // Verify signature is included (64 bytes after count)
    if len(serialized) < 65 { // 1 byte count + 64 bytes signature
        t.Error("Serialized transaction should include signature")
    }
    
    t.Log("✅ Transaction serialization test passed")
}

// Helper functions

func createTestAddress(t *testing.T) SolanaAddress {
    var addr SolanaAddress
    _, err := rand.Read(addr[:])
    if err != nil {
        t.Fatalf("Failed to create test address: %v", err)
    }
    return addr
}

func addressFromPoint(point Point) SolanaAddress {
    bytes := point.CompressedBytes()
    var addr SolanaAddress
    copy(addr[:], bytes)
    return addr
}

func equalBytes(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}
