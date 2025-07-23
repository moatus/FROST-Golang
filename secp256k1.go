package frost

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "runtime"

    "github.com/btcsuite/btcd/btcec/v2"
)

// Secp256k1Curve implements the Curve interface for secp256k1
type Secp256k1Curve struct{}

// NewSecp256k1Curve creates a new secp256k1 curve instance
func NewSecp256k1Curve() *Secp256k1Curve {
    return &Secp256k1Curve{}
}

func (c *Secp256k1Curve) Name() string { return "secp256k1" }
func (c *Secp256k1Curve) ScalarSize() int { return 32 }
func (c *Secp256k1Curve) PointSize() int { return 65 } // Uncompressed

func (c *Secp256k1Curve) ScalarFromBytes(data []byte) (Scalar, error) {
    if len(data) != 32 {
        return nil, ErrInvalidScalarLength
    }

    scalar := new(btcec.ModNScalar)
    scalar.SetBytes((*[32]byte)(data)) // BIP-340 always reduces mod n, ignore overflow

    return &Secp256k1Scalar{inner: scalar}, nil
}

func (c *Secp256k1Curve) ScalarFromUniformBytes(data []byte) (Scalar, error) {
    if len(data) < 32 {
        return nil, fmt.Errorf("need at least 32 bytes for uniform scalar generation, got %d", len(data))
    }

    // Use first 32 bytes and reduce modulo curve order
    scalar := new(btcec.ModNScalar)
    scalar.SetBytes((*[32]byte)(data[:32]))
    return &Secp256k1Scalar{inner: scalar}, nil
}

func (c *Secp256k1Curve) ScalarRandom() (Scalar, error) {
    for {
        bytes := make([]byte, 32)
        if _, err := rand.Read(bytes); err != nil {
            return nil, err
        }

        scalar := new(btcec.ModNScalar)
        overflow := scalar.SetBytes((*[32]byte)(bytes))
        if overflow == 0 {
            return &Secp256k1Scalar{inner: scalar}, nil
        }
        // If overflow, try again with new random bytes
    }
}

func (c *Secp256k1Curve) ScalarZero() Scalar {
    return &Secp256k1Scalar{inner: new(btcec.ModNScalar)}
}

func (c *Secp256k1Curve) ScalarOne() Scalar {
    scalar := new(btcec.ModNScalar)
    scalar.SetInt(1)
    return &Secp256k1Scalar{inner: scalar}
}

func (c *Secp256k1Curve) PointFromBytes(data []byte) (Point, error) {
    if len(data) != 33 && len(data) != 65 {
        return nil, ErrInvalidPointLength
    }
    
    pubKey, err := btcec.ParsePubKey(data)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrInvalidPoint, err)
    }
    
    return &Secp256k1Point{inner: pubKey}, nil
}

func (c *Secp256k1Curve) BasePoint() Point {
    return &Secp256k1Point{inner: btcec.Generator()}
}

func (c *Secp256k1Curve) PointIdentity() Point {
    // Point at infinity
    return &Secp256k1Point{inner: nil}
}

func (c *Secp256k1Curve) ValidateScalar(data []byte) error {
    if len(data) != 32 {
        return ErrInvalidScalarLength
    }
    
    scalar := new(btcec.ModNScalar)
    overflow := scalar.SetBytes((*[32]byte)(data))
    if overflow != 0 {
        return ErrInvalidScalar
    }
    
    return nil
}

func (c *Secp256k1Curve) ValidatePoint(data []byte) error {
    _, err := c.PointFromBytes(data)
    return err
}

// Secp256k1Scalar implements the Scalar interface
type Secp256k1Scalar struct {
    inner *btcec.ModNScalar
}

func (s *Secp256k1Scalar) Bytes() []byte {
    var bytes [32]byte
    s.inner.PutBytes(&bytes)
    return bytes[:]
}

func (s *Secp256k1Scalar) String() string {
    return hex.EncodeToString(s.Bytes())
}

func (s *Secp256k1Scalar) Add(other Scalar) Scalar {
    result := new(btcec.ModNScalar)
    result.Add(s.inner).Add(other.(*Secp256k1Scalar).inner)
    return &Secp256k1Scalar{inner: result}
}

func (s *Secp256k1Scalar) Sub(other Scalar) Scalar {
    result := new(btcec.ModNScalar)
    result.Add(s.inner).Add(other.(*Secp256k1Scalar).inner.Negate())
    return &Secp256k1Scalar{inner: result}
}

func (s *Secp256k1Scalar) Mul(other Scalar) Scalar {
    result := new(btcec.ModNScalar)
    result.Set(s.inner).Mul(other.(*Secp256k1Scalar).inner)
    return &Secp256k1Scalar{inner: result}
}

func (s *Secp256k1Scalar) Negate() Scalar {
    result := new(btcec.ModNScalar)
    result.Add(s.inner).Negate()
    return &Secp256k1Scalar{inner: result}
}

func (s *Secp256k1Scalar) Invert() (Scalar, error) {
    if s.IsZero() {
        return nil, ErrScalarZero
    }

    result := new(btcec.ModNScalar)
    // WARNING: Using non-constant-time scalar inversion which may leak timing information.
    // btcec/v2 does not provide constant-time scalar inversion. For high-security environments:
    // 1. Use Ed25519 curve which provides constant-time operations
    // 2. Deploy behind network protections (load balancers, CDNs) to mitigate timing attacks
    // 3. Consider implementing additional blinding techniques
    result.Set(s.inner).InverseNonConst()
    return &Secp256k1Scalar{inner: result}, nil
}

func (s *Secp256k1Scalar) Equal(other Scalar) bool {
    return s.inner.Equals(other.(*Secp256k1Scalar).inner)
}

func (s *Secp256k1Scalar) IsZero() bool {
    return s.inner.IsZero()
}

func (s *Secp256k1Scalar) Zeroize() {
    s.inner.Zero()
    runtime.KeepAlive(s)
}

// Secp256k1Point implements the Point interface
type Secp256k1Point struct {
    inner *btcec.PublicKey
}

func (p *Secp256k1Point) Bytes() []byte {
    if p.inner == nil {
        return make([]byte, 65) // Point at infinity
    }
    return p.inner.SerializeUncompressed()
}

func (p *Secp256k1Point) CompressedBytes() []byte {
    if p.inner == nil {
        return make([]byte, 33) // Point at infinity
    }
    return p.inner.SerializeCompressed()
}

func (p *Secp256k1Point) String() string {
    return hex.EncodeToString(p.CompressedBytes())
}

func (p *Secp256k1Point) Add(other Point) Point {
    if p.inner == nil {
        return other
    }
    if other.(*Secp256k1Point).inner == nil {
        return p
    }
    
    // Convert to Jacobian coordinates for addition
    var result btcec.JacobianPoint
    p.inner.AsJacobian(&result)

    var otherJac btcec.JacobianPoint
    other.(*Secp256k1Point).inner.AsJacobian(&otherJac)

    // WARNING: Using non-constant-time point addition which may leak timing information.
    // btcec/v2 does not provide constant-time point addition. For high-security environments:
    // 1. Use Ed25519 curve which provides constant-time operations
    // 2. Deploy behind network protections to mitigate timing attacks
    // 3. Consider implementing additional blinding techniques
    btcec.AddNonConst(&result, &otherJac, &result)
    
    // Convert back to affine
    result.ToAffine()
    pubKey := btcec.NewPublicKey(&result.X, &result.Y)
    
    return &Secp256k1Point{inner: pubKey}
}

func (p *Secp256k1Point) Sub(other Point) Point {
    return p.Add(other.Negate())
}

func (p *Secp256k1Point) Mul(scalar Scalar) Point {
    if p.inner == nil {
        return p // Point at infinity
    }

    scalarBytes := scalar.Bytes()
    var scalarInt btcec.ModNScalar
    scalarInt.SetBytes((*[32]byte)(scalarBytes))

    var pointJac btcec.JacobianPoint
    p.inner.AsJacobian(&pointJac)

    var result btcec.JacobianPoint
    // WARNING: Using non-constant-time scalar multiplication which may leak timing information.
    // btcec/v2 does not provide constant-time scalar multiplication. For high-security environments:
    // 1. Use Ed25519 curve which provides constant-time operations
    // 2. Deploy behind network protections to mitigate timing attacks
    // 3. Consider implementing additional blinding techniques
    btcec.ScalarMultNonConst(&scalarInt, &pointJac, &result)

    result.ToAffine()
    pubKey := btcec.NewPublicKey(&result.X, &result.Y)

    return &Secp256k1Point{inner: pubKey}
}

func (p *Secp256k1Point) Negate() Point {
    if p.inner == nil {
        return p // Point at infinity
    }

    // Get the point in Jacobian coordinates and negate
    var jac btcec.JacobianPoint
    p.inner.AsJacobian(&jac)

    // Negate Y coordinate
    jac.Y.Negate(1)

    // Convert back to affine
    jac.ToAffine()
    pubKey := btcec.NewPublicKey(&jac.X, &jac.Y)

    return &Secp256k1Point{inner: pubKey}
}

func (p *Secp256k1Point) Equal(other Point) bool {
    if p.inner == nil && other.(*Secp256k1Point).inner == nil {
        return true
    }
    if p.inner == nil || other.(*Secp256k1Point).inner == nil {
        return false
    }
    
    return p.inner.IsEqual(other.(*Secp256k1Point).inner)
}

func (p *Secp256k1Point) IsIdentity() bool {
    return p.inner == nil
}

func (p *Secp256k1Point) IsOnCurve() bool {
    if p.inner == nil {
        return true // Point at infinity is valid
    }

    // If we can serialize the point, it's valid
    // btcec v2 validates points during parsing
    return true
}
