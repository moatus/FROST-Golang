package frost

import (
    "crypto/rand"
    "errors"
    "fmt"
)

// Curve defines the interface for elliptic curve operations
type Curve interface {
    // Metadata
    Name() string
    ScalarSize() int
    PointSize() int
    
    // Scalar operations
    ScalarFromBytes([]byte) (Scalar, error)
    ScalarFromUniformBytes([]byte) (Scalar, error)
    ScalarRandom() (Scalar, error)
    ScalarZero() Scalar
    ScalarOne() Scalar
    
    // Point operations
    PointFromBytes([]byte) (Point, error)
    BasePoint() Point
    PointIdentity() Point
    
    // Validation
    ValidateScalar([]byte) error
    ValidatePoint([]byte) error
}

// Scalar represents a scalar value in the curve's field
type Scalar interface {
    // Serialization
    Bytes() []byte
    String() string
    
    // Arithmetic operations
    Add(Scalar) Scalar
    Sub(Scalar) Scalar
    Mul(Scalar) Scalar
    Negate() Scalar
    Invert() (Scalar, error)
    
    // Comparison
    Equal(Scalar) bool
    IsZero() bool
    
    // Security
    Zeroize()
}

// Point represents a point on the elliptic curve
type Point interface {
    // Serialization
    Bytes() []byte
    CompressedBytes() []byte
    String() string
    
    // Arithmetic operations
    Add(Point) Point
    Sub(Point) Point
    Mul(Scalar) Point
    Negate() Point
    
    // Comparison
    Equal(Point) bool
    IsIdentity() bool
    
    // Validation
    IsOnCurve() bool
}

// CurveType represents supported curve types
type CurveType string

const (
    Secp256k1 CurveType = "secp256k1"
    Ed25519   CurveType = "ed25519"
)

// NewCurve creates a new curve instance
func NewCurve(curveType CurveType) (Curve, error) {
    switch curveType {
    case Secp256k1:
        return NewSecp256k1Curve(), nil
    case Ed25519:
        return NewEd25519Curve(), nil
    default:
        return nil, fmt.Errorf("unsupported curve type: %s", curveType)
    }
}

// Common errors
var (
    ErrInvalidScalarLength = errors.New("invalid scalar length")
    ErrInvalidPointLength  = errors.New("invalid point length")
    ErrInvalidScalar       = errors.New("invalid scalar value")
    ErrInvalidPoint        = errors.New("invalid point")
    ErrPointNotOnCurve     = errors.New("point not on curve")
    ErrScalarZero          = errors.New("scalar is zero")
)

// SecureRandom generates cryptographically secure random bytes
func SecureRandom(size int) ([]byte, error) {
    bytes := make([]byte, size)
    _, err := rand.Read(bytes)
    return bytes, err
}
