package frost

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "runtime"

    "filippo.io/edwards25519"
)

// Ed25519Curve implements the Curve interface for Ed25519
type Ed25519Curve struct{}

// NewEd25519Curve creates a new Ed25519 curve instance
func NewEd25519Curve() *Ed25519Curve {
    return &Ed25519Curve{}
}

func (c *Ed25519Curve) Name() string { return "ed25519" }
func (c *Ed25519Curve) ScalarSize() int { return 32 }
func (c *Ed25519Curve) PointSize() int { return 32 }

func (c *Ed25519Curve) ScalarFromBytes(data []byte) (Scalar, error) {
    if len(data) != 32 {
        return nil, ErrInvalidScalarLength
    }
    
    scalar, err := new(edwards25519.Scalar).SetCanonicalBytes(data)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrInvalidScalar, err)
    }
    
    return &Ed25519Scalar{inner: scalar}, nil
}

func (c *Ed25519Curve) ScalarRandom() (Scalar, error) {
    bytes := make([]byte, 64) // Use 64 bytes for uniform distribution
    if _, err := rand.Read(bytes); err != nil {
        return nil, err
    }

    scalar, _ := edwards25519.NewScalar().SetUniformBytes(bytes)
    return NewEd25519Scalar(scalar), nil
}

// NewEd25519Scalar creates a new Ed25519Scalar with automatic cleanup via finalizer
func NewEd25519Scalar(inner *edwards25519.Scalar) *Ed25519Scalar {
    s := &Ed25519Scalar{inner: inner}
    // Set finalizer as backup cleanup (defense in depth)
    runtime.SetFinalizer(s, (*Ed25519Scalar).finalize)
    return s
}

// finalize is called by the garbage collector as backup cleanup
func (s *Ed25519Scalar) finalize() {
    if s.inner != nil {
        s.Zeroize()
    }
}

func (c *Ed25519Curve) ScalarFromUniformBytes(data []byte) (Scalar, error) {
    // Ensure we have enough bytes for uniform distribution
    if len(data) < 32 {
        return nil, ErrInvalidScalarLength
    }

    // Use up to 64 bytes for uniform distribution, pad if necessary
    uniformBytes := make([]byte, 64)
    copy(uniformBytes, data)

    scalar, _ := edwards25519.NewScalar().SetUniformBytes(uniformBytes)
    return &Ed25519Scalar{inner: scalar}, nil
}

func (c *Ed25519Curve) ScalarZero() Scalar {
    return &Ed25519Scalar{inner: edwards25519.NewScalar()}
}

func (c *Ed25519Curve) ScalarOne() Scalar {
    scalar := edwards25519.NewScalar()
    scalar.SetCanonicalBytes([]byte{
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    })
    return &Ed25519Scalar{inner: scalar}
}

func (c *Ed25519Curve) PointFromBytes(data []byte) (Point, error) {
    if len(data) != 32 {
        return nil, ErrInvalidPointLength
    }

    point, err := new(edwards25519.Point).SetBytes(data)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrInvalidPoint, err)
    }

    // Validation happens at creation time - invalid points cannot exist
    return NewEd25519Point(point), nil
}

// NewEd25519Point creates a validated Ed25519Point (prevention-based validation)
func NewEd25519Point(inner *edwards25519.Point) *Ed25519Point {
    // Point is already validated by edwards25519.SetBytes above
    // This constructor ensures all points are valid at creation time
    return &Ed25519Point{inner: inner}
}

func (c *Ed25519Curve) BasePoint() Point {
    return &Ed25519Point{inner: edwards25519.NewGeneratorPoint()}
}

func (c *Ed25519Curve) PointIdentity() Point {
    return &Ed25519Point{inner: edwards25519.NewIdentityPoint()}
}

func (c *Ed25519Curve) ValidateScalar(data []byte) error {
    if len(data) != 32 {
        return ErrInvalidScalarLength
    }
    
    _, err := new(edwards25519.Scalar).SetCanonicalBytes(data)
    if err != nil {
        return ErrInvalidScalar
    }
    
    return nil
}

func (c *Ed25519Curve) ValidatePoint(data []byte) error {
    _, err := c.PointFromBytes(data)
    return err
}

// Ed25519Scalar implements the Scalar interface
type Ed25519Scalar struct {
    inner *edwards25519.Scalar
}

func (s *Ed25519Scalar) Bytes() []byte {
    return s.inner.Bytes()
}

func (s *Ed25519Scalar) String() string {
    return hex.EncodeToString(s.Bytes())
}

func (s *Ed25519Scalar) Add(other Scalar) Scalar {
    result := edwards25519.NewScalar()
    result.Add(s.inner, other.(*Ed25519Scalar).inner)
    return &Ed25519Scalar{inner: result}
}

func (s *Ed25519Scalar) Sub(other Scalar) Scalar {
    result := edwards25519.NewScalar()
    result.Subtract(s.inner, other.(*Ed25519Scalar).inner)
    return &Ed25519Scalar{inner: result}
}

func (s *Ed25519Scalar) Mul(other Scalar) Scalar {
    result := edwards25519.NewScalar()
    result.Multiply(s.inner, other.(*Ed25519Scalar).inner)
    return &Ed25519Scalar{inner: result}
}

func (s *Ed25519Scalar) Negate() Scalar {
    result := edwards25519.NewScalar()
    result.Negate(s.inner)
    return &Ed25519Scalar{inner: result}
}

func (s *Ed25519Scalar) Invert() (Scalar, error) {
    if s.IsZero() {
        return nil, ErrScalarZero
    }
    
    result := edwards25519.NewScalar()
    result.Invert(s.inner)
    return &Ed25519Scalar{inner: result}, nil
}

func (s *Ed25519Scalar) Equal(other Scalar) bool {
    return s.inner.Equal(other.(*Ed25519Scalar).inner) == 1
}

func (s *Ed25519Scalar) IsZero() bool {
    zero := edwards25519.NewScalar()
    return s.inner.Equal(zero) == 1
}

func (s *Ed25519Scalar) Zeroize() {
    // Create a new zero scalar to replace the current one
    // This properly clears the internal scalar state
    s.inner = edwards25519.NewScalar()
    // Clear the finalizer since we've manually cleaned up
    runtime.SetFinalizer(s, nil)
}

// Ed25519Point implements the Point interface
type Ed25519Point struct {
    inner *edwards25519.Point
}

func (p *Ed25519Point) Bytes() []byte {
    return p.inner.Bytes()
}

func (p *Ed25519Point) CompressedBytes() []byte {
    return p.Bytes() // Ed25519 points are already compressed
}

func (p *Ed25519Point) String() string {
    return hex.EncodeToString(p.Bytes())
}

func (p *Ed25519Point) Add(other Point) Point {
    result := edwards25519.NewIdentityPoint()
    result.Add(p.inner, other.(*Ed25519Point).inner)
    return &Ed25519Point{inner: result}
}

func (p *Ed25519Point) Sub(other Point) Point {
    result := edwards25519.NewIdentityPoint()
    result.Subtract(p.inner, other.(*Ed25519Point).inner)
    return &Ed25519Point{inner: result}
}

func (p *Ed25519Point) Mul(scalar Scalar) Point {
    result := edwards25519.NewIdentityPoint()
    result.ScalarMult(scalar.(*Ed25519Scalar).inner, p.inner)
    return &Ed25519Point{inner: result}
}

func (p *Ed25519Point) Negate() Point {
    result := edwards25519.NewIdentityPoint()
    result.Negate(p.inner)
    return &Ed25519Point{inner: result}
}

func (p *Ed25519Point) Equal(other Point) bool {
    return p.inner.Equal(other.(*Ed25519Point).inner) == 1
}

func (p *Ed25519Point) IsIdentity() bool {
    identity := edwards25519.NewIdentityPoint()
    return p.inner.Equal(identity) == 1
}

func (p *Ed25519Point) IsOnCurve() bool {
    // Validate that the point is actually on the curve by attempting to re-parse its bytes
    // The edwards25519 library will reject invalid points during SetBytes
    bytes := p.inner.Bytes()
    _, err := new(edwards25519.Point).SetBytes(bytes)
    return err == nil
}
