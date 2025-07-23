package frost

import (
    "fmt"
)

// Polynomial represents a polynomial over a scalar field
type Polynomial struct {
    curve        Curve
    coefficients []Scalar
}

// NewRandomPolynomial creates a new random polynomial with given degree and constant term
func NewRandomPolynomial(curve Curve, degree int, constantTerm Scalar) (*Polynomial, error) {
    if degree < 0 {
        return nil, fmt.Errorf("degree must be non-negative")
    }
    
    coefficients := make([]Scalar, degree+1)
    coefficients[0] = constantTerm // a0 = constant term
    
    // Generate random coefficients for higher degree terms
    for i := 1; i <= degree; i++ {
        coeff, err := curve.ScalarRandom()
        if err != nil {
            return nil, fmt.Errorf("failed to generate coefficient %d: %w", i, err)
        }
        coefficients[i] = coeff
    }
    
    return &Polynomial{
        curve:        curve,
        coefficients: coefficients,
    }, nil
}

// Evaluate evaluates the polynomial at a given point
func (p *Polynomial) Evaluate(x Scalar) Scalar {
    if len(p.coefficients) == 0 {
        return p.curve.ScalarZero()
    }
    
    // Use Horner's method: f(x) = a0 + x(a1 + x(a2 + x(a3 + ...)))
    result := p.coefficients[len(p.coefficients)-1]
    
    for i := len(p.coefficients) - 2; i >= 0; i-- {
        result = result.Mul(x).Add(p.coefficients[i])
    }
    
    return result
}

// Degree returns the degree of the polynomial
func (p *Polynomial) Degree() int {
    return len(p.coefficients) - 1
}

// Zeroize securely clears the polynomial coefficients
func (p *Polynomial) Zeroize() {
    for _, coeff := range p.coefficients {
        if coeff != nil {
            coeff.Zeroize()
        }
    }
    // Clear the slice itself
    for i := range p.coefficients {
        p.coefficients[i] = nil
    }
    p.coefficients = nil
}
