package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"filippo.io/edwards25519"
	"gomonero/err_msg"
)

//todo add stringers

type Point struct {
	edPoint *edwards25519.Point
	Err     error
}

type Scalar struct {
	edScalar *edwards25519.Scalar
	Err      error
}

func NewPointFromBytes(b []byte) (R *Point) {
	R = new(Point)
	R.edPoint, R.Err = new(edwards25519.Point).SetBytes(b)
	return
}

func NewPointFromHexString(s string) (R *Point) {
	R = new(Point)
	sBytes, err := hex.DecodeString(s)
	if err != nil {
		R.Err = err
		return
	}
	R.edPoint, R.Err = new(edwards25519.Point).SetBytes(sBytes)
	return
}

func (P *Point) Bytes() (r []byte) {
	if P.Err != nil {
		return
	}
	r = P.edPoint.Bytes()
	return
}

func (P *Point) Byte32() (r [32]byte) {
	if P.Err != nil {
		return
	}
	copy(r[:], P.edPoint.Bytes())
	return
}

// Copy returns a copy of P
func (P *Point) Copy() (R *Point) {
	R = new(Point)
	if P.Err != nil {
		R.Err = P.Err
		return
	}
	R.edPoint = new(edwards25519.Point).Set(P.edPoint)
	return
}

func (P *Point) Add(Q *Point) (R *Point) {
	R = new(Point)
	if P.Err != nil {
		R.Err = P.Err
		return
	}
	if Q.Err != nil {
		R.Err = Q.Err
		return
	}
	R.edPoint = new(edwards25519.Point).Add(P.edPoint, Q.edPoint)
	return
}

func (P *Point) Subtract(Q *Point) (R *Point) {
	R = new(Point)
	if P.Err != nil {
		R.Err = P.Err
		return
	}
	if Q.Err != nil {
		R.Err = Q.Err
		return
	}
	R.edPoint = new(edwards25519.Point).Subtract(P.edPoint, Q.edPoint)
	return
}

func (P *Point) ScalarMult(x *Scalar) (R *Point) {
	R = new(Point)
	//TODO wrap errors throughout package
	if P.Err != nil {
		R.Err = P.Err
		return
	}
	if x.Err != nil {
		R.Err = x.Err
		return
	}

	R.edPoint = new(edwards25519.Point).ScalarMult(x.edScalar, P.edPoint)
	return
}

func (P *Point) MultByCofactor() (R *Point) {
	R = new(Point)
	if P.Err != nil {
		R.Err = P.Err
		return
	}
	R.edPoint = new(edwards25519.Point).MultByCofactor(P.edPoint)
	return
}

func (P *Point) Equal(Q *Point) (r int) {
	if P.Err != nil || Q.Err != nil {
		return
	}
	r = P.edPoint.Equal(Q.edPoint)
	return
}

func (P *Point) HashToScalar() (r *Scalar) {
	if P.Err != nil {
		r = new(Scalar)
		r.Err = P.Err
		return
	}
	r = HashToScalar(P.Bytes())
	return
}

func NewScalarFromBytes(b []byte) (r *Scalar) {
	r = new(Scalar)
	r.edScalar, r.Err = new(edwards25519.Scalar).SetCanonicalBytes(b)
	return
}

func NewScalarFromHexString(s string) (r *Scalar) {
	r = new(Scalar)
	sBytes, err := hex.DecodeString(s)
	if err != nil {
		r.Err = err
		return
	}
	r.edScalar, r.Err = new(edwards25519.Scalar).SetCanonicalBytes(sBytes)
	return
}

func NewScalarFromAmount(amount [8]byte) (r *Scalar) {
	padding := make([]byte, 24)
	amountBytes32 := append(amount[:], padding...)
	r = NewScalarFromBytes(amountBytes32)
	return
}

// HashToEC Creates a point on the Edwards Curve by hashing the Scalar
func (s *Scalar) HashToEC() (result *Point) {
	h := Keccak256(s.Bytes())
	result = new(Point).fromFEBytes(h[:]).MultByCofactor()
	return
}

func (s *Scalar) Bytes() (r []byte) {
	if s.Err != nil {
		return
	}
	r = s.edScalar.Bytes()
	return
}

func (s *Scalar) Byte32() (r [32]byte) {
	if s.Err != nil {
		return
	}
	copy(r[:], s.edScalar.Bytes())
	return
}

func NewRandomScalar() (r *Scalar) {
	r = new(Scalar)
	b := make([]byte, 64)
	rand.Read(b)
	r.edScalar, r.Err = new(edwards25519.Scalar).SetUniformBytes(b)
	return
}

// Copy returns a copy of s
func (s *Scalar) Copy() (r *Scalar) {
	r = new(Scalar)
	if s.Err != nil {
		r.Err = s.Err
		return
	}
	r.edScalar = new(edwards25519.Scalar).Set(s.edScalar)
	r.Err = s.Err
	return
}

func (s *Scalar) Equal(a *Scalar) (r int) {
	if s.Err != nil || a.Err != nil {
		r = 0
		return
	}
	r = s.edScalar.Equal(a.edScalar)
	return
}

// MultPoint returns s * P
func (s *Scalar) MultPoint(P *Point) (R *Point) {
	R = new(Point)
	if s.Err != nil {
		R.Err = s.Err
		return
	}
	if P.Err != nil {
		R.Err = P.Err
		return
	}
	R.edPoint = new(edwards25519.Point).ScalarMult(s.edScalar, P.edPoint)
	return
}

// MultG returns s * G
func (s *Scalar) MultG() (R *Point) {
	R = new(Point)
	if s.Err != nil {
		R.Err = s.Err
		return
	}
	R.edPoint = new(edwards25519.Point).ScalarBaseMult(s.edScalar)
	return
}

// MultH returns s * H
func (s *Scalar) MultH() (R *Point) {
	R = new(Point)
	if s.Err != nil {
		R.Err = s.Err
		return
	}
	R.edPoint = new(edwards25519.Point).ScalarMult(s.edScalar, PointH().edPoint)
	return
}

// MultX returns s * X
func (s *Scalar) MultX() (R *Point) {
	R = new(Point)
	if s.Err != nil {
		R.Err = s.Err
		return
	}
	R.edPoint = new(edwards25519.Point).ScalarMult(s.edScalar, PointX().edPoint)
	return
}

// MultU returns s * U
func (s *Scalar) MultU() (R *Point) {
	R = new(Point)
	if s.Err != nil {
		R.Err = s.Err
		return
	}
	R.edPoint = new(edwards25519.Point).ScalarMult(s.edScalar, PointU().edPoint)
	return
}

// Add returns s + a
func (s *Scalar) Add(a *Scalar) (r *Scalar) {
	r = new(Scalar)
	if s.Err != nil {
		r.Err = s.Err
		return
	}
	if a.Err != nil {
		r.Err = a.Err
		return
	}
	r.edScalar = new(edwards25519.Scalar).Add(s.edScalar, a.edScalar)
	return
}

// Subtract returns s - a
func (s *Scalar) Subtract(a *Scalar) (r *Scalar) {
	r = new(Scalar)
	if s.Err != nil {
		r.Err = s.Err
		return
	}
	if a.Err != nil {
		r.Err = a.Err
		return
	}
	r.edScalar = new(edwards25519.Scalar).Subtract(s.edScalar, a.edScalar)
	return
}

// Multiply returns s * a
func (s *Scalar) Multiply(a *Scalar) (r *Scalar) {
	r = new(Scalar)
	if s.Err != nil {
		r.Err = s.Err
		return
	}
	if a.Err != nil {
		r.Err = a.Err
		return
	}
	r.edScalar = new(edwards25519.Scalar).Multiply(s.edScalar, a.edScalar)
	return
}

// MultiplyAdd returns s * a + b
func (s *Scalar) MultiplyAdd(a *Scalar, b *Scalar) (r *Scalar) {
	r = new(Scalar)
	if s.Err != nil {
		r.Err = s.Err
		return
	}
	if a.Err != nil {
		r.Err = a.Err
		return
	}
	if b.Err != nil {
		r.Err = b.Err
		return
	}
	r.edScalar = new(edwards25519.Scalar).MultiplyAdd(s.edScalar, a.edScalar, b.edScalar)
	return
}

// Invert returns s^-1
func (s *Scalar) Invert() (r *Scalar) {
	r = new(Scalar)
	if s.Err != nil {
		r.Err = s.Err
		return
	}
	r.edScalar = new(edwards25519.Scalar).Invert(s.edScalar)
	return
}

// Negate returns -s
func (s *Scalar) Negate() (r *Scalar) {
	r = new(Scalar)
	if s.Err != nil {
		r.Err = s.Err
		return
	}
	r.edScalar = new(edwards25519.Scalar).Negate(s.edScalar)
	return
}

// DoubleScalarBaseMult returns s*G + a*A (addkeys2 in monero reference implementation)
func (s *Scalar) DoubleScalarBaseMult(a *Scalar, A *Point) (R *Point) {
	R = new(Point)
	if s.Err != nil {
		R.Err = s.Err
		return
	}
	if a.Err != nil {
		R.Err = a.Err
		return
	}
	if A.Err != nil {
		R.Err = A.Err
		return
	}
	R.edPoint = new(edwards25519.Point).VarTimeDoubleScalarBaseMult(a.edScalar, A.edPoint, s.edScalar)
	return
}

// PowersOfScalar Returns a struct a slice of n powers of the scalar
func (s *Scalar) PowersOfScalar(n int) (r *ScalarSlice) {
	if s.Err != nil {
		r = new(ScalarSlice)
		r.err = s.Err
	}
	if n <= 0 {
		r = new(ScalarSlice)
		r.err = err_msg.InvalidPowersOfScalarN
	}
	r = NewScalarSlice(n)
	if n == 0 {
		return
	}

	r.slice[0] = ScalarIdentity()
	if n == 1 {
		return
	}

	r.slice[1] = s.Copy()
	for i := 2; i < n; i++ {
		r.slice[i] = r.slice[i-1].Multiply(s)
	}
	return
}

// VectorPowerSum Returns the sum of the scalar's powers from 0 to n-1
func (s *Scalar) VectorPowerSum(n int) (r *Scalar) {
	if n == 0 {
		r = ScalarZero()
		return
	}

	r = ScalarIdentity()
	if n == 1 {
		return
	}
	//this returns true of zero, is this a problem?
	a := s.Copy()
	isPowerOf2 := n&(n-1) == 0
	if isPowerOf2 {
		r = r.Add(a)
		for n > 2 {
			a = a.Multiply(a)
			r = a.MultiplyAdd(r, r)
			n /= 2
		}
	} else {
		prev := a
		for i := 1; i < n; i++ {
			if i > 1 {
				prev = prev.Multiply(a)
				r = r.Add(prev)
			}
		}
	}

	return
}

func (s *Scalar) KeyDerive(salt string) (r *Scalar) {
	data := append(s.PaddedBytes(136), []byte(salt)...)
	r = HashToScalar(data)
	return
}

func (s *Scalar) PaddedBytes(length int) (r []byte) {
	b := s.Bytes()
	paddingSize := length - len(b)
	padding := make([]byte, paddingSize)
	r = append(b, padding...)
	return
}
