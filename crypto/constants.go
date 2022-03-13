package crypto

import "filippo.io/edwards25519"

const (
	KeyLength = 32
)

//Zero, Identity and L
var scalarZero, _ = new(edwards25519.Scalar).SetCanonicalBytes([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
var scalarIdentity, _ = new(edwards25519.Scalar).SetCanonicalBytes([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
var scalarL, _ = new(edwards25519.Scalar).SetCanonicalBytes([]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})

// ScalarZero returns a new Scalar set to Zero.
func ScalarZero() (r *Scalar) {
	r = new(Scalar)
	r.edScalar = new(edwards25519.Scalar).Set(scalarZero)
	return
}

// ScalarIdentity returns a new Scalar set to Identity.
func ScalarIdentity() (r *Scalar) {
	r = new(Scalar)
	r.edScalar = new(edwards25519.Scalar).Set(scalarIdentity)
	return
}

// ScalarL returns a new Scalar set to L.
func ScalarL() (r *Scalar) {
	r = new(Scalar)
	r.edScalar = new(edwards25519.Scalar).Set(scalarL)
	return
}

// pointH
// H = G.HashToEC(), where G is the basepoint
var pointH, _ = new(edwards25519.Point).SetBytes([]byte{
	0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
	0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
	0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
	0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94})

// PointH returns a new Point set to H.
func PointH() (R *Point) {
	R = new(Point)
	R.edPoint = new(edwards25519.Point).Set(pointH)
	return
}

// pointX for jamtis
// hex = 4017a126181c34b0774d590523a08346be4f42348eddd50eb7a441b571b2b613
var pointX, _ = new(edwards25519.Point).SetBytes([]byte{
	0x40, 0x17, 0xa1, 0x26, 0x18, 0x1c, 0x34, 0xb0,
	0x77, 0x4d, 0x59, 0x05, 0x23, 0xa0, 0x83, 0x46,
	0xbe, 0x4f, 0x42, 0x34, 0x8e, 0xdd, 0xd5, 0x0e,
	0xb7, 0xa4, 0x41, 0xb5, 0x71, 0xb2, 0xb6, 0x13})

// PointX returns a new Point set to X.
func PointX() (R *Point) {
	R = new(Point)
	R.edPoint = new(edwards25519.Point).Set(pointX)
	return
}

// pointU for jamtis
// hex = 126582dfc357b10ecb0ce0f12c26359f53c64d4900b7696c2c4b3f7dcab7f730
var pointU, _ = new(edwards25519.Point).SetBytes([]byte{
	0x12, 0x65, 0x82, 0xdf, 0xc3, 0x57, 0xb1, 0x0e,
	0xcb, 0x0c, 0xe0, 0xf1, 0x2c, 0x26, 0x35, 0x9f,
	0x53, 0xc6, 0x4d, 0x49, 0x00, 0xb7, 0x69, 0x6c,
	0x2c, 0x4b, 0x3f, 0x7d, 0xca, 0xb7, 0xf7, 0x30})

// PointU returns a new Point set to U.
func PointU() (R *Point) {
	R = new(Point)
	R.edPoint = new(edwards25519.Point).Set(pointU)
	return
}

// PointG returns new generator point
func PointG() (R *Point) {
	R = new(Point)
	R.edPoint = edwards25519.NewGeneratorPoint()
	return
}

// PointI returns new identity point
func PointI() (R *Point) {
	R = new(Point)
	R.edPoint = edwards25519.NewIdentityPoint()
	return
}