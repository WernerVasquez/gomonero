package crypto

import (
	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// This file violates the following coding practices of this package
// AVOID calling field and rely on the abstractions of edwards25519
// SHOULD the need arise to extensively call the field package
// the variables immediately below SHOULD have functions which return copies
// otherwise they could potentially be changed during runtime
// field should be refactored like Point and Scalar did for edwards25519
// This was not done below as that work was not deemed worthwhile for writing a single function

var elementMa2, _ = new(field.Element).SetBytes([]byte{0xC9, 0xE3, 0x3D, 0xDB, 0xC8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F})
var elementMa, _ = new(field.Element).SetBytes([]byte{0xE7, 0x92, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F})
var feFffb1, _ = new(field.Element).SetBytes([]byte{0xEE, 0x41, 0x1C, 0x32, 0x75, 0x69, 0xA7, 0x22, 0x8D, 0x73, 0x2A, 0xB9, 0xA8, 0x04, 0x94, 0xD1, 0xE3, 0x19, 0xFB, 0x41, 0x37, 0xC5, 0xA9, 0x20, 0x17, 0x1B, 0xD6, 0xDA, 0xEF, 0xFB, 0x71, 0x7E})
var feFffb2, _ = new(field.Element).SetBytes([]byte{0xE0, 0x9A, 0x7C, 0x60, 0x83, 0x64, 0xDE, 0xD2, 0xDF, 0xF7, 0x56, 0x04, 0x46, 0x03, 0xDE, 0x51, 0xBE, 0x5F, 0x16, 0xC0, 0xB7, 0x51, 0xD4, 0x91, 0xF6, 0x2C, 0x5A, 0x04, 0x0A, 0x1E, 0x06, 0x4D})
var feFffb3, _ = new(field.Element).SetBytes([]byte{0x66, 0x2C, 0x30, 0x17, 0x87, 0x7D, 0x1B, 0x58, 0x29, 0x42, 0x96, 0xA5, 0x4E, 0xFF, 0x24, 0x40, 0xED, 0xA2, 0x0D, 0x3F, 0x40, 0x46, 0x95, 0xB8, 0xEF, 0x08, 0xC2, 0x14, 0x0D, 0x11, 0x4A, 0x67})
var feFffb4, _ = new(field.Element).SetBytes([]byte{0x86, 0x91, 0xB3, 0xB6, 0x03, 0x19, 0x3D, 0x85, 0x49, 0x4A, 0x3F, 0xA1, 0x08, 0xFC, 0x46, 0xEE, 0x2E, 0x43, 0xF7, 0x7E, 0x88, 0xF4, 0xC0, 0x26, 0xF9, 0xDB, 0x67, 0x10, 0x03, 0xF3, 0x43, 0x1A})
var feSqrtM1, _ = new(field.Element).SetBytes([]byte{0xB0, 0xA0, 0x0E, 0x4A, 0x27, 0x1B, 0xEE, 0xC4, 0x78, 0xE4, 0x2F, 0xAD, 0x06, 0x18, 0x43, 0x2F, 0xA7, 0xD7, 0xFB, 0x3D, 0x99, 0x00, 0x4D, 0x2B, 0x0B, 0xDF, 0xC1, 0x4F, 0x80, 0x24, 0x83, 0x2B})

// fromFEBytes and
func (P *Point) fromFEBytes(s []byte) (R *Point) {
	// X, Y, and Z for a projective group element
	PX := new(field.Element)
	PY := new(field.Element)
	PZ := new(field.Element)

	//u := new(field.Element) //declared later
	v := new(field.Element)
	w := new(field.Element)
	x := new(field.Element)
	y := new(field.Element)
	z := new(field.Element)

	u, err := new(field.Element).SetBytes(s)
	if err != nil {
		R = new(Point)
		R.Err = err
		return
	}

	//FeSquare2(&v, &u) // 2 * u^2
	v.Square(u)
	v.Mult32(v, 2) // 2 * u^2
	w.One()
	//FeAdd(&w, &v, &w)        // w = 2 * u^2 + 1
	w.Add(v, w) // w = 2 * u^2 + 1
	//FeSquare(&x, &w)         // w^2
	x.Square(w) // w^2
	//FeMul(&y, &FeMa2, &v)    // -2 * A^2 * u^2
	y.Multiply(elementMa2, v)
	//FeAdd(&x, &x, &y)        // x = w^2 - 2 * A^2 * u^2
	x.Add(x, y)
	//feDivPowM1(&p.X, &w, &x) // (w / x)^(m + 1)
	feDivPowM1(PX, w, x)

	//FeSquare(&y, &p.X)
	y.Square(PX)
	//FeMul(&x, &y, &x)
	x.Multiply(y, x)
	//FeSub(&y, &w, &x)
	y.Subtract(w, x)
	//FeCopy(&z, &FeMa)
	z.Set(elementMa)

	isNegative := false
	var sign int
	if y.Equal(new(field.Element).Zero()) == 0 { //y = 0 return false
		//FeAdd(&y, &w, &x)
		y.Add(w, x)
		if y.Equal(new(field.Element).Zero()) == 0 { //y.IsNonZero() != 0 { //y == 0 return false
			isNegative = true
		} else {
			//FeMul(&p.X, &p.X, &feFffb1)
			PX.Multiply(PX, feFffb1)

		}
	} else {
		//FeMul(&p.X, &p.X, &feFffb2)
		PX.Multiply(PX, feFffb2)
	}
	if isNegative {
		//FeMul(&x, &x, &FeSqrtM1)
		x.Multiply(x, feSqrtM1)
		//FeSub(&y, &w, &x)
		y.Subtract(w, x)
		if y.Equal(new(field.Element).Zero()) == 0 {
			//FeAdd(&y, &w, &x)
			y.Add(w, x)
			//FeMul(&p.X, &p.X, &feFffb3)
			PX.Multiply(PX, feFffb3)
		} else {
			//FeMul(&p.X, &p.X, &feFffb4)
			PX.Multiply(PX, feFffb4)
		}
		sign = 1
	} else {
		//FeMul(&p.X, &p.X, &u) // u * sqrt(2 * A * (A + 2) * w / x)
		PX.Multiply(PX, u)
		//FeMul(&z, &z, &v)     // -2 * A * u^2
		z.Multiply(z, v)
		sign = 0
	}
	if PX.IsNegative() != sign {
		//FeNeg(&p.X, &p.X)
		PX.Negate(PX)
	}
	//FeAdd(&p.Z, &z, &w)
	PZ.Add(z, w)
	//FeSub(&p.Y, &z, &w)
	PY.Subtract(z, w)
	//FeMul(&p.X, &p.X, &p.Z)
	PX.Multiply(PX, PZ)

	// construct extended group element
	X := new(field.Element)
	Y := new(field.Element)
	Z := new(field.Element)
	T := new(field.Element)

	//FeMul(&r.X, &p.X, &p.Z)
	X.Multiply(PX, PZ)
	//FeMul(&r.Y, &p.Y, &p.Z)
	Y.Multiply(PY, PZ)
	//FeMul(&r.Z, &p.Z, &p.Z)
	Z.Square(PZ)
	//FeMul(&r.T, &p.X, &p.Y)
	T.Multiply(PX, PY)

	P.edPoint, P.Err = new(edwards25519.Point).SetExtendedCoordinates(X, Y, Z, T)

	return P
}

func feDivPowM1(out, u, v *field.Element) {
	var v3, uv7, t0 *field.Element

	//FeSquare(&v3, v)
	v3.Square(v)
	//FeMul(&v3, &v3, v) /* v3 = v^3 */
	v3.Multiply(v3, v)
	//FeSquare(&uv7, &v3)
	uv7.Square(v3)
	//FeMul(&uv7, &uv7, v)
	uv7.Multiply(uv7, v)
	//FeMul(&uv7, &uv7, u) /* uv7 = uv^7 */
	uv7.Multiply(uv7, u)

	//fePow22523(&t0, &uv7)
	t0.Pow22523(uv7)
	/* t0 = (uv^7)^((q-5)/8) */
	//FeMul(&t0, &t0, &v3)
	t0.Multiply(t0, v3)
	//FeMul(out, &t0, u) /* u^(m+1)v^(-(m+1)) */
	out.Multiply(t0, u)
}
