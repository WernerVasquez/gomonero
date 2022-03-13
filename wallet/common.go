package wallet

import (
	"crypto/rand"
	"gomonero/crypto"
	"gomonero/err_msg"
)

// amount64 is an 8 byte array (64 bits) used for storing the amount
type amount64 [8]byte

func (a amount64) Scalar() (r *crypto.Scalar) {
	padding := make([]byte, 24)
	amountBytes32 := append(a[:], padding...)
	r = crypto.NewScalarFromBytes(amountBytes32)
	return
}

// newRandomAmount returns a random amount for use in testing
func newRandomAmount() (a amount64) {
	aSlice := make([]byte, 8)
	rand.Read(aSlice)
	copy(a[:], aSlice)
	return
}

// XOR returns a XOR m if they are the sane length, otherwise it returns ErrMismatchedLengths
func (a amount64) XOR(m []byte) (r amount64, err error) {
	if len(a) != len(m) {
		err = err_msg.ErrMismatchedLengths
		return
	}
	masked := make([]byte, len(a))
	for i := range a {
		masked[i] = a[i] ^ m[i]
	}
	copy(r[:], masked)
	return
}
