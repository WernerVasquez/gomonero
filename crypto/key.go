package crypto

import (
	"io"
)

// PublicKey Alias of Point
type PublicKey = Point

// PrivateKey Alias of Point
type PrivateKey = Scalar

func (s *PrivateKey) PublicKey() (R *PublicKey) {
	if s.Err != nil {
		R = new(PublicKey)
		R.Err = s.Err
		return
	}
	R = s.MultG()
	return
}

func NewKeyPair() (a *PrivateKey, A *PublicKey) {
	a = NewRandomScalar()
	A = a.MultG()
	return
}

// ParseBytes returns a []byte of KeyLength size from buf
func ParseBytes(buf io.Reader) (result []byte, err error) {
	bytes := make([]byte, KeyLength)
	if _, err = buf.Read(bytes); err != nil {
		return
	}
	copy(result[:], bytes)
	return
}
