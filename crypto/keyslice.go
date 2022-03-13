package crypto

import (
	"gomonero/err_msg"
)

type ScalarSlice struct {
	slice []*PrivateKey
	err   error
}

// Add returns a ScalarSlice where r[i] = p[i] + a[i] in the underlying slice
func (p *ScalarSlice) Add(a *ScalarSlice) (r *ScalarSlice) {

	if len(p.slice) != len(a.slice) {
		r = NewScalarSlice(0)
		r.err = err_msg.IncompatibleSizesAB
		return
	}
	r = NewScalarSlice(len(p.slice))
	for i := 0; i < len(p.slice); i++ {
		r.slice[i] = p.slice[i].Add(a.slice[i])
	}
	return
}

// Hadamard returns a ScalarSlice that is the Hadamard product of p and a
func (p *ScalarSlice) Hadamard(a *ScalarSlice) (r *ScalarSlice) {
	if len(p.slice) != len(a.slice) {
		r = NewScalarSlice(0)
		r.err = err_msg.IncompatibleSizesAB
		return
	}
	r = NewScalarSlice(len(p.slice))
	for i := 0; i < len(p.slice); i++ {
		r.slice[i] = p.slice[i].Multiply(a.slice[i])
	}
	return
}

// AddScalar returns a ScalarSlice where r[i] = p[i] + a in the underlying slice
func (p *ScalarSlice) AddScalar(a *Scalar) (r *ScalarSlice) {
	r = NewScalarSlice(len(p.slice))
	for i := 0; i < len(p.slice); i++ {
		r.slice[i] = p.slice[i].Add(a)
	}
	return
}

// SubtractScalar returns a ScalarSlice where r[i] = p[i] - a[i] in the underlying slice
func (p *ScalarSlice) SubtractScalar(a *Scalar) (r *ScalarSlice) {
	r = NewScalarSlice(len(p.slice))
	for i := 0; i < len(p.slice); i++ {
		r.slice[i] = p.slice[i].Subtract(a)
	}
	return
}

// MulScalar returns a ScalarSlice where r[i] = p[i] * a in the underlying slice
func (p *ScalarSlice) MulScalar(a *Scalar) (r *ScalarSlice) {
	r = NewScalarSlice(len(p.slice))
	for i := 0; i < len(p.slice); i++ {
		r.slice[i] = p.slice[i].Multiply(a)
	}
	return
}

// Copy returns a copy of the ScalarSlice
func (p *ScalarSlice) Copy() (r *ScalarSlice) {
	r = NewScalarSlice(len(p.slice))
	for i := 0; i < len(p.slice); i++ {
		r.slice[i] = p.slice[i].Copy()
	}
	return
}

// Len returns the length of the ScalarSlice
func (p ScalarSlice) Len() (r int) {
	r = len(p.slice)
	return
}

func (p *ScalarSlice) Invert() (r *ScalarSlice) {
	r = p.Copy()
	scratch := NewScalarSlice(len(r.slice))
	acc := ScalarIdentity()

	for n := 0; n < len(r.slice); n++ {
		(*scratch).slice[n] = acc
		if n == 0 {
			acc = r.slice[0]
		} else {
			acc = acc.Multiply(r.slice[n])
		}
	}

	acc = acc.Invert()

	for i := len(r.slice) - 1; i >= 0; i-- {
		tmp := acc.Multiply(r.slice[i])
		r.slice[i] = acc.Multiply(scratch.slice[i])
		acc = tmp
	}

	return r
}

func NewScalarSlice(n int) (r *ScalarSlice) {
	r = new(ScalarSlice)
	if n <= 0 {
		r.err = err_msg.InvalidScalarSliceN
	}
	r.slice = make([]*Scalar, n)
	for i := 0; i < n; i++ {
		r.slice[i] = new(Scalar)
	}
	return
}

func RandomScalars(n int) (result *ScalarSlice) {
	result = NewScalarSlice(n)
	for i := 0; i < n; i++ {
		result.slice[i] = NewRandomScalar()
	}
	return
}

// InnerProduct returns a Scalar that is the inner product of p and a
func (p *ScalarSlice) InnerProduct(a *ScalarSlice) (r *Scalar) {

	if len(p.slice) != len(a.slice) {
		r = new(Scalar)
		r.Err = err_msg.IncompatibleSizesAB
		return
	}

	r = ScalarZero()

	for i := range p.slice {
		r = p.slice[i].MultiplyAdd(a.slice[i], r)
	}

	return
}
