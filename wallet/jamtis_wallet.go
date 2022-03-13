package wallet

import (
	"gomonero/address"
	"gomonero/crypto"
	"gomonero/err_msg"
)

type JamtisWallet struct {
	//private keys
	km    *crypto.Scalar
	kvb   *crypto.Scalar
	kac   *crypto.Scalar
	kfr   *crypto.Scalar
	ka    []*crypto.Scalar   //kai = ka[i]
	kaddr [][]*crypto.Scalar //kaddr i,j =  kaddr[i][j]
	kx    [][]*crypto.Scalar //kx i,j = kx[i][j]
	//public keys
	Ks      *crypto.Point
	Kid     *crypto.Point
	Kfr     *crypto.Point
	address address.JamtisAddress //pub keys
	outputs []*output

	jamtisAddressLookup map[[32]byte]JamtisAddressIndex //map of K1 keys for IDing outputs
}

type JamtisAddressIndex struct {
	i, j uint32
}

type JamtisOutput struct {
	Ke *crypto.Point //ephemeral key
	v  byte          //view tag
	Ko *crypto.Point //one time address
	ae amount64      //encrypted amount
	C  *crypto.Point //commitment
	// private values
	amount amount64
	blind  *crypto.Scalar
	index  JamtisAddressIndex
	ksp    *crypto.Scalar //partial private spend key
	s      bool           //spend status
}

func NewJamtisWallet() (w *JamtisWallet) {
	w = new(JamtisWallet)
	w.km = crypto.NewRandomScalar()
	w.kvb = w.km.KeyDerive("view-balance key\x00")
	//todo implement birthday
	w.kac = w.kvb.KeyDerive("account-creation key\x00")
	w.kfr = w.kvb.KeyDerive("find-received key\x00")
	//Ks = kvb * X + km * U
	w.Ks = w.kvb.MultX().Add(w.km.MultU())
	//KID = kac * G
	w.Kid = w.kac.MultG()
	w.Kfr = w.kfr.MultG()

	n := 10 // initial number of pre generated keys

	w.ka = make([]*crypto.Scalar, n) //todo decide how many to premake
	for i := range w.ka {
		//kai = KeyDerive(kac, "account key" || i)
		kaSalt := "account key\x00" + string(byte(i))
		w.ka[i] = w.kac.KeyDerive(kaSalt)
	}

	w.kaddr = make([][]*crypto.Scalar, n)
	w.kx = make([][]*crypto.Scalar, n)
	for i := 0; i < n; i++ {
		w.kaddr[i] = make([]*crypto.Scalar, n)
		w.kx[i] = make([]*crypto.Scalar, n)
		for j := 0; j < n; j++ {
			kaddrSalt := "address key\x00" + string(byte(i)) + string(byte(j))
			w.kaddr[i][j] = w.ka[i].KeyDerive(kaddrSalt)

			kxSalt := "key extension\x00" + string(byte(i)) + string(byte(j))
			w.kx[i][j] = w.kaddr[i][j].KeyDerive(kxSalt)
		}
	}

	w.InitializeJamtisAddressLookup(uint32(n), uint32(n))
	return
}

func (w *JamtisWallet) Address(index JamtisAddressIndex) (r *address.JamtisAddress, err error) {
	//bounds check
	if index.i >= uint32(len(w.kx)) || index.i >= uint32(len(w.kaddr)) {
		err = err_msg.ErrOutOfBounds
		return
	}
	if index.j >= uint32(len(w.kx[index.i])) || index.j >= uint32(len(w.kaddr[index.i])) {
		err = err_msg.ErrOutOfBounds
		return
	}
	//todo add code to generate more keys if index is out of bounds

	r = new(address.JamtisAddress)
	//K1(i,j) = Ks + kx(i,j) * X
	r.K1 = w.kx[index.i][index.j].MultX().Add(w.Ks)
	//K2(i,j) = kaddr(i,j) * Kfr
	r.K2 = w.Kfr.ScalarMult(w.kaddr[index.i][index.j])
	//K3(i,j) = kaddr(i,j) * G
	r.K3 = w.kaddr[index.i][index.j].MultG()

	return
}

func (w *JamtisWallet) InitializeJamtisAddressLookup(iMax, jMax uint32) {
	var i, j uint32
	w.jamtisAddressLookup = make(map[[32]byte]JamtisAddressIndex, i*j)
	for i = 0; i < iMax; i++ {
		for j = 0; j < jMax; j++ {
			aij, err := w.Address(JamtisAddressIndex{i, j})
			if err == nil {
				w.jamtisAddressLookup[aij.K1.Byte32()] = JamtisAddressIndex{i, j}
			}
		}
	}
}

func (w *JamtisWallet) CreateOutput(a *address.JamtisAddress, amount amount64) (output *JamtisOutput, err error) {
	output = new(JamtisOutput)
	r := crypto.NewRandomScalar()
	output.Ke = a.K3.ScalarMult(r)
	Kd := a.K2.ScalarMult(r).MultByCofactor()

	vHashData := append([]byte("view tag\x00"), Kd.Bytes()...)
	output.v = crypto.Hash8(vHashData)

	qHashData := append([]byte("sender-receiver secret\x00"), Kd.Bytes()...)
	q := crypto.HashToScalar(qHashData)

	output.Ko = a.K1.Add(q.MultX())

	rG := r.MultG()
	bHashData := append([]byte("blind\x00"), q.Bytes()...)
	bHashData = append(bHashData, rG.Bytes()...)
	b := crypto.HashToScalar(bHashData)

	aMaskHashData := append([]byte("amount\x00"), q.Bytes()...)
	aMaskHashData = append(aMaskHashData, rG.Bytes()...)
	aMask := crypto.Hash64(aMaskHashData)

	output.ae, err = amount.XOR(aMask[:])
	if err != nil {
		output = nil
		return
	}

	output.C = b.DoubleScalarBaseMult(amount.Scalar(), crypto.PointH())

	//todo add change and self spend logic
	return
}

func (w *JamtisWallet) ReceiveOutput(output *JamtisOutput) (err error) {
	Kd := output.Ke.ScalarMult(w.kfr).MultByCofactor()

	vHashData := append([]byte("view tag\x00"), Kd.Bytes()...)
	v := crypto.Hash8(vHashData)

	if v != output.v {
		err = err_msg.ErrViewTag
		return
	}

	qHashData := append([]byte("sender-receiver secret\x00"), Kd.Bytes()...)
	q := crypto.HashToScalar(qHashData)

	Ks := output.Ko.Subtract(q.MultX())
	index, ok := w.jamtisAddressLookup[Ks.Byte32()]

	if !ok {
		err = err_msg.ErrLookup
		output = nil
		return
	}
	output.index = index

	rG := output.Ke.ScalarMult(w.kaddr[index.i][index.j].Invert())

	aMaskHashData := append([]byte("amount\x00"), q.Bytes()...)
	aMaskHashData = append(aMaskHashData, rG.Bytes()...)
	aMask := crypto.Hash64(aMaskHashData)

	output.amount, err = output.ae.XOR(aMask[:])
	if err != nil {
		output = nil
		return
	}

	bHashData := append([]byte("blind\x00"), q.Bytes()...)
	bHashData = append(bHashData, rG.Bytes()...)
	output.blind = crypto.HashToScalar(bHashData)

	C := output.blind.DoubleScalarBaseMult(output.amount.Scalar(), crypto.PointH())

	if C.Equal(output.C) == 0 {
		err = err_msg.ErrJanus
		output = nil
		return
	}

	output.ksp = w.kvb.Add(w.kx[index.i][index.j]).Add(q)
	Kt := w.Ks.Subtract(w.kvb.MultX()).ScalarMult(output.ksp.Invert())
	_ = Kt

	return
}

//KeyDerive in crypto package
