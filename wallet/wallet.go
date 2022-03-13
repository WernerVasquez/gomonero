package wallet

import (
	"encoding/binary"
	"gomonero/address"
	"gomonero/crypto"
)

type SubAddressIndex struct {
	Major, Minor uint32
}

type Wallet struct {
	kv               *crypto.PrivateKey
	ks               *crypto.PrivateKey
	address          address.StandardAddress //pub keys
	outputs          []*output
	subAddressLookup map[[32]byte]SubAddressIndex //map of public spend keys for IDing transactions
}

type output struct {
	Ko     *crypto.PublicKey
	ko     *crypto.PrivateKey
	amount uint64
	mask   [crypto.HashLength]byte
	spent  bool
}

func NewWallet() (w *Wallet) {

	w = new(Wallet)

	w.kv, w.address.Kv = crypto.NewKeyPair()
	w.ks, w.address.Ks = crypto.NewKeyPair()
	w.address.Network = address.MainNetwork
	return
}

func (w *Wallet) FromKeys(kv, ks *crypto.PrivateKey) *Wallet {

	w.kv = kv
	w.address.Kv = kv.PublicKey()
	w.ks = ks
	w.address.Ks = ks.PublicKey()
	w.address.Network = address.MainNetwork
	return w
}

func (w *Wallet) ScanOutputForStandardAddress(Ko, Ke *crypto.PublicKey) (r int) {
	//kv * Ke * 8 = Kss = random scalar * public view key = shared secret
	Kss := w.kv.MultPoint(Ke).MultByCofactor()

	//Check if Ks = Ko - Hs(Kss) * G to recognize output
	Ks := Ko.Subtract(Kss.HashToScalar().MultG())

	return Ks.Equal(w.address.Ks)
}

func (w *Wallet) StandardAddressOneTimeAddressPrivateKey(Ke *crypto.PublicKey) (ko *crypto.PrivateKey) {
	//todo consider using a less wordy function name

	//kv * Ke * 8 = Kss = random scalar * public view key = shared secret
	Kss := w.kv.MultPoint(Ke).MultByCofactor()

	//One time address private spend key = Hs(Kss) + ks
	ko = Kss.HashToScalar().Add(w.ks)
	return
}

//monero/src/device/device_default.cpp 121

//subadresses MRL-006
//https://github.com/monero-project/monero/pull/2056

//cryptonote_format_utils.cpp
//is_out_to_acc_precomp

func (w *Wallet) SubAddress(i SubAddressIndex) (A *address.Subaddress) {
	// Kvi = Public ViewKey for subaddress i
	// Ksi = Public SpendKey for subaddress i
	// kv = private view key

	// Refer to method's comments for subAddressPublicSpendKey construction
	Ksi := w.SubAddressPublicSpendKey(i)

	// Kvi = kv * Ksi
	Kvi := Ksi.ScalarMult(w.kv)

	A = &address.Subaddress{
		Network: address.MainNetworkSubAddress,
		Kvi:     Kvi,
		Ksi:     Ksi,
	}

	return
}

func (w *Wallet) SubAddressPublicSpendKey(i SubAddressIndex) (Ksi *crypto.PublicKey) {
	// Ksi = public spend key for SubAddress i
	// ksi = private spend key for SubAddress i
	// Ks = public spend key

	// ksi = ks + Hs("SubAddr\0" || kv || index_major || index_minor)
	ksi := w.SubAddressPrivateSpendKey(i)

	// Ksi = ksi * G
	Ksi = ksi.MultG()

	return
}

func (w *Wallet) SubAddressPrivateSpendKey(i SubAddressIndex) (ksi *crypto.PrivateKey) {
	// ksi = ks + Hs("SubAddr\x00" || kv || index_major || index_minor)

	data := []byte("SubAddr\x00")

	data = append(data, w.kv.Bytes()...)

	index := make([]byte, 4)
	binary.LittleEndian.PutUint32(index[0:], i.Major)
	data = append(data, index...)

	binary.LittleEndian.PutUint32(index[0:], i.Minor)
	data = append(data, index...)

	ksi = w.ks.Add(crypto.HashToScalar(data))
	return
}

func (w *Wallet) InitializeSubAddressLookup(MajorMax, MinorMax uint32) {
	var i, j uint32
	w.subAddressLookup = make(map[[32]byte]SubAddressIndex, i*j)
	for i = 0; i < MajorMax; i++ {
		for j = 0; j < MinorMax; j++ {
			PubKey := w.SubAddressPublicSpendKey(SubAddressIndex{i, j}).Byte32()
			w.subAddressLookup[PubKey] = SubAddressIndex{i, j}
		}
	}
}

func (w *Wallet) SubAddressLookup(Ksi *crypto.PublicKey) (i SubAddressIndex, ok bool) {
	i, ok = w.subAddressLookup[Ksi.Byte32()]
	return
}

// ScanOutputForSubAddress used to recognize outputs sent to a subaddress and return the subaddress index
func (w *Wallet) ScanOutputForSubAddress(Ko *crypto.PublicKey, Ke *crypto.PublicKey) (i SubAddressIndex, ok bool) {
	// Ko = output address (one time address)
	// Ke = ephemeral key
	// kv = private view key
	// Kss = shared secret = kv * Ke
	// Ksi = calculated subaddress public spend key = Ko - Hs(Kss)*G

	Kss := Ke.ScalarMult(w.kv)
	Ksi := Ko.Subtract(Kss.HashToScalar().MultG())
	return w.SubAddressLookup(Ksi)

}

func (w *Wallet) SubaddressOutputPrivateKey(Ke *crypto.PublicKey, i SubAddressIndex) (ko *crypto.PrivateKey) {
	// Ke = ephemeral key (txPublicKey)
	// Kss = kv * Ke
	// ksi = subaddress private spend key = Hs("SubAddr\x00" || kv || index_major || index_minor)
	// ko = output private key = Hs(Kss) + ksi

	Kss := Ke.ScalarMult(w.kv)
	ksi := w.SubAddressPrivateSpendKey(i)

	ko = Kss.HashToScalar().Add(ksi)

	return

}
