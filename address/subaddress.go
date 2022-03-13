package address

import (
	"bytes"
	"gomonero/crypto"
	"gomonero/err_msg"
)

//var LengthError = errors.New("address is the wrong length")
//var ChecksumError = errors.New("checksum does not validate")

type Subaddress struct {
	Network int
	Kvi     *crypto.PublicKey
	Ksi     *crypto.PublicKey
}

func (a *Subaddress) Base58() (result string) {
	prefix := []byte{byte(a.Network)}
	checksum := crypto.GetChecksum(prefix, a.Ksi.Bytes(), a.Kvi.Bytes())
	result = EncodeMoneroBase58(prefix, a.Ksi.Bytes(), a.Kvi.Bytes(), checksum[:])
	return
}

func NewSubaddress(address string) (result *Subaddress, err error) {
	raw := DecodeMoneroBase58(address)
	if len(raw) != 69 {
		err = err_msg.LengthError
		return
	}
	checksum := crypto.GetChecksum(raw[:65])
	if bytes.Compare(checksum[:], raw[65:]) != 0 {
		err = err_msg.ChecksumError
		return
	}

	result = &Subaddress{
		Network: int(raw[0]),
		Kvi:     crypto.NewPointFromBytes(raw[33:65]), //new(Key).FromSlice(raw[33:65]),
		Ksi:     crypto.NewPointFromBytes(raw[1:33]),  // new(Key).FromSlice(raw[1:33]),
	}
	return
}

func NewSubaddressFromKeys(ksi *crypto.PrivateKey, kvi *crypto.PrivateKey, network int) (result *Subaddress, err string) {
	result = &Subaddress{
		Network: network,
		Kvi:     kvi.MultG(),
		Ksi:     ksi.MultG(),
	}
	return
}

func (a *Subaddress) OneTimeAddress() (Ko *crypto.PublicKey, Ke *crypto.PublicKey, ok bool) {
	// Ko = one time address = Hs(Kss) * G + Ksi
	// Ke = ephemeral key (Transaction Public Key)
	// Kss = shared secret

	if a.Network != MainNetworkSubAddress {
		Ko = nil
		Ke = nil
		ok = false
		return
	}

	r := crypto.NewRandomScalar()
	// monero later checks r < l, but this is already true here

	// Ke = ephemeral key  = random scalar * public spend key * 8
	Ke = a.Ksi.ScalarMult(r).MultByCofactor()

	// Kss = shared secret = random scalar * public view key * 8
	Kss := a.Kvi.ScalarMult(r).MultByCofactor()

	// Ko = one time address = Hs(Kss) * G + Ksi
	Ko = Kss.HashToScalar().MultG().Add(a.Ksi)

	return
}
