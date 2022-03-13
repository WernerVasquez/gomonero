package address

import (
	"bytes"
	"gomonero/err_msg"

	"gomonero/crypto"
)

type StandardAddress struct {
	Network int
	Kv      *crypto.PublicKey
	Ks      *crypto.PublicKey
}

func (a *StandardAddress) Base58() (result string) {
	prefix := []byte{byte(a.Network)}
	checksum := crypto.GetChecksum(prefix, a.Ks.Bytes(), a.Kv.Bytes())
	result = EncodeMoneroBase58(prefix, a.Ks.Bytes(), a.Kv.Bytes(), checksum[:])
	return
}

func NewStandardAddress(address string) (result *StandardAddress, err error) {
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

	result = &StandardAddress{
		Network: int(raw[0]),
		Kv:      crypto.NewPointFromBytes(raw[33:65]), //new(Key).FromSlice(raw[33:65]),
		Ks:      crypto.NewPointFromBytes(raw[1:33]),  // new(Key).FromSlice(raw[1:33]),
	}
	return
}

func NewStandardAddressFromKeys(ks *crypto.PrivateKey, kv *crypto.PrivateKey, network int) (result *StandardAddress, err string) {
	result = &StandardAddress{
		Network: network,
		Kv:      kv.MultG(),
		Ks:      ks.MultG(),
	}
	return
}

func (a *StandardAddress) OneTimeAddress() (Ko *crypto.PublicKey, Ke *crypto.PublicKey, err error) {
	//Ko = one time address
	//Ke = ephemeral key = transaction public key
	//Kss = Shared Secret

	if a.Network != MainNetworkSubAddress {
		err = err_msg.AddressTypeError
		return
	}

	r := crypto.NewRandomScalar()

	//Ke = ephemeral key (transaction public key)
	Ke = r.MultG()

	//Kss = Shared Secret = random scalar * public view key * 8
	Kss := r.MultPoint(a.Kv).MultByCofactor()

	//Ko = one time address = Hs(Kss) * G + Ks
	Ko = Kss.HashToScalar().MultG().Add(a.Ks)
	return
}
