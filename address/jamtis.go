package address

import (
	"gomonero/crypto"
)

type JamtisAddress struct {
	Network int
	K1      *crypto.PublicKey
	K2      *crypto.PublicKey
	K3      *crypto.PublicKey
}

//TODO add base58 methods
