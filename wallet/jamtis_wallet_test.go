package wallet

import (
	"testing"
)

func TestJamtis(t *testing.T) {
	w := NewJamtisWallet()

	index := JamtisAddressIndex{2, 3}
	a, addressErr := w.Address(index)
	if addressErr != nil {
		t.Errorf(addressErr.Error())
		return
	}

	amount := newRandomAmount()

	o, createErr := w.CreateOutput(a, amount)
	if createErr != nil {
		t.Errorf(createErr.Error())
		return
	}

	receiveErr := w.ReceiveOutput(o)
	if receiveErr != nil {
		t.Errorf(receiveErr.Error())
		return
	}

	if amount != o.amount {
		t.Errorf("wrong amount decoded")
		return
	}

	Ko := o.ksp.MultX().Add(w.km.MultU())
	if Ko.Equal(o.Ko) == 0 {
		t.Errorf("ko does not match Ko")
	}
}
