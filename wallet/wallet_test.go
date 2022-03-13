package wallet

import (
	"gomonero/address"
	"gomonero/crypto"
	"testing"
)

func TestSubAddressIndexFromOutput(t *testing.T) {

	currentWallet := NewWallet()

	currentWallet.InitializeSubAddressLookup(5, 20)
	for i := 0; i < 100; i++ {
		minor := uint32(i % 20)
		major := uint32(i / 20)

		want := SubAddressIndex{Major: major, Minor: minor}

		output, txPublicKey, _ := currentWallet.SubAddress(want).OneTimeAddress()

		got, ok := currentWallet.ScanOutputForSubAddress(output, txPublicKey)

		if want != got || !ok {
			t.Errorf("SubAddress not found. want: %v got: %v", want, got)
		}
	}
}

func TestPrivateOutputKey(t *testing.T) {

	currentWallet := NewWallet()

	currentWallet.InitializeSubAddressLookup(5, 20)
	for i := 0; i < 100; i++ {
		minor := uint32(i % 20)
		major := uint32(i / 20)

		index := SubAddressIndex{Major: major, Minor: minor}

		want, txPublicKey, _ := currentWallet.SubAddress(index).OneTimeAddress()

		p := currentWallet.SubaddressOutputPrivateKey(txPublicKey, index)

		got := p.MultG()

		if want.Equal(got) == 0 {
			t.Errorf("Wrong private Key: want: %v got: %v", want.Bytes(), got.Bytes())
		}
	}
}

func TestSubAddressFromKeys(t *testing.T) {
	tests := []struct {
		name               string
		network            int
		privateSpendKeyHex string
		privateViewKeyHex  string
		publicSpendKeyHex  string
		publicViewKeyHex   string
		address            string
		indexMajor         uint32
		indexMinor         uint32
		subAddress         string
	}{
		{
			name:               "Lithium Luna Test Case",
			network:            address.MainNetwork,
			privateSpendKeyHex: "5cb87ea14173499040473c1df47d62ade23537d14ad17bce93002c4c8d227204",
			privateViewKeyHex:  "75327f96ed4f4c9daacde2ac3441d487b34c0ca6daf33d0f5ad9820b4a46b403",
			publicSpendKeyHex:  "7d28e32e1538e6fa361c428c840ec2e12495cd2c8a3a3aa64a883f7cdd05ae8c",
			publicViewKeyHex:   "fefa012df0f93450cac5fe2dc58ef35af2c5b2dc5d9c9f8426d80d246e1a71a6",
			address:            "46NCgFFE9uPirN6W1xVgWdefAm2ZzG8vMUpEUiZW9eMbQaqbVneu5mVEWnVmsuUJ4iGDK8zGRtsJeP73Aggr9fAYKoYusAY",
			indexMajor:         3,
			indexMinor:         5,
			subAddress:         "8BQnJDbRY3ABPMLAKLdVNKjT38GSiPwNVPQf8i14CLQfUgtFn4cx1hgiAQHy7PDh42dS3egnXKdcVcSYy3jP9dDvHDxjq7G",
		},
	}

	for _, test := range tests {
		privateSpendKey := crypto.NewScalarFromHexString(test.privateSpendKeyHex)
		privateViewKey := crypto.NewScalarFromHexString(test.privateViewKeyHex)
		publicSpendKey := crypto.NewPointFromHexString(test.publicSpendKeyHex)
		publicViewKey := crypto.NewPointFromHexString(test.publicViewKeyHex)

		currentWallet := new(Wallet).FromKeys(privateViewKey, privateSpendKey)

		currentWallet.InitializeSubAddressLookup(test.indexMajor, test.indexMinor)

		//now check and see if the things match

		if publicSpendKey.Equal(currentWallet.address.Ks) == 0 {
			t.Errorf("Wrong public spend key: want: %v got: %v", publicSpendKey, currentWallet.address.Ks)
		}
		if publicViewKey.Equal(currentWallet.address.Kv) == 0 {
			t.Errorf("Wrong public spend key: want: %v got: %v", publicViewKey, currentWallet.address.Kv)
		}
		if test.address != currentWallet.address.Base58() {
			t.Errorf("Wrong address: want: %v got: %v", test.address, currentWallet.address.Base58())
		}
		if test.subAddress != currentWallet.SubAddress(SubAddressIndex{test.indexMajor, test.indexMinor}).Base58() {
			t.Errorf("Wrong subAddress: want: %v got: %v", test.subAddress, currentWallet.SubAddress(SubAddressIndex{test.indexMajor, test.indexMinor}).Base58())
		}
	}
}

func BenchmarkWallet_InitializeSubAddressLookup(b *testing.B) {

	currentWallet := NewWallet()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		currentWallet.InitializeSubAddressLookup(5, 20)
	}
}

func BenchmarkWallet_SubAddress(b *testing.B) {
	w := NewWallet()
	i := SubAddressIndex{1, 1}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		w.SubAddress(i)
	}
}
