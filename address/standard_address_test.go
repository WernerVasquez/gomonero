package address

import (
	"bytes"
	"encoding/hex"
	"errors"
	"gomonero/crypto"
	"gomonero/err_msg"
	"testing"
)

func TestAddressError(t *testing.T) {
	_, err := NewStandardAddress("")
	//want := errors.New("StandardAddress is the wrong length")
	if !errors.Is(err, err_msg.LengthError) {
		t.Errorf("want: %s, got: %s", err_msg.LengthError, err)
	}
	_, err = NewStandardAddress("46w3n5EGhBeZkYmKvQRsd8UK9GhvcbYWQDobJape3NLMMFEjFZnJ3CnRmeKspubQGiP8iMTwFEX2QiBsjUkjKT4SSPd3fK1")
	//want = errors.New("Checksum does not validate")
	if !errors.Is(err, err_msg.ChecksumError) {
		t.Errorf("want: %s, got: %s", err_msg.ChecksumError, err)
	}
}

func TestAddress(t *testing.T) {
	tests := []struct {
		name           string
		network        int
		spendingKeyHex string
		viewingKeyHex  string
		address        string
	}{
		{
			name:           "generic",
			network:        MainNetwork,
			spendingKeyHex: "8c1a9d5ff5aaf1c3cdeb2a1be62f07a34ae6b15fe47a254c8bc240f348271679",
			viewingKeyHex:  "0a29b163e392eb9416a52907fd7d3b84530f8d02ff70b1f63e72fdcb54cf7fe1",
			address:        "46w3n5EGhBeZkYmKvQRsd8UK9GhvcbYWQDobJape3NLMMFEjFZnJ3CnRmeKspubQGiP8iMTwFEX2QiBsjUkjKT4SSPd3fKp",
		},
		{
			name:           "generic 2",
			network:        MainNetwork,
			spendingKeyHex: "5007b84275af9a173c2080683afce90b2157ab640c18ddd5ce3e060a18a9ce99",
			viewingKeyHex:  "27024b45150037b677418fcf11ba9675494ffdf994f329b9f7a8f8402b7934a0",
			address:        "44f1Y84r9Lu4tQdLWRxV122rygfhUeVBrcmBaqcYCwUHScmf1ht8DFLXX9YN4T7nPPLcpqYLUdrFiY77nQYeH9RuK9gg4p6",
		},
		{
			name:           "require 1 padding in middle",
			network:        MainNetwork,
			spendingKeyHex: "6add197bd82866e8bfbf1dc2fdf49873ec5f679059652da549cd806f2b166756",
			viewingKeyHex:  "f5cf2897088fda0f7ac1c42491ed7d558a46ee41d0c81d038fd53ff4360afda0",
			address:        "45fzHekTd5FfvxWBPYX2TqLPbtWjaofxYUeWCi6BRQXYFYd85sY2qw73bAuKhqY7deFJr6pN3STY81bZ9x2Zf4nGKASksqe",
		},
		{
			name:           "require 1 padding in last chunk",
			network:        MainNetwork,
			spendingKeyHex: "50defe92d88b19aaf6bf66f061dd4380b79866a4122b25a03bceb571767dbe7b",
			viewingKeyHex:  "f8f6f28283921bf5a17f0bcf4306233fc25ce9b6276154ad0de22aebc5c67702",
			address:        "44grjkXtDHJVbZgtU1UKnrNXidcHfZ3HWToU5WjR3KgHMjgwrYLjXC6i5vm3HCp4vnBfYaNEyNiuZVwqtHD2SenS1JBRyco",
		},
		{
			name:           "testnet",
			network:        TestNetwork,
			spendingKeyHex: "8de9cce254e60cd940abf6c77ef344c3a21fad74320e45734fbfcd5870e5c875",
			viewingKeyHex:  "27024b45150037b677418fcf11ba9675494ffdf994f329b9f7a8f8402b7934a0",
			address:        "9xYZvCDf6aFdLd7Qawg5XHZitWLKoeFvcLHfe5GxsGCFLbXSWeQNKciXX9YN4T7nPPLcpqYLUdrFiY77nQYeH9RuK9bogZJ",
		},
		{
			name:           "https://xmr.llcoins.net",
			network:        MainNetwork,
			spendingKeyHex: "cd278101fc0f8f74a70273894aa418a2eae1c10d3f0a71d370da731be8af159b",
			viewingKeyHex:  "5fb5a16420bca5aca8bb49019846f5b08a7f849e5a5cbedd615580c2f4ede22a",
			address:        "49Q2Rv3mj5YLWg75nV1Pr7UFWE7jGsqMicNEyY8czSngSzKdFi2yjX2Vt1ZPHfHForWXfoGCCav4de2fbGLqoCRP5o6gTqc",
		},
	}
	var base58 string
	var spendingKey, viewingKey []byte
	for _, test := range tests {
		spendingKey, _ = hex.DecodeString(test.spendingKeyHex)
		viewingKey, _ = hex.DecodeString(test.viewingKeyHex)
		address, _ := NewStandardAddress(test.address)
		if address.Network != test.network {
			t.Errorf("%s: want: %d, got: %d", test.name, test.network, address.Network)
			continue
		}
		if bytes.Compare(address.Ks.Bytes(), spendingKey) != 0 {
			t.Errorf("%s: want: %x, got: %x", test.name, spendingKey, address.Ks.Bytes())
			continue
		}
		if bytes.Compare(address.Kv.Bytes(), viewingKey) != 0 {
			t.Errorf("%s: want: %x, got: %x", test.name, viewingKey, address.Kv.Bytes())
			continue
		}
		base58 = address.Base58()
		if base58 != test.address {
			t.Errorf("%s: want: %s, got: %s", test.name, test.address, base58)
			continue
		}
	}
}

func TestAddressFromKeys(t *testing.T) {
	tests := []struct {
		name               string
		network            int
		privateSpendKeyHex string
		privateViewKeyHex  string
		publicSpendKeyHex  string
		publicViewKeyHex   string
		address            string
	}{
		{
			name:               "https://xmr.llcoins.net",
			network:            MainNetwork,
			privateSpendKeyHex: "6bd3770e5b4aac434641ccf49ede426115d340b75a190808351b0eca62262203",
			privateViewKeyHex:  "dba32ad135b7ae788401487abea6b7bdb14fb4d51f58f334c9ea2faaf961670c",
			publicSpendKeyHex:  "cd278101fc0f8f74a70273894aa418a2eae1c10d3f0a71d370da731be8af159b",
			publicViewKeyHex:   "5fb5a16420bca5aca8bb49019846f5b08a7f849e5a5cbedd615580c2f4ede22a",
			address:            "49Q2Rv3mj5YLWg75nV1Pr7UFWE7jGsqMicNEyY8czSngSzKdFi2yjX2Vt1ZPHfHForWXfoGCCav4de2fbGLqoCRP5o6gTqc",
		},
	}

	for _, test := range tests {
		tempSlice, _ := hex.DecodeString(test.privateSpendKeyHex)
		privateSpendKey := crypto.NewScalarFromBytes(tempSlice)
		tempSlice, _ = hex.DecodeString(test.privateViewKeyHex)
		privateViewKey := crypto.NewScalarFromBytes(tempSlice)
		spendingKey, _ := hex.DecodeString(test.publicSpendKeyHex)
		viewingKey, _ := hex.DecodeString(test.publicViewKeyHex)
		address, _ := NewStandardAddressFromKeys(privateSpendKey, privateViewKey, test.network)
		if address.Network != test.network {
			t.Errorf("%s: want: %d, got: %d", test.name, test.network, address.Network)
			continue
		}
		if bytes.Compare(address.Ks.Bytes(), spendingKey) != 0 {
			t.Errorf("%s: want: %x, got: %x", test.name, spendingKey, address.Ks.Bytes())
			continue
		}
		if bytes.Compare(address.Kv.Bytes(), viewingKey) != 0 {
			t.Errorf("%s: want: %x, got: %x", test.name, viewingKey, address.Kv.Bytes())
			continue
		}
		base58 := address.Base58()
		if base58 != test.address {
			t.Errorf("%s: want: %s, got: %s", test.name, test.address, base58)
			continue
		}
	}
}
