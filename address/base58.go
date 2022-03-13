/*
Monero Utilities
Copyright (c) 2017, Paxos <jimmy.song@paxos.com>

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package address

import (
	"math/big"
	"strings"
)

//TODO test if this should be replaced with something faster

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Lookup = map[string]int{
	"1": 0, "2": 1, "3": 2, "4": 3, "5": 4, "6": 5, "7": 6, "8": 7,
	"9": 8, "A": 9, "B": 10, "C": 11, "D": 12, "E": 13, "F": 14, "G": 15,
	"H": 16, "J": 17, "K": 18, "L": 19, "M": 20, "N": 21, "P": 22, "Q": 23,
	"R": 24, "S": 25, "T": 26, "U": 27, "V": 28, "W": 29, "X": 30, "Y": 31,
	"Z": 32, "a": 33, "b": 34, "c": 35, "d": 36, "e": 37, "f": 38, "g": 39,
	"h": 40, "i": 41, "j": 42, "k": 43, "m": 44, "n": 45, "o": 46, "p": 47,
	"q": 48, "r": 49, "s": 50, "t": 51, "u": 52, "v": 53, "w": 54, "x": 55,
	"y": 56, "z": 57,
}
var bigBase = big.NewInt(58)

func encodeChunk(raw []byte, padding int) (result string) {
	remainder := new(big.Int)
	remainder.SetBytes(raw)
	bigZero := new(big.Int)
	for remainder.Cmp(bigZero) > 0 {
		current := new(big.Int)
		remainder.DivMod(remainder, bigBase, current)
		result = string(BASE58[current.Int64()]) + result
	}
	if len(result) < padding {
		result = strings.Repeat("1", padding-len(result)) + result
	}
	return
}

func decodeChunk(encoded string) (result []byte) {
	bigResult := big.NewInt(0)
	currentMultiplier := big.NewInt(1)
	tmp := new(big.Int)
	for i := len(encoded) - 1; i >= 0; i-- {
		tmp.SetInt64(int64(base58Lookup[string(encoded[i])]))
		tmp.Mul(currentMultiplier, tmp)
		bigResult.Add(bigResult, tmp)
		currentMultiplier.Mul(currentMultiplier, bigBase)
	}
	result = bigResult.Bytes()
	return
}

func EncodeMoneroBase58(data ...[]byte) (result string) {
	var combined []byte
	for _, item := range data {
		combined = append(combined, item...)
	}
	length := len(combined)
	rounds := length / 8
	for i := 0; i < rounds; i++ {
		result += encodeChunk(combined[i*8:(i+1)*8], 11)
	}
	if length%8 > 0 {
		result += encodeChunk(combined[rounds*8:], 7)
	}
	return
}

func DecodeMoneroBase58(data string) (result []byte) {
	length := len(data)
	rounds := length / 11
	for i := 0; i < rounds; i++ {
		result = append(result, decodeChunk(data[i*11:(i+1)*11])...)
	}
	if length%11 > 0 {
		result = append(result, decodeChunk(data[rounds*11:])...)
	}
	return
}
