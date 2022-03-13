package err_msg

import "errors"

//common

var ErrOutOfBounds = errors.New("index out of bounds")

var ErrMismatchedLengths = errors.New("arguments have mismatched lengths")

//address

var LengthError = errors.New("address is the wrong length")
var ChecksumError = errors.New("checksum does not validate")
var AddressTypeError = errors.New("wrong address type")

//jamtis

var ErrViewTag = errors.New("view tag does not match")
var ErrLookup = errors.New("address not found in lookup table")
var ErrJanus = errors.New("possible Janus attack")

//crypto

var InvalidPowersOfScalarN = errors.New("PowersOfScalar: n must be 1 or greater")

//keySlice

var IncompatibleSizesAB = errors.New("incompatible sizes of a and b")
var InvalidScalarSliceN = errors.New("NewScalarSlice: n must be 1 or greater")
