// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Contains all the wrappers from the math/big package.

package geth

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// A BigInt represents a signed multi-precision integer.
type BigInt struct {
	bigint *big.Int
}

// NewBigInt allocates and returns a new BigInt set to x.
func NewBigInt(x int64) *BigInt {
	return &BigInt{big.NewInt(x)}
}

// NewBigIntFromString allocates and returns a new BigInt set to x
// interpreted in the provided base.
func NewBigIntFromString(x string, base int) *BigInt {
	b, success := new(big.Int).SetString(x, base)
	if !success {
		return nil
	}
	return &BigInt{b}
}

// GetBytes returns the absolute value of x as a big-endian byte slice.
func (bi *BigInt) GetBytes() []byte {
	return bi.bigint.Bytes()
}

// String returns the value of x as a formatted decimal string.
func (bi *BigInt) String() string {
	return bi.bigint.String()
}

// GetInt64 returns the int64 representation of x. If x cannot be represented in
// an int64, the result is undefined.
func (bi *BigInt) GetInt64() int64 {
	return bi.bigint.Int64()
}

// SetBytes interprets buf as the bytes of a big-endian unsigned integer and sets
// the big int to that value.
func (bi *BigInt) SetBytes(buf []byte) {
	bi.bigint.SetBytes(common.CopyBytes(buf))
}

// SetInt64 sets the big int to x.
func (bi *BigInt) SetInt64(x int64) {
	bi.bigint.SetInt64(x)
}

// Sign returns:
//
//	-1 if x <  0
//	 0 if x == 0
//	+1 if x >  0
//
func (bi *BigInt) Sign() int {
	return bi.bigint.Sign()
}

// SetString sets the big int to x.
//
// The string prefix determines the actual conversion base. A prefix of "0x" or
// "0X" selects base 16; the "0" prefix selects base 8, and a "0b" or "0B" prefix
// selects base 2. Otherwise the selected base is 10.
func (bi *BigInt) SetString(x string, base int) {
	bi.bigint.SetString(x, base)
}

// ADDED by Jakub Pajek (big int)
// Add returns the sum bi+bi2 as new big int.
func (bi *BigInt) Add(bi2 *BigInt) *BigInt {
	return &BigInt{new(big.Int).Add(bi.bigint, bi2.bigint)}
}

// ADDED by Jakub Pajek (big int)
// Sub returns the difference bi-bi2 as new big int.
func (bi *BigInt) Sub(bi2 *BigInt) *BigInt {
	return &BigInt{new(big.Int).Sub(bi.bigint, bi2.bigint)}
}

// ADDED by Jakub Pajek (big int)
// Mul returns the product bi*bi2 as new big int.
func (bi *BigInt) Mul(bi2 *BigInt) *BigInt {
	return &BigInt{new(big.Int).Mul(bi.bigint, bi2.bigint)}
}

// ADDED by Jakub Pajek (big int)
// Div returns the quotient bi/bi2 as new big int (panics on division by 0).
func (bi *BigInt) Div(bi2 *BigInt) *BigInt {
	return &BigInt{new(big.Int).Div(bi.bigint, bi2.bigint)}
}

// ADDED by Jakub Pajek (big int)
// DivMod returns the quotient bi/bi2 and modulus bi%bi2 as two new big ints (panics on division by 0).
func (bi *BigInt) DivMod(bi2 *BigInt) *BigInts {
	bigInts := NewBigInts(2)
	q, m := new(big.Int).DivMod(bi.bigint, bi2.bigint, new(big.Int))
	bigInts.Set(0, &BigInt{q})
	bigInts.Set(1, &BigInt{m})
	return bigInts
}

// BigInts represents a slice of big ints.
type BigInts struct{ bigints []*big.Int }

// NewBigInts creates a slice of uninitialized big numbers.
func NewBigInts(size int) *BigInts {
	return &BigInts{
		bigints: make([]*big.Int, size),
	}
}

// Size returns the number of big ints in the slice.
func (bi *BigInts) Size() int {
	return len(bi.bigints)
}

// Get returns the bigint at the given index from the slice.
func (bi *BigInts) Get(index int) (bigint *BigInt, _ error) {
	if index < 0 || index >= len(bi.bigints) {
		return nil, errors.New("index out of bounds")
	}
	return &BigInt{bi.bigints[index]}, nil
}

// Set sets the big int at the given index in the slice.
func (bi *BigInts) Set(index int, bigint *BigInt) error {
	if index < 0 || index >= len(bi.bigints) {
		return errors.New("index out of bounds")
	}
	bi.bigints[index] = bigint.bigint
	return nil
}

// GetString returns the value of x as a formatted string in some number base.
func (bi *BigInt) GetString(base int) string {
	return bi.bigint.Text(base)
}

// ADDED by Jakub Pajek (big float)
// A BigFloat represents a multi-precision floating point number.
type BigFloat struct {
	bigfloat *big.Float
}

// ADDED by Jakub Pajek (big float)
// NewBigFloat allocates and returns a new BigFloat set to x (panics if x is a NaN).
func NewBigFloat(x float64) *BigFloat {
	return &BigFloat{big.NewFloat(x)}
}

// ADDED by Jakub Pajek (big float)
// NewBigFloatFromString allocates and returns a new BigFloat set to x, or nil on parsing failure.
func NewBigFloatFromString(x string) *BigFloat {
	if b, success := new(big.Float).SetString(x); success {
		return &BigFloat{b}
	}
	return nil
}

// ADDED by Jakub Pajek (big float)
// NewBigFloatFromInt allocates and returns a new BigFloat set to the (possibly rounded) value of x.
func NewBigFloatFromInt(x *BigInt) *BigFloat {
	return &BigFloat{new(big.Float).SetInt(x.bigint)}
}

// ADDED by Jakub Pajek (big float)
// String returns the value of x as a formatted string like x.Text('g', 10).
func (bi *BigFloat) String() string {
	return bi.bigfloat.String()
}

// ADDED by Jakub Pajek (big float)
// Text returns the value of x as a formatted string according to the given format and precision.
func (bi *BigFloat) Text(format int, prec int) string {
	return bi.bigfloat.Text(byte(format), prec)
}

// ADDED by Jakub Pajek (big float)
// GetFloat64 returns the float64 value nearest to x. Rounding error is ignored.
func (bi *BigFloat) GetFloat64() float64 {
	b, _ := bi.bigfloat.Float64()
	return b
}

// ADDED by Jakub Pajek (big float)
// SetFloat64 sets the big float to the (possibly rounded) value of x (panics if x is a NaN).
func (bi *BigFloat) SetFloat64(x float64) {
	bi.bigfloat.SetFloat64(x)
}

// ADDED by Jakub Pajek (big float)
// GetInt returns the big int value nearest to x. Rounding error is ignored.
func (bi *BigFloat) GetInt() *BigInt {
	b, _ := bi.bigfloat.Int(nil)
	return &BigInt{b}
}

// ADDED by Jakub Pajek (big float)
// SetInt sets the big float to the (possibly rounded) value of x.
func (bi *BigFloat) SetInt(x *BigInt) {
	bi.bigfloat.SetInt(x.bigint)
}

// ADDED by Jakub Pajek (big float)
// Sign returns:
//
//	-1 if x <  0
//	 0 if x == 0
//	+1 if x >  0
//
func (bi *BigFloat) Sign() int {
	return bi.bigfloat.Sign()
}

// ADDED by Jakub Pajek (big float)
// SetString sets the big float to x and returns boolean indicating success.
// On failure the value of big float becomes undefined.
func (bi *BigFloat) SetString(x string) bool {
	_, success := bi.bigfloat.SetString(x)
	return success
}

// ADDED by Jakub Pajek (big float)
// Add returns the rounded sum bi+bi2 as new big float  (panics if both operands are infinities with opposite signs).
func (bi *BigFloat) Add(bi2 *BigFloat) *BigFloat {
	return &BigFloat{new(big.Float).Add(bi.bigfloat, bi2.bigfloat)}
}

// ADDED by Jakub Pajek (big float)
// Sub returns the rounded difference bi-bi2 as new big float (panics if both operands are infinities with equal signs).
func (bi *BigFloat) Sub(bi2 *BigFloat) *BigFloat {
	return &BigFloat{new(big.Float).Sub(bi.bigfloat, bi2.bigfloat)}
}

// ADDED by Jakub Pajek (big float)
// Mul returns the rounded product bi*bi2 as new big float (panics if one operand is zero and the other operand an infinity).
func (bi *BigFloat) Mul(bi2 *BigFloat) *BigFloat {
	return &BigFloat{new(big.Float).Mul(bi.bigfloat, bi2.bigfloat)}
}

// ADDED by Jakub Pajek (big float)
// Quo returns the rounded quotient bi/bi2 as new big float (panics if both operands are zero or infinities).
func (bi *BigFloat) Quo(bi2 *BigFloat) *BigFloat {
	return &BigFloat{new(big.Float).Quo(bi.bigfloat, bi2.bigfloat)}
}
