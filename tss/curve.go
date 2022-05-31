// Copyright © Sisu network contributors
//
// This file is a derived work from Binance's tss-lib. Please refer to the
// LICENSE copyright file at the root directory for usage of the source code.
//
// Original license:
//
// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"fmt"
	"strings"

	s256k1 "github.com/btcsuite/btcd/btcec"

	"github.com/decred/dcrd/dcrec/edwards/v2"
)

var (
	ed, ec elliptic.Curve
)

// Init default curve (secp256k1)
func init() {
	ec = s256k1.S256()
	ed = edwards.Edwards()

	fmt.Println("ed.Params().Name = ", ed.Params().Name)
}

// EC returns the current elliptic curve in use. The default is secp256k1
func EC(name string) elliptic.Curve {
	switch strings.ToLower(name) {
	case "", "ec", "ecdsa", "secp256k1":
		return ec
	case "ed", "eddsa":
		return ed
	default:
		panic(fmt.Errorf("Unknown curve: %s", name))
	}
}

// // EC returns the current elliptic curve in use. The default is secp256k1
// func EC() elliptic.Curve {
// 	return ec
// }

// // SetCurve sets the curve used by TSS. Must be called before Start. The default is secp256k1
// func SetCurve(curve elliptic.Curve) {
// 	if curve == nil {
// 		panic(errors.New("SetCurve received a nil curve"))
// 	}
// 	ec = curve
// }
