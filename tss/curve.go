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

const (
	EcdsaScheme = "ecdsa"
	EddsaScheme = "eddsa"
)

var (
	ed, ec elliptic.Curve
)

// Init default curve (secp256k1)
func init() {
	ec = s256k1.S256()
	ed = edwards.Edwards()
}

// EC returns the current elliptic curve in use. The default is secp256k1
func EC(scheme string) elliptic.Curve {
	switch strings.ToLower(scheme) {
	case "", EcdsaScheme:
		return ec
	case EddsaScheme:
		return ed
	default:
		panic(fmt.Errorf("Unknown curve: %s", scheme))
	}
}

func GetCurveScheme(curve elliptic.Curve) string {
	if curve == ec {
		return "ecdsa"
	} else if curve == ed {
		return "eddsa"
	}

	panic(fmt.Errorf("Unknown curve %v", curve))
}
