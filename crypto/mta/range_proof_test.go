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

package mta

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/crypto/paillier"
	"github.com/sisu-network/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

func TestProveRangeAlice(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk, err := paillier.GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(q)
	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(primes)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(pk, c, NTildei, h1i, h2i, m, r)
	assert.NoError(t, err)

	ok := proof.Verify(pk, NTildei, h1i, h2i, c)
	assert.True(t, ok, "proof must verify")
}
