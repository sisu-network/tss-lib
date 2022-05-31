// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkp_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	. "github.com/sisu-network/tss-lib/crypto/zkp"
	"github.com/sisu-network/tss-lib/tss"
)

func TestSchnorrProof(t *testing.T) {
	curve := "ecdsa"
	q := tss.EC(curve).Params().N
	u := common.GetRandomPositiveInt(q)
	uG := crypto.ScalarBaseMult(tss.EC(curve), u)
	proof, _ := NewDLogProof(curve, u, uG)

	assert.True(t, proof.Alpha.IsOnCurve())
	assert.NotZero(t, proof.Alpha.X())
	assert.NotZero(t, proof.Alpha.Y())
	assert.NotZero(t, proof.T)
}

func TestSchnorrProofVerify(t *testing.T) {
	curve := "ecdsa"
	q := tss.EC(curve).Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(curve), u)

	proof, _ := NewDLogProof(curve, u, X)
	res := proof.Verify(curve, X)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	curve := "ecdsa"
	q := tss.EC(curve).Params().N
	u := common.GetRandomPositiveInt(q)
	u2 := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(curve), u)
	X2 := crypto.ScalarBaseMult(tss.EC(curve), u2)

	proof, _ := NewDLogProof(curve, u2, X2)
	res := proof.Verify(curve, X)

	assert.False(t, res, "verify result must be false")
}
