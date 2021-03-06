// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/hashicorp/go-multierror"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/ecdsa/presign"
	"github.com/sisu-network/tss-lib/tss"
)

const (
	TaskNameFinalize = "signing-finalize"
)

// FinalizeGetOurSigShare is called in one-round signing mode to build a final signature given others' s_i shares and a msg.
// Note: each P in otherPs should correspond with that P's s_i at the same index in otherSIs.
func FinalizeGetAndVerifyFinalSig(
	presignData presign.LocalPresignData,
	pk *ecdsa.PublicKey,
	msg *big.Int,
	ourP *tss.PartyID,
	ourSI *big.Int,
	otherSIs map[*tss.PartyID]*big.Int,
) (*common.ECSignature, *btcec.Signature, *tss.Error) {
	if len(otherSIs) == 0 {
		return nil, nil, FinalizeWrapError(errors.New("len(otherSIs) == 0"), ourP)
	}
	if presignData.T != int32(len(otherSIs)) {
		return nil, nil, FinalizeWrapError(errors.New("len(otherSIs) != T"), ourP)
	}

	N := tss.EC("ecdsa").Params().N
	modN := common.ModInt(N)

	bigR, err := crypto.NewECPoint(tss.EC("ecdsa"),
		new(big.Int).SetBytes(presignData.BigR.GetX()),
		new(big.Int).SetBytes(presignData.BigR.GetY()))
	if err != nil {
		return nil, nil, FinalizeWrapError(err, ourP)
	}

	r, s := bigR.X(), ourSI
	culprits := make([]*tss.PartyID, 0, len(otherSIs))

	for Pj, sJ := range otherSIs {
		bigRBarJBz := presignData.BigRBarJ[Pj.Id]
		bigSJBz := presignData.BigSJ[Pj.Id]

		if Pj == nil || bigRBarJBz == nil || bigSJBz == nil {
			return nil, nil, FinalizeWrapError(errors.New("in loop: Pj or map value s_i is nil"), Pj)
		}

		// prep for identify aborts in phase 7
		bigRBarJ, err := crypto.NewECPoint(tss.EC("ecdsa"),
			new(big.Int).SetBytes(bigRBarJBz.GetX()),
			new(big.Int).SetBytes(bigRBarJBz.GetY()))
		if err != nil {
			culprits = append(culprits, Pj)
			continue
		}
		bigSI, err := crypto.NewECPoint(tss.EC("ecdsa"),
			new(big.Int).SetBytes(bigSJBz.GetX()),
			new(big.Int).SetBytes(bigSJBz.GetY()))
		if err != nil {
			culprits = append(culprits, Pj)
			continue
		}

		// identify aborts of "type 8" in phase 7
		// verify that R^S_i = Rdash_i^m * S_i^r
		bigRBarIM, bigSIR, bigRSI := bigRBarJ.ScalarMult(msg), bigSI.ScalarMult(r), bigR.ScalarMult(sJ)
		bigRBarIMBigSIR, err := bigRBarIM.Add(bigSIR)
		if err != nil || !bigRSI.Equals(bigRBarIMBigSIR) {
			culprits = append(culprits, Pj)
			continue
		}

		s = modN.Add(s, sJ)
	}
	if 0 < len(culprits) {
		return nil, nil, FinalizeWrapError(errors.New("identify abort assertion fail in phase 7"), ourP, culprits...)
	}

	// Calculate Recovery ID: It is not possible to compute the public key out of the signature itself;
	// the Recovery ID is used to enable extracting the public key from the signature.
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	recId := 0
	if bigR.X().Cmp(N) > 0 {
		recId = 2
	}
	if bigR.Y().Bit(0) != 0 {
		recId |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(N, 1)
	if s.Cmp(secp256k1halfN) > 0 {
		s.Sub(N, s)
		recId ^= 1
	}

	ok := ecdsa.Verify(pk, msg.Bytes(), r, s)
	if !ok {
		return nil, nil, FinalizeWrapError(fmt.Errorf("signature verification 1 failed"), ourP)
	}

	// save the signature for final output
	signature := new(common.ECSignature)
	signature.R, signature.S = r.Bytes(), s.Bytes()
	signature.Signature = append(r.Bytes(), s.Bytes()...)
	signature.SignatureRecovery = []byte{byte(recId)}
	signature.M = msg.Bytes()

	btcecSig := &btcec.Signature{R: r, S: s}
	if ok = btcecSig.Verify(msg.Bytes(), (*btcec.PublicKey)(pk)); !ok {
		return nil, nil, FinalizeWrapError(fmt.Errorf("signature verification 2 failed"), ourP)
	}

	return signature, btcecSig, nil
}

func FinalizeWrapError(err error, victim *tss.PartyID, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskNameFinalize, 8, victim, culprits...)
}

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 8
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	Pi := round.PartyID()
	i := Pi.Index

	culprits := make([]*tss.PartyID, 0, len(round.temp.signRound1Message))

	ourSI := round.temp.sI
	otherSIs := make(map[*tss.PartyID]*big.Int, len(Ps)-1)

	var multiErr error
	for j, msg := range round.temp.signRound1Message {
		if j == i {
			continue
		}
		Pj := round.Parties().IDs()[j]

		r1msg := msg.Content().(*SignRound1Message)

		if !msg.ValidateBasic() {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, fmt.Errorf("round 1: unexpected abort message while in success mode: %+v", r1msg))
			continue
		}
		sI := r1msg.Si
		otherSIs[Pj] = new(big.Int).SetBytes(sI)
	}
	if 0 < len(culprits) {
		return round.WrapError(multiErr, culprits...)
	}

	pk := &ecdsa.PublicKey{
		Curve: tss.EC("ecdsa"),
		X:     round.presignData.ECDSAPub.X(),
		Y:     round.presignData.ECDSAPub.Y(),
	}
	signature, _, err := FinalizeGetAndVerifyFinalSig(*round.presignData, pk, round.temp.m, round.PartyID(), ourSI, otherSIs)
	if err != nil {
		return err
	}

	round.end <- signature
	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
