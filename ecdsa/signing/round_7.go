// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/hashicorp/go-multierror"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/tss"
)

func (round *round7) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 7
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	culprits := make([]*tss.PartyID, 0, len(round.temp.signRound6Messages))

	// bigR is stored as bytes for the OneRoundData protobuf struct
	bigRX, bigRY := new(big.Int).SetBytes(round.temp.BigR.GetX()), new(big.Int).SetBytes(round.temp.BigR.GetY())
	bigR := crypto.NewECPointNoCurveCheck(tss.EC(), bigRX, bigRY)

	h, err := crypto.ECBasePoint2(tss.EC())
	if err != nil {
		return round.WrapError(err, Pi)
	}

	bigSJ := make(map[string]*common.ECPoint, len(round.temp.signRound6Messages))
	bigSJProducts := (*crypto.ECPoint)(nil)
	var multiErr error
	for j, msg := range round.temp.signRound6Messages {
		Pj := round.Parties().IDs()[j]
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		r6msgInner, ok := msg.Content().(*SignRound6Message).GetContent().(*SignRound6Message_Success)
		if !ok {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, fmt.Errorf("unexpected abort message while in success mode: %+v", r6msgInner))
			continue
		}
		r6msg := r6msgInner.Success

		TI, err := r3msg.UnmarshalTI()
		if err != nil {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, err)
			continue
		}
		bigSI, err := r6msg.UnmarshalSI()
		if err != nil {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, err)
			continue
		}
		bigSJ[Pj.Id] = bigSI.ToProtobufPoint()

		// ZK STProof check
		if j != i {
			stProof, err := r6msg.UnmarshalSTProof()
			if err != nil {
				culprits = append(culprits, Pj)
				multiErr = multierror.Append(multiErr, err)
				continue
			}
			if ok := stProof.Verify(bigSI, TI, bigR, h); !ok {
				culprits = append(culprits, Pj)
				multiErr = multierror.Append(multiErr, errors.New("STProof verify failure"))
				continue
			}
		}

		// bigSI consistency check
		if bigSJProducts == nil {
			bigSJProducts = bigSI
			continue
		}
		if bigSJProducts, err = bigSJProducts.Add(bigSI); err != nil {
			culprits = append(culprits, Pj)
			multiErr = multierror.Append(multiErr, err)
			continue
		}
	}
	if 0 < len(culprits) {
		return round.WrapError(multiErr, culprits...)
	}

	round.temp.rI = bigR
	round.temp.BigSJ = bigSJ
	if y := round.presignData.ECDSAPub; !bigSJProducts.Equals(y) {
		round.abortingT7 = true
		common.Logger.Warnf("round 7: consistency check failed: y != bigSJ products, entering Type 7 identified abort")

		// If we abort here, one-round mode won't matter now - we will proceed to round "8" anyway.
		r7msg := NewSignRound7MessageAbort(Pi, &round.temp.r7AbortData)
		round.temp.signRound7Messages[i] = r7msg
		round.out <- r7msg
		return nil
	}
	// wipe sensitive data for gc, not used from here
	round.temp.r7AbortData = SignRound7Message_AbortData{}

	// PRE-PROCESSING FINISHED
	// If we are in one-round signing mode (msg is nil), we will exit out with the current state here and we are done.
	round.temp.T = int32(len(round.Parties().IDs()) - 1)
	round.data.OneRoundData = &round.temp.SignatureData_OneRoundData
	if round.temp.m == nil {
		round.end <- round.data
		for j := range round.ok {
			round.ok[j] = true
		}
		return nil
	}

	// Continuing the full online protocol.
	sI := FinalizeGetOurSigShare(round.data, round.temp.m)
	round.temp.sI = sI

	r7msg := NewSignRound7MessageSuccess(round.PartyID(), sI)
	round.temp.signRound7Messages[i] = r7msg
	round.out <- r7msg
	return nil
}

func (round *round7) Update() (bool, *tss.Error) {
	// Collect messages for the full online protocol OR identified abort of type 7.
	for j, msg := range round.temp.signRound7Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round7) CanAccept(msg tss.ParsedMessage) bool {
	// Collect messages for the full online protocol OR identified abort of type 7.
	if _, ok := msg.Content().(*SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round7) NextRound() tss.Round {
	// If we are in one-round signing mode (msg is nil), we will exit out with the current state here and there are no further rounds.
	if !round.abortingT7 && round.temp.m == nil {
		return nil
	}
	// Continuing the full online protocol.
	round.started = false
	return &finalization{round}
}
