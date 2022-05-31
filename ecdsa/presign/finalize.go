// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/crypto/paillier"
	"github.com/sisu-network/tss-lib/crypto/zkp"
	"github.com/sisu-network/tss-lib/tss"
)

const (
	TaskNameFinalize = "presign-finalize"
)

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

	culprits := make([]*tss.PartyID, 0, len(round.temp.presignRound6Messages))

	// Identifiable Abort Type 7 triggered during Phase 6 (GG20)
	if round.abortingT7 {
		common.Logger.Infof("round 8: Abort Type 7 code path triggered")
		q := tss.EC("ecdsa").Params().N
		kIs := make([][]byte, len(Ps))
		gMus := make([][]*crypto.ECPoint, len(Ps))
		gNus := make([][]*crypto.ECPoint, len(Ps))
		gSigmaIPfs := make([]*zkp.ECDDHProof, len(Ps))
		for i := range gMus {
			gMus[i] = make([]*crypto.ECPoint, len(Ps))
		}
		for j := range gNus {
			gNus[j] = make([]*crypto.ECPoint, len(Ps))
		}
	outer:
		for j, msg := range round.temp.presignRound7Messages {
			Pj := round.Parties().IDs()[j]
			var err error
			var paiPKJ *paillier.PublicKey
			if j == i {
				paiPKJ = &round.key.PaillierSK.PublicKey
			} else {
				paiPKJ = round.key.PaillierPKs[j]
			}

			r7msgInner, ok := msg.Content().(*PresignRound7Message).GetContent().(*PresignRound7Message_Abort)
			if !ok {
				common.Logger.Warnf("round 8: unexpected success message while in aborting mode: %+v", r7msgInner)
				culprits = append(culprits, Pj)
				continue
			}
			r7msg := r7msgInner.Abort

			// keep k_i and the g^sigma_i proof for later
			kIs[j] = r7msg.GetKI()
			if gSigmaIPfs[j], err = r7msg.UnmarshalSigmaIProof(); err != nil {
				culprits = append(culprits, Pj)
				continue
			}

			// content length sanity check
			// note: the len equivalence of each of the slices in this msg have already been checked in ValidateBasic(), so just look at the UIJ slice here
			if len(r7msg.GetMuIJ()) != len(Ps) {
				culprits = append(culprits, Pj)
				continue
			}

			// re-encrypt k_i to make sure it matches the one we have "on record"
			cA, err := paiPKJ.EncryptWithChosenRandomness(
				new(big.Int).SetBytes(r7msg.GetKI()),
				new(big.Int).SetBytes(r7msg.GetKRandI()))
			r1msg1 := round.temp.presignRound1Message1s[j].Content().(*PresignRound1Message1)
			if err != nil || !bytes.Equal(cA.Bytes(), r1msg1.GetC()) {
				culprits = append(culprits, Pj)
				continue
			}

			mus := common.ByteSlicesToBigInts(r7msg.GetMuIJ())
			muRands := common.ByteSlicesToBigInts(r7msg.GetMuRandIJ())

			// check correctness of mu_i_j
			if muIJ, muRandIJ := mus[i], muRands[i]; j != i {
				cB, err := paiPKJ.EncryptWithChosenRandomness(muIJ, muRandIJ)
				if err != nil || !bytes.Equal(cB.Bytes(), round.temp.c2JIs[j].Bytes()) {
					culprits = append(culprits, Pj)
					continue outer
				}
			}
			// compute g^mu_i_j
			for k, mu := range mus {
				if k == j {
					continue
				}
				gMus[j][k] = crypto.ScalarBaseMult(tss.EC("ecdsa"), mu.Mod(mu, q))
			}
		}
		bigR := round.temp.rI
		if 0 < len(culprits) {
			goto fail
		}
		// compute g^nu_j_i's
		for i := range Ps {
			for j := range Ps {
				if j == i {
					continue
				}
				gWJKI := round.temp.bigWs[j].ScalarMultBytes(kIs[i])
				gNus[i][j], _ = gWJKI.Sub(gMus[i][j])
			}
		}
		// compute g^sigma_i's
		for i, P := range Ps {
			gWIMulKi := round.temp.bigWs[i].ScalarMultBytes(kIs[i])
			gSigmaI := gWIMulKi
			for j := range Ps {
				if j == i {
					continue
				}
				// add sum g^mu_i_j, sum g^nu_j_i
				gMuIJ, gNuJI := gMus[i][j], gNus[j][i]
				gSigmaI, _ = gSigmaI.Add(gMuIJ)
				gSigmaI, _ = gSigmaI.Add(gNuJI)
			}
			bigSI, _ := crypto.NewECPointFromProtobuf("ecdsa", round.temp.BigSJ[P.Id])
			if !gSigmaIPfs[i].VerifySigmaI(tss.EC("ecdsa"), gSigmaI, bigR, bigSI) {
				culprits = append(culprits, P)
				continue
			}
		}
	fail:
		return round.WrapError(errors.New("round 7 consistency check failed: y != bigSJ products, Type 7 identified abort, culprits known"), culprits...)
	}

	// We have successfully generated local presgin data.
	round.temp.LocalPresignData.PartyId = round.PartyID().Id
	round.temp.LocalPresignData.ECDSAPub = round.key.ECDSAPub

	round.end <- round.temp.LocalPresignData

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
