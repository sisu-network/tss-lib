package presign

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/crypto/commitments"
	"github.com/sisu-network/tss-lib/crypto/mta"
	"github.com/sisu-network/tss-lib/ecdsa/keygen"
	"github.com/sisu-network/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *LocalPresignData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPresignData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	k := common.GetRandomPositiveInt(tss.EC().Params().N)
	gamma := common.GetRandomPositiveInt(tss.EC().Params().N)

	pointGamma := crypto.ScalarBaseMult(tss.EC(), gamma)
	cmt := commitments.NewHashCommitment(pointGamma.X(), pointGamma.Y())
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.pointGamma = pointGamma
	round.temp.deCommit = cmt.D

	i := round.PartyID().Index
	round.ok[i] = true

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		cA, pi, err := mta.AliceInit(round.key.PaillierPKs[i], k, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j])
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		r1msg1 := NewSignRound1Message1(Pj, round.PartyID(), cA, pi)
		round.temp.cis[j] = cA
		round.out <- r1msg1
	}

	r1msg2 := NewSignRound1Message2(round.PartyID(), cmt.C)
	round.temp.presignRound1Message2s[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg1 := range round.temp.presignRound1Message1s {
		if round.ok[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		msg2 := round.temp.presignRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*PresignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*PresignRound1Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks
	bigXs := round.key.BigXj

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, bigWs := PrepareForPresigning(i, len(ks), xi, ks, bigXs)

	round.temp.w = wi
	round.temp.bigWs = bigWs
	return nil
}
