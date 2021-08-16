package presign

import (
	"errors"
	"flag"

	errors2 "github.com/pkg/errors"
	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/crypto/commitments"
	"github.com/sisu-network/tss-lib/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	R := round.temp.pointGamma
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		r1msg2 := round.temp.presignRound1Message2s[j].Content().(*PresignRound1Message2)
		r4msg := round.temp.presignRound4Messages[j].Content().(*PresignRound4Message)
		SCj, SDj := r1msg2.UnmarshalCommitment(), r4msg.UnmarshalDeCommitment()
		cmtDeCmt := commitments.HashCommitDecommit{C: SCj, D: SDj}
		ok, bigGammaJ := cmtDeCmt.DeCommit()
		if !ok || len(bigGammaJ) != 2 {
			return round.WrapError(errors.New("commitment verify failed"), Pj)
		}
		bigGammaJPoint, err := crypto.NewECPoint(tss.EC(), bigGammaJ[0], bigGammaJ[1])
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigGammaJ)"), Pj)
		}
		proof, err := r4msg.UnmarshalZKProof()
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal bigGamma proof"), Pj)
		}
		ok = proof.Verify(bigGammaJPoint)
		if !ok {
			return round.WrapError(errors.New("failed to prove bigGamma"), Pj)
		}
		R, err = R.Add(bigGammaJPoint)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "R.Add(bigGammaJ)"), Pj)
		}
	}

	R = R.ScalarMult(round.temp.thetaInverse)
	N := tss.EC().Params().N
	modN := common.ModInt(N)
	rx := R.X()
	ry := R.Y()
	rSigma := modN.Mul(rx, round.temp.sigma)

	if flag.Lookup("test.v") == nil {
		// clear temp.w and temp.k from memory. Keep it in test mode
		round.temp.w = zero
		round.temp.k = zero
	}

	round.temp.rx = rx
	round.temp.ry = ry
	round.temp.bigR = R
	round.temp.rSigma = rSigma

	presignData := common.PresignatureData{
		W:       round.temp.w.Bytes(),
		K:       round.temp.k.Bytes(),
		Sigma:   round.temp.sigma.Bytes(),
		RSigmai: rSigma.Bytes(),
	}

	round.end <- presignData

	return nil
}

func (round *round5) Update() (bool, *tss.Error) {
	// TODO: Add 2 more rounds for Phase 5, 6 to do ZK proof for R & Si.
	return false, nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	// TODO: Add 2 more rounds for Phase 5, 6 to do ZK proof for R & Si.
	return false
}

func (round *round5) NextRound() tss.Round {
	return nil
}
