package presign

import (
	"errors"
	"fmt"
	"math/big"

	cmt "github.com/sisu-network/tss-lib/crypto/commitments"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/crypto/mta"
	"github.com/sisu-network/tss-lib/ecdsa/keygen"
	"github.com/sisu-network/tss-lib/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data common.PresignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- common.PresignatureData
	}

	localMessageStore struct {
		presignRound1Message1s,
		presignRound1Message2s,
		presignRound2Messages,
		presignRound3Messages,
		presignRound4Messages,
		presignRound5Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		w,
		k,
		theta,
		thetaInverse,
		sigma,
		gamma *big.Int
		cis        []*big.Int
		bigWs      []*crypto.ECPoint
		pointGamma *crypto.ECPoint
		deCommit   cmt.HashDeCommitment

		// round 2
		betas, // return value of Bob_mid
		c1jis,
		c2jis,
		vs []*big.Int // return value of Bob_mid_wc
		pi1jis []*mta.ProofBob
		pi2jis []*mta.ProofBobWC

		// round 5
		rx,
		ry,
		rSigma *big.Int

		bigR *crypto.ECPoint
	}
)

func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- common.PresignatureData,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      common.PresignatureData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.presignRound1Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound1Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound4Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.cis = make([]*big.Int, partyCount)
	p.temp.bigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.betas = make([]*big.Int, partyCount)
	p.temp.c1jis = make([]*big.Int, partyCount)
	p.temp.c2jis = make([]*big.Int, partyCount)
	p.temp.pi1jis = make([]*mta.ProofBob, partyCount)
	p.temp.pi2jis = make([]*mta.ProofBobWC, partyCount)
	p.temp.vs = make([]*big.Int, partyCount)
	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName, func(round tss.Round) *tss.Error {
		round1, ok := round.(*round1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *PresignRound1Message1:
		p.temp.presignRound1Message1s[fromPIdx] = msg
	case *PresignRound1Message2:
		p.temp.presignRound1Message2s[fromPIdx] = msg
	case *PresignRound2Message:
		p.temp.presignRound2Messages[fromPIdx] = msg
	case *PresignRound3Message:
		p.temp.presignRound3Messages[fromPIdx] = msg
	case *PresignRound4Message:
		p.temp.presignRound4Messages[fromPIdx] = msg

	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
