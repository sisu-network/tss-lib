// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package presign

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	cmt "github.com/sisu-network/tss-lib/crypto/commitments"
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

		// outbound messaging
		out chan<- tss.Message
		end chan<- *LocalPresignData
	}

	localMessageStore struct {
		presignRound1Message1s,
		presignRound1Message2s,
		presignRound2Messages,
		presignRound3Messages,
		presignRound4Messages,
		presignRound5Messages,
		presignRound6Messages,
		presignRound7Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		wI,
		cAKI,
		rAKI,
		deltaI,
		sigmaI,
		gammaI *big.Int
		c1Is     []*big.Int
		bigWs    []*crypto.ECPoint
		gammaIG  *crypto.ECPoint
		deCommit cmt.HashDeCommitment

		// round 2
		betas, // return value of Bob_mid
		c1JIs,
		c2JIs,
		vJIs []*big.Int // return value of Bob_mid_wc
		pI1JIs []*mta.ProofBob
		pI2JIs []*mta.ProofBobWC

		// round 3
		lI *big.Int

		// round 5
		bigGammaJs  []*crypto.ECPoint
		r5AbortData PresignRound6Message_AbortData

		// round 6
		*LocalPresignData

		// round 7
		sI *big.Int
		rI,
		TI *crypto.ECPoint
		r7AbortData PresignRound7Message_AbortData
	}
)

// Constructs a new ECDSA presign party.
func NewLocalParty(
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- *LocalPresignData,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.presignRound1Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound1Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound4Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound5Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound6Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.presignRound7Messages = make([]tss.ParsedMessage, partyCount)
	// temp data init
	p.temp.c1Is = make([]*big.Int, partyCount)
	p.temp.bigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.betas = make([]*big.Int, partyCount)
	p.temp.c1JIs = make([]*big.Int, partyCount)
	p.temp.c2JIs = make([]*big.Int, partyCount)
	p.temp.pI1JIs = make([]*mta.ProofBob, partyCount)
	p.temp.pI2JIs = make([]*mta.ProofBobWC, partyCount)
	p.temp.vJIs = make([]*big.Int, partyCount)
	p.temp.bigGammaJs = make([]*crypto.ECPoint, partyCount)
	p.temp.r5AbortData.AlphaIJ = make([][]byte, partyCount)
	p.temp.r5AbortData.BetaJI = make([][]byte, partyCount)

	p.temp.LocalPresignData = &LocalPresignData{}
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
	case *PresignRound5Message:
		p.temp.presignRound5Messages[fromPIdx] = msg
	case *PresignRound6Message:
		p.temp.presignRound6Messages[fromPIdx] = msg
	case *PresignRound7Message:
		p.temp.presignRound7Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warnf("unrecognised message ignored: %v", msg)
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
