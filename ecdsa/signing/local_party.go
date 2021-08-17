package signing

import (
	"fmt"
	"math/big"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/ecdsa/presign"
	"github.com/sisu-network/tss-lib/tss"
)

var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		presignData *presign.LocalPresignData
		sigData     *common.SignatureData
		temp        localTempData

		// outbound messaging
		out chan<- tss.Message
		end chan<- common.SignatureData
	}

	localMessageStore struct {
		signRound1Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		m, pubX, pubY, si *big.Int
	}
)

func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	presignData *presign.LocalPresignData,
	pubX, pubY *big.Int,

	out chan<- tss.Message,
	end chan<- common.SignatureData,
) tss.Party {
	p := &LocalParty{
		BaseParty:   new(tss.BaseParty),
		params:      params,
		temp:        localTempData{},
		presignData: presignData,
		sigData:     &common.SignatureData{},
		out:         out,
		end:         end,
	}
	partyCount := len(params.Parties().IDs())

	p.temp.signRound1Messages = make([]tss.ParsedMessage, partyCount)

	p.temp.m = msg
	p.temp.pubX = pubX
	p.temp.pubY = pubY

	return p
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, p.presignData, p.sigData, &p.temp, p.out, p.end)
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	switch msg.Content().(type) {
	case *SignRound1Message:
		p.temp.signRound1Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}

	return true, nil
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

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
