package presign

import (
	"math/big"

	cmt "github.com/sisu-network/tss-lib/crypto/commitments"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto/mta"
	"github.com/sisu-network/tss-lib/tss"
)

// Protobuf command: protoc --proto_path=protob --go_out=ecdsa/presign --go_opt=paths=source_relative ecdsa-presign.proto

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*PresignRound1Message1)(nil),
	}
)

func NewSignRound1Message1(
	to, from *tss.PartyID,
	c *big.Int,
	proof *mta.RangeProofAlice,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBz := proof.Bytes()
	content := &PresignRound1Message1{
		C:               c.Bytes(),
		RangeProofAlice: pfBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *PresignRound1Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetC()) &&
		common.NonEmptyMultiBytes(m.GetRangeProofAlice(), mta.RangeProofAliceBytesParts)
}

// ----- //

func NewSignRound1Message2(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &PresignRound1Message2{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *PresignRound1Message2) ValidateBasic() bool {
	return m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment())
}

func (m *PresignRound1Message2) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}
