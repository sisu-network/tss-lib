package signing

import (
	"math/big"

	"github.com/sisu-network/tss-lib/tss"
)

// Protobuf gen command: protoc --proto_path=protob --go_out=ecdsa/signing --go_opt=paths=source_relative ecdsa-signing.proto

func NewSignRound1Message(from *tss.PartyID, si *big.Int) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}

	content := &SignRound1Message{
		Si: si.Bytes(),
	}

	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m.Si != nil
}

func (m *SignRound1Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.Si)
}
