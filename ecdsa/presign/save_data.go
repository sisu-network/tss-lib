package presign

import (
	"encoding/json"
	"math/big"

	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/tss"
)

type (
	LocalPresignData struct {
		PartyIds             tss.SortedPartyIDs
		ECDSAPub             *crypto.ECPoint
		W, K, Rx, Ry, RSigma *big.Int
	}
)

func NewLocalPresignData(partyIds tss.SortedPartyIDs) *LocalPresignData {
	return &LocalPresignData{
		PartyIds: partyIds,
	}
}

func (d *LocalPresignData) Marshall() ([]byte, error) {
	return json.Marshal(d)
}
