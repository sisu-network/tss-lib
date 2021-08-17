package presign

import (
	"math/big"

	"github.com/sisu-network/tss-lib/tss"
)

type (
	LocalPresignData struct {
		PartyIds             tss.SortedPartyIDs
		W, K, Rx, Ry, RSigma *big.Int
	}
)
