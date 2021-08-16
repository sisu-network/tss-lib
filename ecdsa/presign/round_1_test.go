package presign

import (
	"math/big"
	"testing"
	"time"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/ecdsa/keygen"
	"github.com/sisu-network/tss-lib/tss"
	"github.com/stretchr/testify/assert"
)

const (
	testParticipants = 20
	testThreshold    = testParticipants / 2
)

func TestRound1(t *testing.T) {
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")

	p2pCtx := tss.NewPeerContext(signPIDs)
	params := tss.NewParameters(p2pCtx, signPIDs[0], len(signPIDs), testThreshold)
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.PresignatureData, len(signPIDs))

	P := NewLocalParty(big.NewInt(42), params, keys[0], outCh, endCh).(*LocalParty)

	round1 := P.FirstRound()
	round1.Start()

	select {
	case <-outCh:
	case <-time.After(time.Second * 3):
		assert.Fail(t, "Round 1 Timeout")
	}
}
