package signing

import (
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/ecdsa/presign"
	"github.com/sisu-network/tss-lib/test"
	"github.com/sisu-network/tss-lib/tss"
	"github.com/stretchr/testify/assert"
)

func TestSigning(t *testing.T) {
	n := 11
	threshold := n - 1

	savedData := presign.LoadPresignData(n)
	p2pCtx := tss.NewPeerContext(savedData[0].PartyIds)
	parties := make([]*LocalParty, 0, len(savedData))

	errCh := make(chan *tss.Error, len(savedData))
	outCh := make(chan tss.Message, len(savedData))
	endCh := make(chan common.SignatureData, len(savedData))

	updater := test.SharedPartyUpdater

	msgInt := new(big.Int).SetBytes([]byte("this is a test"))
	for i := 0; i < n; i++ {
		params := tss.NewParameters(p2pCtx, savedData[i].PartyIds[i], len(savedData), threshold)
		P := NewLocalParty(msgInt, params, savedData[i], savedData[0].ECDSAPub.X(), savedData[0].ECDSAPub.Y(), outCh, endCh).(*LocalParty)

		parties = append(parties, P)

		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32

signing:
	for {
		// fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			return

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(savedData)) {
				fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
				fmt.Println("All tasks finished")
				break signing
			}
		}
	}

	// Check that everyone has the same signature. The signature verification is done in the
	// final round.
	for _, p := range parties {
		assert.Equal(t, p.sigData.R, parties[0].sigData.R)
		assert.Equal(t, p.sigData.S, parties[0].sigData.S)
	}
}
