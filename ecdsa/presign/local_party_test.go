package presign

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/ecdsa/keygen"
	"github.com/sisu-network/tss-lib/test"
	"github.com/sisu-network/tss-lib/tss"
	"github.com/stretchr/testify/assert"
)

func TestE2EConcurrent(t *testing.T) {
	// log.SetLogLevel("tss-lib", "info")

	n := 15
	threshold := 10

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(threshold+1, n)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, threshold+1, len(keys))
	assert.Equal(t, threshold+1, len(signPIDs))

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.PresignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msgToSign := []byte("This is a test")
	msgInt := new(big.Int).SetBytes(msgToSign)

	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(msgInt, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	var ended int32

presignature:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
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
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				fmt.Println("All tasks finished")
				break presignature
			}
		}
	}

	verifyPubKey(t, parties, keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y())
	verifyTheta(t, parties)
	verifySigma(t, parties)
	verifyR(t, parties)
	verifySignature(t, parties, msgInt, keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y())
}

func verifyPubKey(t *testing.T, parties []*LocalParty, pubX, pubY *big.Int) {
	N := tss.EC().Params().N
	modN := common.ModInt(N)

	w := big.NewInt(0)
	for _, p := range parties {
		w = modN.Add(w, p.temp.w)
	}

	px, py := tss.EC().ScalarBaseMult(w.Bytes())
	assert.Equal(t, px, pubX)
	assert.Equal(t, py, pubY)
}

func verifyTheta(t *testing.T, parties []*LocalParty) {
	// Verify theta = sum(theta_i) * sum(k_i)

	N := tss.EC().Params().N
	modN := common.ModInt(N)

	theta := big.NewInt(0)
	sumK := big.NewInt(0)
	sumGamma := big.NewInt(0)

	for _, p := range parties {
		theta = modN.Add(theta, p.temp.theta)
		sumK = modN.Add(sumK, p.temp.k)
		sumGamma = modN.Add(sumGamma, p.temp.gamma)
	}

	mul := modN.Mul(sumK, sumGamma)

	assert.Equal(t, theta, mul)
}

func verifySigma(t *testing.T, parties []*LocalParty) {
	N := tss.EC().Params().N
	modN := common.ModInt(N)

	sigma := big.NewInt(0)
	sumK := big.NewInt(0)
	sumW := big.NewInt(0)

	for _, p := range parties {
		sigma = modN.Add(sigma, p.temp.sigma)
		sumK = modN.Add(sumK, p.temp.k)
		sumW = modN.Add(sumW, p.temp.w)
	}

	mul := modN.Mul(sumK, sumW)

	assert.Equal(t, sigma, mul)
}

func verifyR(t *testing.T, parties []*LocalParty) {
	N := tss.EC().Params().N
	modN := common.ModInt(N)

	// Verify that all R are the same
	for _, p := range parties {
		if p.temp.rx.Cmp(parties[0].temp.rx) != 0 {
			assert.FailNow(t, "rx does not match")
		}

		if p.temp.ry.Cmp(parties[0].temp.ry) != 0 {
			assert.FailNow(t, "ry does not match")
		}
	}

	// Verify R = g * k
	k := big.NewInt(0)
	for _, p := range parties {
		k = modN.Add(k, p.temp.k)
	}
	k = modN.ModInverse(k)

	gkx, gky := tss.EC().ScalarBaseMult(k.Bytes())
	assert.Equal(t, gkx, parties[0].temp.bigR.X())
	assert.Equal(t, gky, parties[0].temp.bigR.Y())
}

func verifySignature(t *testing.T, parties []*LocalParty, msgInt, pkX, pkY *big.Int) {
	R := parties[0].temp.bigR
	r := parties[0].temp.rx
	fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

	modN := common.ModInt(tss.EC().Params().N)

	// BEGIN check s correctness
	sumS := big.NewInt(0)
	for _, p := range parties {
		si := modN.Mul(msgInt, p.temp.k)
		si = modN.Add(si, p.temp.rSigma)

		sumS = modN.Add(sumS, si)
	}
	fmt.Printf("S: %s\n", sumS.String())
	// END check s correctness

	// BEGIN ECDSA verify
	pk := ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     pkX,
		Y:     pkY,
	}
	ok := ecdsa.Verify(&pk, msgInt.Bytes(), R.X(), sumS)
	assert.True(t, ok, "ecdsa verify must pass")
	t.Log("ECDSA signing test done.")
	// END ECDSA verify
}
