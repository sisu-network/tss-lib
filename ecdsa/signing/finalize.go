package signing

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 10
	round.started = true
	round.resetOK()

	sumS := round.temp.si
	modN := common.ModInt(tss.EC().Params().N)

	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r1msg := round.temp.signRound1Messages[j].Content().(*SignRound1Message)
		sumS = modN.Add(sumS, r1msg.UnmarshalS())
	}

	recid := 0
	rx := round.presignData.Rx
	ry := round.presignData.Ry

	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if rx.Cmp(tss.EC().Params().N) > 0 {
		recid = 2
	}
	if ry.Bit(0) != 0 {
		recid |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(tss.EC().Params().N, 1)
	if sumS.Cmp(secp256k1halfN) > 0 {
		sumS.Sub(tss.EC().Params().N, sumS)
		recid ^= 1
	}

	// save the signature for final output
	bitSizeInBytes := tss.EC().Params().BitSize / 8
	round.sigData.R = padToLengthBytesInPlace(round.presignData.Rx.Bytes(), bitSizeInBytes)
	round.sigData.S = padToLengthBytesInPlace(sumS.Bytes(), bitSizeInBytes)
	round.sigData.Signature = append(round.sigData.R, round.sigData.S...)
	round.sigData.SignatureRecovery = []byte{byte(recid)}
	round.sigData.M = round.temp.m.Bytes()

	pk := ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     round.temp.pubX,
		Y:     round.temp.pubY,
	}
	ok := ecdsa.Verify(&pk, round.temp.m.Bytes(), rx, sumS)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}

	round.end <- *round.sigData

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}

func padToLengthBytesInPlace(src []byte, length int) []byte {
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src
}
