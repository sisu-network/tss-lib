package presign

import (
	"fmt"
	"math/big"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/crypto"
	"github.com/sisu-network/tss-lib/tss"
)

func PrepareForPresigning(i, pax int, xi *big.Int, ks []*big.Int, bigXs []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint) {
	modQ := common.ModInt(tss.EC().Params().N)
	if len(ks) != len(bigXs) {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(bigXs)))
	}
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
	}

	// 2-4.
	wi = xi
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ks[j], ks[i])))
		wi = modQ.Mul(wi, coef)
	}

	// 5-10.
	bigWs = make([]*crypto.ECPoint, len(ks))
	for j := 0; j < pax; j++ {
		bigWj := bigXs[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc := ks[c]
			ksj := ks[j]
			if ksj.Cmp(ksc) == 0 {
				panic(fmt.Errorf("index of two parties are equal"))
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)
			iota := modQ.Mul(ksc, modQ.ModInverse(new(big.Int).Sub(ksc, ksj)))
			bigWj = bigWj.ScalarMult(iota)
		}
		bigWs[j] = bigWj
	}
	return
}
