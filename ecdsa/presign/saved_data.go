package presign

import (
	common "github.com/sisu-network/tss-lib/common"
)

type (
	LocalPresignData struct {

		// Sanity check in FinalizeGetAndVerifyFinalSig
		T int32

		// Components to produce s = sum(s_i)
		KI      []byte
		RSigmaI []byte
		BigR    *common.ECPoint
		// Components for identifiable aborts during the final phase
		BigRBarJ map[string]*common.ECPoint
		BigSJ    map[string]*common.ECPoint
	}
)
