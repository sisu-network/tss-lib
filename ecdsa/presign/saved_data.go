package presign

import (
	common "github.com/sisu-network/tss-lib/common"
)

type (
	LocalPresignData struct {
		// Sanity check in FinalizeGetAndVerifyFinalSig
		T int32 `protobuf:"varint,1,opt,name=t,proto3" json:"t,omitempty"`
		// Components to produce s = sum(s_i)
		KI      []byte          `protobuf:"bytes,2,opt,name=k_i,json=kI,proto3" json:"k_i,omitempty"`
		RSigmaI []byte          `protobuf:"bytes,3,opt,name=r_sigma_i,json=rSigmaI,proto3" json:"r_sigma_i,omitempty"`
		BigR    *common.ECPoint `protobuf:"bytes,4,opt,name=big_r,json=bigR,proto3" json:"big_r,omitempty"`
		// Components for identifiable aborts during the final phase
		BigRBarJ map[string]*common.ECPoint `protobuf:"bytes,5,rep,name=big_r_bar_j,json=bigRBarJ,proto3" json:"big_r_bar_j,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
		BigSJ    map[string]*common.ECPoint `protobuf:"bytes,6,rep,name=big_s_j,json=bigSJ,proto3" json:"big_s_j,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	}
)

func NewLocalPresignData(oneRoundData *SignatureData_OneRoundData) *LocalPresignData {
	return &LocalPresignData{
		T:        oneRoundData.T,
		KI:       oneRoundData.KI,
		RSigmaI:  oneRoundData.RSigmaI,
		BigR:     oneRoundData.BigR,
		BigRBarJ: oneRoundData.BigRBarJ,
		BigSJ:    oneRoundData.BigSJ,
	}
}
