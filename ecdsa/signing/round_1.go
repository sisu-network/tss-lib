package signing

// // Spec requires calculate H(M) here,
// // but considered different blockchain use different hash function we accept the converted big.Int
// // if this big.Int is not belongs to Zq, the client might not comply with common rule (for ECDSA):
// // https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L263
// if round.temp.m.Cmp(tss.EC().Params().N) >= 0 {
// 	return round.WrapError(errors.New("hashed message is not valid"))
// }
