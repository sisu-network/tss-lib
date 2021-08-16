package main

import (
	"github.com/ipfs/go-log"
	tkeygen "github.com/sisu-network/tss-lib/test/keygen"
)

// Main function to do local testing, not meant to run a program.
func main() {
	log.SetLogLevel("tss-lib", "debug")

	tkeygen.DoKeygen(2, 3)
}
