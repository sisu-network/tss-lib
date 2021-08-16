package keygen

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sisu-network/tss-lib/common"
	"github.com/sisu-network/tss-lib/ecdsa/keygen"
	"github.com/sisu-network/tss-lib/test"
	"github.com/sisu-network/tss-lib/tss"
)

const (
	PREPARAMS_FILE = "data/preparams.txt"
)

var (
	allPreParams []*keygen.LocalPreParams
	partiesID    []*tss.PartyID
	keyGenWg     sync.WaitGroup
	parties      []tss.Party
	threshold    int
	KEYS         []*big.Int
)

func savePreparams() {
	f, err := os.Create(PREPARAMS_FILE)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	count := len(KEYS)
	for i := 0; i < count; i++ {
		common.Logger.Debug("Generating: ", i, count)
		encoded := generatePreparams()
		f.WriteString(encoded)
		if i < count-1 {
			f.WriteString("\n")
		}
		f.Sync()
	}
}

func generatePreparams() string {
	preParams, _ := keygen.GeneratePreParams(1 * time.Minute)

	bytes, err := json.Marshal(preParams)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(bytes)
}

func loadPreparams() {
	content, err := ioutil.ReadFile(PREPARAMS_FILE)
	if err != nil {
		panic(err)
	}

	values := strings.Split(string(content), "\n")
	common.Logger.Debug(len(values))

	for _, value := range values {
		preParams := decodePreparam(value)
		allPreParams = append(allPreParams, &preParams)
	}

	common.Logger.Debug("Done loading preparams")
}

func decodePreparam(encoded string) keygen.LocalPreParams {
	val, err := hex.DecodeString(encoded)
	if err != nil {
		panic(err)
	}

	var preParam keygen.LocalPreParams
	err = json.Unmarshal(val, &preParam)
	if err != nil {
		panic(err)
	}

	return preParam
}

func generateSigningNode(p2pCtx *tss.PeerContext, pIDs []*tss.PartyID, index int, P tss.Party, errCh chan *tss.Error, outCh chan tss.Message, endCh chan keygen.LocalPartySaveData) {
	go func(P tss.Party) {
		common.Logger.Debug("Starting party ", index)

		if err := P.Start(); err != nil {
			panic(err)
		}
	}(P)

	for {
		select {
		case err := <-errCh:
			panic(err)

		case msg := <-outCh:
			common.Logger.Debug("Message received. From", msg.GetFrom())
			if len(parties) != len(KEYS) {
				panic("Not enough parties")
			}

			dest := msg.GetTo()
			if dest == nil { // broadcast!
				common.Logger.Debug("Doing broadcast...")

				for _, party := range parties {
					if party.PartyID().Id == msg.GetFrom().Id {
						continue
					}

					go test.SharedPartyUpdater(party, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Id == msg.GetFrom().Id {
					// panic("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom())
					panic("Failed")
				}

				for _, party := range parties {
					if party.PartyID().Id == dest[0].Id {
						go test.SharedPartyUpdater(party, msg, errCh)
						break
					}
				}
			}

		case msg := <-endCh:
			common.Logger.Debug("Ending channel")

			index, err := msg.OriginalIndex()
			if err != nil {
				panic(err)
			}

			// pubKey, err := GetTssPubKey(msg.ECDSAPub)
			keyGenWg.Done()

			common.Logger.Debug("Done!", index)
			return
		}
	}
}

func DoKeygen(t, n int) {
	threshold = t
	KEYS = make([]*big.Int, n)

	for i := range KEYS {
		KEYS[i] = common.GetRandomPositiveInt(tss.EC().Params().N)
	}

	if _, err := os.Stat(PREPARAMS_FILE); os.IsNotExist(err) {
		savePreparams()
	}

	loadPreparams()

	var pIDs []*tss.PartyID
	for i, key := range KEYS {
		pid := tss.NewPartyID(strconv.Itoa(i), "", key)
		pIDs = append(pIDs, pid)
	}

	partiesID = tss.SortPartyIDs(pIDs)
	p2pCtx := tss.NewPeerContext(partiesID)

	// Generates parties
	errChs := make([]chan *tss.Error, len(KEYS))
	outChs := make([]chan tss.Message, len(KEYS))
	endChs := make([]chan keygen.LocalPartySaveData, len(KEYS))

	for i := range KEYS {
		errChs[i] = make(chan *tss.Error)
		outChs[i] = make(chan tss.Message, len(KEYS))
		endChs[i] = make(chan keygen.LocalPartySaveData, len(KEYS))

		params := tss.NewParameters(p2pCtx, pIDs[i], len(KEYS), threshold)
		P := keygen.NewLocalParty(params, outChs[i], endChs[i], *allPreParams[i])

		parties = append(parties, P)
	}

	for i, _ := range KEYS {
		keyGenWg.Add(1)
		go func(index int) {
			generateSigningNode(p2pCtx, partiesID, index, parties[index], errChs[index], outChs[index], endChs[index])
		}(i)
	}

	keyGenWg.Wait()
}
