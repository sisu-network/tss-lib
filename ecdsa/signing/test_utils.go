package signing

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/sisu-network/tss-lib/ecdsa/keygen"
	"github.com/sisu-network/tss-lib/tss"
	"github.com/stretchr/testify/assert"
)

const (
	testFixtureDirFormat  = "%s/../../test/_ecdsa_oneround_fixtures"
	testFixtureFileFormat = "signing_data_%d.json"
)

type oneRoundDataWrapper struct {
	KeygenData keygen.LocalPartySaveData
	OneRound   *SignatureData_OneRoundData
}

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

func getIndex(parties []*LocalParty, signatureData *SignatureData) int {
	for i, p := range parties {
		if p.temp.BigR == signatureData.OneRoundData.BigR {
			return i
		}
	}

	return -1
}

func tryWriteTestFixtureFile(t *testing.T, index int, pid string, data *SignatureData_OneRoundData, keygenData keygen.LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}

		fmt.Println("Party id = ", data.PartyId)

		bz, err := json.Marshal(&oneRoundDataWrapper{
			KeygenData: keygenData,
			OneRound:   data,
		})
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}

func loadSigningData(n int) ([]*oneRoundDataWrapper, tss.SortedPartyIDs) {
	fixtures := make([]*oneRoundDataWrapper, n)
	for i := 0; i < n; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			panic(err)
		}

		data := new(oneRoundDataWrapper)
		err = json.Unmarshal(bz, data)
		if err != nil {
			panic(err)
		}

		fixtures[i] = data
	}

	partyIDs := make(tss.UnSortedPartyIDs, len(fixtures))
	for i := 0; i < len(fixtures); i++ {
		key := fixtures[i].KeygenData

		partyIDs[i] = tss.NewPartyID(fixtures[i].OneRound.PartyId, fixtures[i].OneRound.PartyId, key.ShareID)
	}

	sortedPIDs := tss.SortPartyIDs(partyIDs)
	sort.Slice(fixtures, func(i, j int) bool {
		return fixtures[i].KeygenData.ShareID.Cmp(fixtures[j].KeygenData.ShareID) == -1
	})

	return fixtures, sortedPIDs
}
