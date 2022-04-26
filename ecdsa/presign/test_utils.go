package presign

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/sisu-network/tss-lib/tss"
)

func LoadPresignTestFixture(n int) ([]LocalPresignData, tss.SortedPartyIDs, error) {
	presigns := LoadPresignData(n)
	partyIds := make([]*tss.PartyID, n)
	if len(presigns[0].BigSJ) != n {
		panic(fmt.Sprintf("n and BigSJ does not match: %d %d", n, len(presigns[0].BigSJ)))
	}

	keys := make([]*big.Int, n)

	for i, presign := range presigns {
		pMoniker := presign.PartyId

		keys[i] = new(big.Int).SetBytes([]byte(presign.PartyId))
		partyIds[i] = tss.NewPartyID(pMoniker, pMoniker, keys[i])
	}

	sortedPIDs := tss.SortPartyIDs(partyIds)
	sort.Slice(presigns, func(i, j int) bool { return keys[i].Cmp(keys[j]) == -1 })

	return presigns, sortedPIDs, nil
}

const (
	testFixtureDirFormat  = "%s/../../test/_ecdsa_presign_fixtures"
	testFixtureFileFormat = "presign_data_%d.json"
)

func SavePresignData(parties []*LocalParty) {
	// Save data
	for i, p := range parties {
		// Do some vanity checking before saving local presign data.
		for _, value := range p.temp.LocalPresignData.BigSJ {
			if value == nil {
				panic("BigSJ is nil")
			}
		}

		bz, err := p.temp.LocalPresignData.Marshall()
		if err != nil {
			panic(err)
		}

		fileName := makeTestFixtureFilePath(i)
		err = ioutil.WriteFile(fileName, bz, 0644)
		if err != nil {
			panic(err)
		}
	}
}

func LoadPresignData(n int) []LocalPresignData {
	ret := make([]LocalPresignData, 0, n)
	for i := 0; i < n; i++ {
		fileName := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fileName)
		if err != nil {
			panic(err)
		}

		presignData := LocalPresignData{}
		err = json.Unmarshal(bz, &presignData)
		if err != nil {
			panic(err)
		}
		ret = append(ret, presignData)
	}

	return ret
}

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}
