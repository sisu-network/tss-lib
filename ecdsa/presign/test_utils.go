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

	type wrapper struct {
		partyId *tss.PartyID
		presign LocalPresignData
	}

	wrappers := make([]*wrapper, n)

	for i, presign := range presigns {
		pMoniker := presign.PartyId
		key := new(big.Int).SetBytes([]byte(presign.PartyId))

		partyIds[i] = tss.NewPartyID(pMoniker, pMoniker, key)
		wrappers[i] = &wrapper{
			partyId: partyIds[i],
			presign: presigns[i],
		}
	}

	sortedPIDs := tss.SortPartyIDs(partyIds)

	// Sort the wrapper using the same sorting function used for SortPartyIDs
	sort.Slice(wrappers, func(i, j int) bool {
		return wrappers[i].partyId.KeyInt().Cmp(wrappers[j].partyId.KeyInt()) == -1
	})

	for i := range wrappers {
		presigns[i] = wrappers[i].presign
	}

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
