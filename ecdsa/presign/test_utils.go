package presign

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"

	"github.com/sisu-network/tss-lib/tss"
)

func LoadPresignTestFixture(testThresholdPlusOne, testParticipants int) ([]LocalPresignData, tss.SortedPartyIDs, error) {
	return nil, nil, nil
}

const (
	testFixtureDirFormat  = "%s/../../test/_ecdsa_presign_fixtures"
	testFixtureFileFormat = "presign_data_%d.json"
)

func SavePresignData(parties []*LocalParty) {
	// Save data
	for i, p := range parties {
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

func LoadPresignData(n int) []*LocalPresignData {
	ret := make([]*LocalPresignData, 0, n)
	for i := 0; i < n; i++ {
		fileName := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fileName)
		if err != nil {
			panic(err)
		}

		presignData := &LocalPresignData{}
		err = json.Unmarshal(bz, presignData)
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
