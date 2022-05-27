package main

import "C"
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/RockX-SG/eth2deposit"
	"github.com/RockX-SG/ssv-dkg/deposit"
	"github.com/RockX-SG/ssv-dkg/tss"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func getOriginalData(path string) ([]eth2deposit.CompactDepositData, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var data []eth2deposit.CompactDepositData

	if err := json.Unmarshal(content, &data); err != nil {
		return nil, err
	} else {
		return data, nil
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func extractPK(group *tss.GroupTwoOfThree) ([48]byte, error) {
	var pk48 [48]byte
	pkBytes, err := hex.DecodeString(group.PublicKey())
	if err != nil {
		return [48]byte{}, err
	}
	copy(pk48[:], pkBytes)
	return pk48, nil
}

func useDkgForDepositData(group *tss.GroupTwoOfThree, data *eth2deposit.CompactDepositData) (*eth2deposit.CompactDepositData, error) {
	pk48, err := extractPK(group)
	if err != nil {
		return nil, err
	}
	tweak, err := deposit.NewTweakDepositData(*data, pk48)
	if err != nil {
		return nil, err
	}
	root, err := tweak.SigningRoot()
	if err != nil {
		return nil, err
	}
	logrus.Infof("Signing root is: %x", root)
	sigHex := group.Sign(string(root[:]))
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, err
	}
	var sig96 [96]byte
	copy(sig96[:], sig)
	tweak.SetSignature(sig96)
	finalCompactData, err := tweak.Output()
	if err != nil {
		return nil, err
	}
	return finalCompactData, nil
}

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{})

	//Set log output to standard output (default output is stderr, standard error)
	//Log message output can be any io.writer type
	logrus.SetOutput(os.Stdout)

	logrus.SetLevel(logrus.DebugLevel)
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: use-dkg <original-deposit-data-path>")
		os.Exit(1)
	}
	path := os.Args[1]
	dataArray, err := getOriginalData(path)
	check(err)

	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	group := tss.NewGroupTwoOfThree()
	group.Keygen()
	var newDataArray []eth2deposit.CompactDepositData
	for _, data := range dataArray {
		newData, err := useDkgForDepositData(group, &data)
		check(err)
		newDataArray = append(newDataArray, *newData)
	}
	jsonStr, err := json.Marshal(newDataArray)
	check(err)

	ts := time.Now().Unix()
	ext := filepath.Ext(path)
	newPath := strings.TrimSuffix(path, ext) + "_use-dkg-" + strconv.Itoa(int(ts)) + ext
	f, err := os.Create(newPath)
	check(err)
	defer f.Close()
	_,err=f.Write(jsonStr)
	check(err)
	logrus.Infof("New deposit data has been written in: %v", newPath)
}
