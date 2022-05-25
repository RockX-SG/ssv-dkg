package deposit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/RockX-SG/eth2deposit"
	"github.com/sirupsen/logrus"
)

type TweakDepositData struct {
	originalData   eth2deposit.CompactDepositData
	newPubKey      [48]byte
	depositMessage eth2deposit.DepositMessage
	forkVersion    [4]byte
	signature      [96]byte
}

func NewTweakDepositData(originalData eth2deposit.CompactDepositData, newPubKey [48]byte) (*TweakDepositData, error) {
	cred, err := hex.DecodeString(originalData.WithdrawCredential)
	if err != nil {
		return nil, err
	}
	if len(cred) != 32 {
		return nil, errors.New(fmt.Sprintf("WithdrawCredentials should be in 32 bytes. Got %v.", len(cred)))
	}

	var cred32 [32]byte
	copy(cred32[:], cred)
	depositMessage := eth2deposit.DepositMessage{
		Pubkey:                newPubKey,
		WithdrawalCredentials: cred32,
		Amount:                uint64(originalData.Amount),
	}
	if err != nil {
		return nil, err
	}

	fv, err := hex.DecodeString(originalData.ForkVersion)
	if err != nil {
		return nil, err
	}
	var forkVersion [4]byte
	copy(forkVersion[:], fv)

	signature := [96]byte{} // Empty signature
	return &TweakDepositData{
		originalData,
		newPubKey,
		depositMessage,
		forkVersion,
		signature,
	}, nil
}

func (d *TweakDepositData) SigningRoot() ([32]byte, error) {
	domain, err := eth2deposit.ComputeDepositDomain(d.forkVersion)
	if err != nil {
		return [32]byte{}, err
	}

	logrus.Debugf("domain is: %x\n", domain)

	messageToSign, err := eth2deposit.ComputeSigningRoot(&d.depositMessage, domain)
	if err != nil {
		return [32]byte{}, err
	}
	var root [32]byte
	copy(root[:], messageToSign)
	return root, nil
}

func (d *TweakDepositData) SetSignature(signature [96]byte) {
	d.signature = signature
}

func (d *TweakDepositData) Output() (*eth2deposit.CompactDepositData, error) {
	if d.signature == [96]byte{} {
		return nil, errors.New("signature is not set yet")
	}
	messageRoot, err := d.depositMessage.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	depositData := eth2deposit.DepositData{
		Amount:                uint64(d.originalData.Amount),
		WithdrawalCredentials: d.depositMessage.WithdrawalCredentials,
		Pubkey:                d.newPubKey,
		Signature:             d.signature,
	}

	dataRoot, err := depositData.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	return &eth2deposit.CompactDepositData{
		PubKey:             hex.EncodeToString(d.newPubKey[:]),
		WithdrawCredential: d.originalData.WithdrawCredential,
		Amount:             d.originalData.Amount,
		Signature:          hex.EncodeToString(d.signature[:]),
		DepositMessageRoot: hex.EncodeToString(messageRoot[:]),
		DepositDataRoot:    hex.EncodeToString(dataRoot[:]),
		ForkVersion:        d.originalData.ForkVersion,
		//Eth2NetworkName:    d.originalData.Eth2NetworkName,
		Eth2NetworkName:   "prater",
		DepositCliVersion: "999.999.999",
	}, nil
}
