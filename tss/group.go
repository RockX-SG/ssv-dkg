package tss

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	tss "github.com/RockX-SG/bls-tss"
	"github.com/herumi/bls-eth-go-binary/bls"
	"math/big"
	"time"
)

type GroupTwoOfThree struct {
	ins        [3]chan string
	outs       [3]chan string
	stop       chan string
	kMachines  [3]*tss.Keygen
	keygenDone bool
	sk         *bls.SecretKey
	pkHex      string
}

func NewGroupTwoOfThree() *GroupTwoOfThree {
	var (
		ins       [3]chan string
		outs      [3]chan string
		kMachines [3]*tss.Keygen
	)

	t := 1
	n := 3
	for i := 1; i < n+1; i++ {
		in := make(chan string, n)
		out := make(chan string, n)
		keygen := tss.NewKeygen(i, t, n, in, out)
		ins[i-1] = in
		outs[i-1] = out
		kMachines[i-1] = keygen
	}
	stop := make(chan string)
	return &GroupTwoOfThree{
		ins, outs, stop, kMachines, false, nil, "",
	}
}

func (g *GroupTwoOfThree) wireUp() {
	o1, o2, o3 := g.outs[0], g.outs[1], g.outs[2]
	i1, i2, i3 := g.ins[0], g.ins[1], g.ins[2]
	go func() {
		send := func(str string) {
			msg := tss.ProtocolMessage{}
			if err := json.Unmarshal([]byte(str), &msg); err != nil {
				fmt.Printf("error: %v\n", err)
			} else {
				switch msg.Receiver {
				case 0:
					if msg.Sender != 1 {
						i1 <- str
					}
					if msg.Sender != 2 {
						i2 <- str
					}
					if msg.Sender != 3 {
						i3 <- str
					}
				case 1:
					i1 <- str
				case 2:
					i2 <- str
				case 3:
					i3 <- str
				}
			}
		}
		for {
			select {
			case str, ok := <-o1:
				if ok {
					send(str)
				}
			case str, ok := <-o2:
				if ok {
					send(str)
				}
			case str, ok := <-o3:
				if ok {
					send(str)
				}
			case <-g.stop:
				break
			}
		}
	}()
}

func (g *GroupTwoOfThree) stopIt() {
	g.stop <- "stop"
}

func (g *GroupTwoOfThree) Keygen() {

	g.wireUp()
	defer g.stopIt()

	go g.kMachines[0].ProcessLoop()
	go g.kMachines[1].ProcessLoop()
	go g.kMachines[2].ProcessLoop()

	g.kMachines[0].Initialize()
	g.kMachines[1].Initialize()
	g.kMachines[2].Initialize()
	var allFinished bool
	for !allFinished {
		select {
		case <-time.After(1 * time.Second):
			allFinished = true
			for _, machine := range g.kMachines {
				allFinished = allFinished && machine.Output() != nil
			}
			if allFinished {
				break
			}
		}
	}
	g.keygenDone = true
	g.extractPK()
	g.reconstructSecret()
}

func (g *GroupTwoOfThree) PublicKey() string {
	return g.pkHex
}

func (g GroupTwoOfThree) Sign(message string) string {
	g.wireUp()
	defer g.stopIt()

	var sMachines []*tss.Sign
	n := 2 // signing group size
	for i := 1; i < n+1; i++ {
		sign := tss.NewSign(message, i, n, *g.kMachines[i-1].Output(), g.ins[i-1], g.outs[i-1])
		sMachines = append(sMachines, sign)
	}

	defer func(machines []*tss.Sign) {
		for _, machine := range machines {
			machine.Free()
		}
	}(sMachines)

	go sMachines[0].ProcessLoop()
	go sMachines[1].ProcessLoop()

	sMachines[0].Initialize()
	sMachines[1].Initialize()
	allFinished := false
	for !allFinished {
		select {
		case <-time.After(1 * time.Second):
			allFinished = true
			for _, machine := range sMachines {
				allFinished = allFinished && machine.Output() != nil
			}
			if allFinished {
				break
			}
		}
	}
	return *sMachines[1].Output()
}

func (g *GroupTwoOfThree) extractPK() {
	localKey1 := new(localKey)
	err := json.Unmarshal([]byte(*g.kMachines[0].Output()), localKey1)
	if err != nil {
		panic(err)
	}
	g.pkHex = localKey1.SharedKeys.Vk.BytesStr
}

func (g *GroupTwoOfThree) reconstructSecret() {
	if !g.keygenDone {
		return
	}
	localKey1 := new(localKey)
	err := json.Unmarshal([]byte(*g.kMachines[0].Output()), localKey1)
	if err != nil {
		panic(err)
	}
	localKey2 := new(localKey)
	err = json.Unmarshal([]byte(*g.kMachines[1].Output()), localKey2)
	if err != nil {
		panic(err)
	}
	sk, err := reconstructSK(*localKey1, *localKey2)
	if err != nil {
		panic(errors.New("Failed reconstruct secret key."))
	}
	g.sk = sk
}

func reconstructSK(lk1 localKey, lk2 localKey) (*bls.SecretKey, error) {
	RHEX := "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
	sk1, err := hex.DecodeString(lk1.SharedKeys.SkI)
	if err != nil {
		return nil, err
	}
	sk2, err := hex.DecodeString(lk2.SharedKeys.SkI)
	if err != nil {
		return nil, err
	}
	rval, err := hex.DecodeString(RHEX)
	if err != nil {
		return nil, err
	}
	r := new(big.Int)
	r.SetBytes(rval)
	i1 := new(big.Int)
	i1.SetBytes(sk1)
	i1_mod_r := new(big.Int)
	i1_mod_r.Mod(i1, r)

	i2 := new(big.Int)
	i2.SetBytes(sk2)
	i2_mod_r := new(big.Int)
	i2_mod_r.Mod(i2, r)

	r_minus_i2_mod_r := new(big.Int)
	r_minus_i2_mod_r.Sub(r, i2_mod_r)

	i1_times_2 := new(big.Int)
	i1_times_2.Mul(i1_mod_r, big.NewInt(2))

	// (2*i1 % r + r - i2 % r) % r
	res_raw := new(big.Int)
	res_raw.Add(i1_times_2, r_minus_i2_mod_r)

	res := new(big.Int)
	res.Mod(res_raw, r)

	var sk bls.SecretKey
	sk.SetHexString(hex.EncodeToString(res.Bytes()))
	return &sk, nil
}

type localKey struct {
	SharedKeys struct {
		Index  int `json:"index"`
		Params struct {
			Threshold  int `json:"threshold"`
			ShareCount int `json:"share_count"`
		} `json:"params"`
		Vk struct {
			BytesStr string `json:"bytes_str"`
		} `json:"vk"`
		SkI string `json:"sk_i"`
	} `json:"shared_keys"`
	VkVec []struct {
		Curve string `json:"curve"`
		Point []int  `json:"point"`
	} `json:"vk_vec"`
	I int `json:"i"`
	T int `json:"t"`
	N int `json:"n"`
}
