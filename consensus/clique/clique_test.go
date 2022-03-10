// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package clique

import (
	"bytes"
	"math/big"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// This test case is a repro of an annoying bug that took us forever to catch.
// In Clique PoA networks (Rinkeby, Görli, etc), consecutive blocks might have
// the same state root (no block subsidy, empty block). If a node crashes, the
// chain ends up losing the recent state and needs to regenerate it from blocks
// already in the database. The bug was that processing the block *prior* to an
// empty one **also completes** the empty one, ending up in a known-block error.
func TestReimportMirroredState(t *testing.T) {
	// Initialize a Clique chain with a single signer
	var (
		db     = rawdb.NewMemoryDatabase()
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		engine = New(params.AllCliqueProtocolChanges.Clique, db)
		signer = new(types.HomesteadSigner)
	)
	genspec := &core.Genesis{
		// MODIFIED by Jakub Pajek (clique permissions)
		//ExtraData: make([]byte, extraVanity+common.AddressLength+extraSeal),
		ExtraData: make([]byte, ExtraVanity+common.AddressLength+1+ExtraSeal),
		Alloc: map[common.Address]core.GenesisAccount{
			addr: {Balance: big.NewInt(10000000000000000)},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	copy(genspec.ExtraData[ExtraVanity:], addr[:])
	// ADDED by Jakub Pajek (clique permissions)
	genspec.ExtraData[ExtraVanity+common.AddressLength] = ExtraVoterMarker
	// ADDED by Jakub Pajek BEG (clique static block rewards)
	// Inject signer's address into the consensus engine so that FinalizeAndAssemble
	// called from GenerateChain below can correctly assign static block rewards.
	engine.Authorize(addr, func(account accounts.Account, s string, data []byte) ([]byte, error) {
		return crypto.Sign(crypto.Keccak256(data), key)
	})
	// ADDED by Jakub Pajek END (clique static block rewards)
	genesis := genspec.MustCommit(db)

	// Generate a batch of blocks, each properly signed
	// MODIFIED by Jakub Pajek (deterministic fork choice rules)
	//chain, _ := core.NewBlockChain(db, nil, params.AllCliqueProtocolChanges, engine, vm.Config{}, nil, nil)
	chain, _ := core.NewBlockChain(db, nil, params.AllCliqueProtocolChanges, engine, vm.Config{}, nil, nil, nil)
	defer chain.Stop()

	blocks, _ := core.GenerateChain(params.AllCliqueProtocolChanges, genesis, engine, db, 3, func(i int, block *core.BlockGen) {
		// The chain maker doesn't have access to a chain, so the difficulty will be
		// lets unset (nil). Set it here to the correct value.
		// MODIFIED by Jakub Pajek (clique 1-n scale difficulties)
		//block.SetDifficulty(diffInTurn)
		block.SetDifficulty(big.NewInt(1)) // single in-turn signer

		// We want to simulate an empty middle block, having the same state as the
		// first one. The last is needs a state change again to force a reorg.
		if i != 1 {
			tx, err := types.SignTx(types.NewTransaction(block.TxNonce(addr), common.Address{0x00}, new(big.Int), params.TxGas, block.BaseFee(), nil), signer, key)
			if err != nil {
				panic(err)
			}
			block.AddTxWithChain(chain, tx)
		}
	})
	for i, block := range blocks {
		header := block.Header()
		if i > 0 {
			header.ParentHash = blocks[i-1].Hash()
		}
		header.Extra = make([]byte, ExtraVanity+ExtraSeal)
		// MODIFIED by Jakub Pajek (clique 1-n scale difficulties)
		//header.Difficulty = diffInTurn
		header.Difficulty = big.NewInt(1) // single in-turn signer

		sig, _ := crypto.Sign(SealHash(header).Bytes(), key)
		copy(header.Extra[len(header.Extra)-ExtraSeal:], sig)
		blocks[i] = block.WithSeal(header)
	}
	// Insert the first two blocks and make sure the chain is valid
	db = rawdb.NewMemoryDatabase()
	genspec.MustCommit(db)

	// MODIFIED by Jakub Pajek (deterministic fork choice rules)
	//chain, _ = core.NewBlockChain(db, nil, params.AllCliqueProtocolChanges, engine, vm.Config{}, nil, nil)
	chain, _ = core.NewBlockChain(db, nil, params.AllCliqueProtocolChanges, engine, vm.Config{}, nil, nil, nil)
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("failed to insert initial blocks: %v", err)
	}
	if head := chain.CurrentBlock().NumberU64(); head != 2 {
		t.Fatalf("chain head mismatch: have %d, want %d", head, 2)
	}

	// Simulate a crash by creating a new chain on top of the database, without
	// flushing the dirty states out. Insert the last block, triggering a sidechain
	// reimport.
	// MODIFIED by Jakub Pajek (deterministic fork choice rules)
	//chain, _ = core.NewBlockChain(db, nil, params.AllCliqueProtocolChanges, engine, vm.Config{}, nil, nil)
	chain, _ = core.NewBlockChain(db, nil, params.AllCliqueProtocolChanges, engine, vm.Config{}, nil, nil, nil)
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks[2:]); err != nil {
		t.Fatalf("failed to insert final block: %v", err)
	}
	if head := chain.CurrentBlock().NumberU64(); head != 3 {
		t.Fatalf("chain head mismatch: have %d, want %d", head, 3)
	}
}

func TestSealHash(t *testing.T) {
	have := SealHash(&types.Header{
		Difficulty: new(big.Int),
		Number:     new(big.Int),
		Extra:      make([]byte, ExtraVanity+ExtraSeal),
		BaseFee:    new(big.Int),
	})
	want := common.HexToHash("0xbd3d1fa43fbc4c5bfcc91b179ec92e2861df3654de60468beb908ff805359e8f")
	if have != want {
		t.Errorf("have %x, want %x", have, want)
	}
}

func TestCalcDifficulty(t *testing.T) {
	addrs := []common.Address{
		common.HexToAddress("0abcdefghijklmnopqrs"),
		common.HexToAddress("1abcdefghijklmnopqrs"),
		common.HexToAddress("2abcdefghijklmnopqrs"),
		common.HexToAddress("3abcdefghijklmnopqrs"),
		common.HexToAddress("4abcdefghijklmnopqrs"),
		common.HexToAddress("5abcdefghijklmnopqrs"),
	}
	for _, test := range []testCalcDifficulty{
		// Genesis.
		{
			name: "3/genesis",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 0},
				addrs[1]: {LastSignedBlock: 0},
				addrs[2]: {LastSignedBlock: 0},
			},
		},
		{
			name: "6/genesis",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 0},
				addrs[1]: {LastSignedBlock: 0},
				addrs[2]: {LastSignedBlock: 0},
				addrs[3]: {LastSignedBlock: 0},
				addrs[4]: {LastSignedBlock: 0},
				addrs[5]: {LastSignedBlock: 0},
			},
		},
		// All signed.
		{
			name: "3/all-signed/in-turn",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 1},
				addrs[1]: {LastSignedBlock: 2},
				addrs[2]: {LastSignedBlock: 3},
			},
		},
		{
			name: "3/all-signed/out-of-turn",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 1},
				addrs[1]: {LastSignedBlock: 4},
				addrs[2]: {LastSignedBlock: 3},
			},
		},
		{
			name: "6/all-signed/in-turn",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 1},
				addrs[1]: {LastSignedBlock: 2},
				addrs[2]: {LastSignedBlock: 3},
				addrs[3]: {LastSignedBlock: 4},
				addrs[4]: {LastSignedBlock: 5},
				addrs[5]: {LastSignedBlock: 6},
			},
		},
		{
			name: "6/all-signed/out-of-turn",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 9},
				addrs[1]: {LastSignedBlock: 2},
				addrs[2]: {LastSignedBlock: 7},
				addrs[3]: {LastSignedBlock: 8},
				addrs[4]: {LastSignedBlock: 5},
				addrs[5]: {LastSignedBlock: 6},
			},
		},
		// One new.
		{
			name: "3/one-new",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 0},
				addrs[1]: {LastSignedBlock: 4},
				addrs[2]: {LastSignedBlock: 3},
			},
		},
		{
			name: "6/one-new",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 1},
				addrs[1]: {LastSignedBlock: 2},
				addrs[2]: {LastSignedBlock: 3},
				addrs[3]: {LastSignedBlock: 4},
				addrs[4]: {LastSignedBlock: 5},
				addrs[5]: {LastSignedBlock: 0},
			},
		},
		// Multiple new.
		{
			name: "3/multiple-new",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 0},
				addrs[1]: {LastSignedBlock: 0},
				addrs[2]: {LastSignedBlock: 3},
			},
		},
		{
			name: "6/multiple-new",
			lastSigned: map[common.Address]Signer{
				addrs[0]: {LastSignedBlock: 0},
				addrs[1]: {LastSignedBlock: 0},
				addrs[2]: {LastSignedBlock: 3},
				addrs[3]: {LastSignedBlock: 0},
				addrs[4]: {LastSignedBlock: 0},
				addrs[5]: {LastSignedBlock: 0},
			},
		},
	} {
		t.Run(test.name, test.run)
	}
}

type testCalcDifficulty struct {
	name       string
	lastSigned map[common.Address]Signer
}

func (test *testCalcDifficulty) run(t *testing.T) {
	var signers []common.Address
	for addr := range test.lastSigned {
		signers = append(signers, addr)
	}
	sort.Slice(signers, func(i, j int) bool {
		iAddr, jAddr := signers[i], signers[j]
		iN, jN := test.lastSigned[iAddr].LastSignedBlock, test.lastSigned[jAddr].LastSignedBlock
		if iN != jN {
			return iN < jN
		}
		return bytes.Compare(iAddr[:], jAddr[:]) < 0
	})
	for i, signer := range signers {
		exp := len(signers) - i
		got := calcDifficulty(test.lastSigned, signer)
		if got.Cmp(new(big.Int).SetUint64(uint64(exp))) != 0 {
			t.Errorf("expected difficulty %d but got %d", exp, got.Uint64())
		}
	}
}
