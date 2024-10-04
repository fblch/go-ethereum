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
	"github.com/ethereum/go-ethereum/rlp"
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
	// ADDED by Jakub Pajek (clique static block rewards)
	// In the future consider disabling block rewards, because this test tests the case when consecutive
	// blocks have the same state root. However rewards are enabled on mainnets, so prioritize this case for now.
	//engine.fakeRewards = true
	genspec := &core.Genesis{
		Config: params.AllCliqueProtocolChanges,
		// MODIFIED by Jakub Pajek (clique permissions)
		//ExtraData: make([]byte, extraVanity+common.AddressLength+extraSeal),
		ExtraData: make([]byte, params.CliqueExtraVanity+common.AddressLength+1+params.CliqueExtraSeal),
		Alloc: map[common.Address]core.GenesisAccount{
			addr: {Balance: big.NewInt(10000000000000000)},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	// MODIFIED by Jakub Pajek (clique params)
	//copy(genspec.ExtraData[extraVanity:], addr[:])
	copy(genspec.ExtraData[params.CliqueExtraVanity:], addr[:])
	// ADDED by Jakub Pajek (clique permissions)
	genspec.ExtraData[params.CliqueExtraVanity+common.AddressLength] = params.CliqueExtraVoterMarker
	// ADDED by Jakub Pajek BEG (clique static block rewards)
	// Inject signer's address into the consensus engine so that FinalizeAndAssemble
	// called from GenerateChain below can correctly assign static block rewards.
	engine.Authorize(addr, func(account accounts.Account, s string, data []byte) ([]byte, error) {
		return crypto.Sign(crypto.Keccak256(data), key)
	})
	// ADDED by Jakub Pajek END (clique static block rewards)

	// Generate a batch of blocks, each properly signed
	// MODIFIED by Jakub Pajek (deterministic fork choice rules)
	//chain, _ := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genspec, nil, engine, vm.Config{}, nil, nil)
	chain, _ := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genspec, nil, engine, vm.Config{}, nil, nil, nil)
	defer chain.Stop()

	_, blocks, _ := core.GenerateChainWithGenesis(genspec, engine, 3, func(i int, block *core.BlockGen) {
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
		// MODIFIED by Jakub Pajek (clique params)
		//header.Extra = make([]byte, extraVanity+extraSeal)
		header.Extra = make([]byte, params.CliqueExtraVanity+params.CliqueExtraSeal)
		// MODIFIED by Jakub Pajek (clique 1-n scale difficulties)
		//header.Difficulty = diffInTurn
		header.Difficulty = big.NewInt(1) // single in-turn signer

		sig, _ := crypto.Sign(SealHash(header).Bytes(), key)
		// MODIFIED by Jakub Pajek (clique params)
		//copy(header.Extra[len(header.Extra)-extraSeal:], sig)
		copy(header.Extra[len(header.Extra)-params.CliqueExtraSeal:], sig)
		blocks[i] = block.WithSeal(header)
	}
	// Insert the first two blocks and make sure the chain is valid
	db = rawdb.NewMemoryDatabase()
	// MODIFIED by Jakub Pajek (deterministic fork choice rules)
	//chain, _ = core.NewBlockChain(db, nil, genspec, nil, engine, vm.Config{}, nil, nil)
	chain, _ = core.NewBlockChain(db, nil, genspec, nil, engine, vm.Config{}, nil, nil, nil)
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("failed to insert initial blocks: %v", err)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 2 {
		t.Fatalf("chain head mismatch: have %d, want %d", head, 2)
	}

	// Simulate a crash by creating a new chain on top of the database, without
	// flushing the dirty states out. Insert the last block, triggering a sidechain
	// reimport.
	// MODIFIED by Jakub Pajek (deterministic fork choice rules)
	//chain, _ = core.NewBlockChain(db, nil, genspec, nil, engine, vm.Config{}, nil, nil)
	chain, _ = core.NewBlockChain(db, nil, genspec, nil, engine, vm.Config{}, nil, nil, nil)
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks[2:]); err != nil {
		t.Fatalf("failed to insert final block: %v", err)
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 3 {
		t.Fatalf("chain head mismatch: have %d, want %d", head, 3)
	}
}

func TestSealHash(t *testing.T) {
	have := SealHash(&types.Header{
		Difficulty: new(big.Int),
		Number:     new(big.Int),
		// MODIFIED by Jakub Pajek (clique params)
		//Extra:      make([]byte, 32+65),
		Extra:   make([]byte, params.CliqueExtraVanity+params.CliqueExtraSeal),
		BaseFee: new(big.Int),
	})
	// MODIFIED by Jakub Pajek (zero size extra)
	//want := common.HexToHash("0xbd3d1fa43fbc4c5bfcc91b179ec92e2861df3654de60468beb908ff805359e8f")
	want := common.HexToHash("0x31775027428c8e2ea15ba3512c7dc42bc356fe2cba2a82b537b3633f7e1907ab")
	if have != want {
		t.Errorf("have %x, want %x", have, want)
	}
}

// ADDED by Jakub Pajek BEG (clique 1-n scale difficulties)
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
	snap := newGenesisSnapshot(nil, nil, 0, common.Hash{}, make([]common.Address, 0), signers, false)
	for _, signer := range signers {
		snap.Signers[signer] = test.lastSigned[signer]
	}
	for i, signer := range signers {
		exp := len(signers) - i
		got := snap.calcSealerRingDifficulty(signer)
		if got.Cmp(new(big.Int).SetUint64(uint64(exp))) != 0 {
			t.Errorf("expected difficulty %d but got %d", exp, got.Uint64())
		}
	}
}

// ADDED by Jakub Pajek END (clique 1-n scale difficulties)

// ADDED by Jakub Pajek BEG (rlp encoded proposals)
func TestProposalsRlpEncoding(t *testing.T) {
	for _, test := range []testProposalsRlpEncoding{
		{
			name:      "proposals/empty",
			proposals: Proposals{},
		},
		{
			name: "proposals/singleSigner",
			proposals: Proposals{
				common.HexToAddress("0xf5efffa5D659E773872E61Ac355b9D1972dd93E1"): Proposal{Block: 359083, Proposal: proposalSignerVote},
			},
		},
		{
			name: "proposals/singleVoter",
			proposals: Proposals{
				common.HexToAddress("0x7BD44224c1a1d311A2F7c7C530b5e64F84Bd4d5c"): Proposal{Block: 181414, Proposal: proposalVoterVote},
			},
		},
		{
			name: "proposals/singleDrop",
			proposals: Proposals{
				common.HexToAddress("0xb2F6eab262b56f08De43AA0E990bd33D30D20936"): Proposal{Block: 867387, Proposal: proposalDropVote},
			},
		},
		{
			name: "proposals/multipleSigner",
			proposals: Proposals{
				common.HexToAddress("0xAFa3569CdB9916F8130dA29Bd8e70F16403e1DDb"): Proposal{Block: 567995, Proposal: proposalSignerVote},
				common.HexToAddress("0xF466F5886e3753d3aB6AeF9Eabb1D8E7BdE24cd6"): Proposal{Block: 710886, Proposal: proposalSignerVote},
				common.HexToAddress("0xFC9C3a46EE1eC56536847aAb7cc0969A592B8143"): Proposal{Block: 176676, Proposal: proposalSignerVote},
				common.HexToAddress("0xD27A54423C9723F8E5a2685A33C9caA0a8355101"): Proposal{Block: 909229, Proposal: proposalSignerVote},
				common.HexToAddress("0x4f4CBC36a0B0d834C29AADC9F7b1E304779beF62"): Proposal{Block: 131303, Proposal: proposalSignerVote},
				common.HexToAddress("0x20b20eAE302c821b53018037B0f3c1eC90c0af5B"): Proposal{Block: 644475, Proposal: proposalSignerVote},
				common.HexToAddress("0x4c9AF439b1A6761B8E549D8d226A468a6b2803A8"): Proposal{Block: 762002, Proposal: proposalSignerVote},
				common.HexToAddress("0xD6B7d52E15678B9195F12F3a6D6cb79dcDcCb690"): Proposal{Block: 759492, Proposal: proposalSignerVote},
				common.HexToAddress("0xaf1b5F42AC0E105F754368b43C012D199478bc07"): Proposal{Block: 706185, Proposal: proposalSignerVote},
				common.HexToAddress("0x6CaA34d5E113468251CD6219e3567093523E568E"): Proposal{Block: 983215, Proposal: proposalSignerVote},
			},
		},
		{
			name: "proposals/multipleVoter",
			proposals: Proposals{
				common.HexToAddress("0xDE2F4F3617Fd02EB0a7bD4d7043021ce515bf82A"): Proposal{Block: 96163, Proposal: proposalVoterVote},
				common.HexToAddress("0xfAeCD9790D80587e92F076e899e3dB1b775caB96"): Proposal{Block: 965056, Proposal: proposalVoterVote},
				common.HexToAddress("0x12755Fd8705c2c1aD3F6D363FDe68D2202b68F97"): Proposal{Block: 215348, Proposal: proposalVoterVote},
				common.HexToAddress("0x73590e408FDE745846cF4B90f9CD445A00dd63B7"): Proposal{Block: 491908, Proposal: proposalVoterVote},
				common.HexToAddress("0x7359852f47d7917986E804E92a44255AD7dD63B7"): Proposal{Block: 810100, Proposal: proposalVoterVote},
				common.HexToAddress("0x8ab426EB95A1C47681B80826eB9446208aAC898f"): Proposal{Block: 461654, Proposal: proposalVoterVote},
				common.HexToAddress("0x022A333F28e9fa47B13D0AdFF812F9230e4Beee9"): Proposal{Block: 477760, Proposal: proposalVoterVote},
				common.HexToAddress("0xdEF8BAF79424fc63744dD3f99b33c16a01CE7235"): Proposal{Block: 481067, Proposal: proposalVoterVote},
				common.HexToAddress("0xfcFFE190Ed10b001a91441fB1482ae446dE2B619"): Proposal{Block: 568934, Proposal: proposalVoterVote},
				common.HexToAddress("0x0d9f01809436c68FFd490821D2ECf723dd7Bf73d"): Proposal{Block: 649533, Proposal: proposalVoterVote},
			},
		},
		{
			name: "proposals/multipleDrop",
			proposals: Proposals{
				common.HexToAddress("0xe9AB8337CAf429E244d8bfa0E97f92d12c39FAd2"): Proposal{Block: 591100, Proposal: proposalDropVote},
				common.HexToAddress("0x43a800f0fadc6aC1Dfc17986edBD4A1e4808Bb31"): Proposal{Block: 689443, Proposal: proposalDropVote},
				common.HexToAddress("0x267B30a636A4bAf53b0E788C8C4fF5C2FD4FfdC0"): Proposal{Block: 176033, Proposal: proposalDropVote},
				common.HexToAddress("0x3d3F20583c80582B5DB10724B8513e7fbc28B718"): Proposal{Block: 224695, Proposal: proposalDropVote},
				common.HexToAddress("0x65Ec775Cd4B535d517b8B1D36199BF83480672aa"): Proposal{Block: 900909, Proposal: proposalDropVote},
				common.HexToAddress("0x958Ef6947b4A17dFE31cDF421463C9342159b198"): Proposal{Block: 188197, Proposal: proposalDropVote},
				common.HexToAddress("0x8ABDcEF84A78497416d476d3424d930D65B453Bf"): Proposal{Block: 846133, Proposal: proposalDropVote},
				common.HexToAddress("0x5F515F6C524B18cA30f7783Fb58Dd4bE2e9904EC"): Proposal{Block: 32504, Proposal: proposalDropVote},
				common.HexToAddress("0xeC8c7F9f3D7427fBB2487a579993Ac46933Bb532"): Proposal{Block: 731578, Proposal: proposalDropVote},
				common.HexToAddress("0xE556bd254ee9a4417eDFa77822D1c43A47C895FA"): Proposal{Block: 777302, Proposal: proposalDropVote},
			},
		},
		{
			name: "proposals/multipleMixed",
			proposals: Proposals{
				common.HexToAddress("0x73590e408FDE745846cF4B90f9CD445A00dd63B7"): Proposal{Block: 491908, Proposal: proposalVoterVote},
				common.HexToAddress("0x4f4CBC36a0B0d834C29AADC9F7b1E304779beF62"): Proposal{Block: 131303, Proposal: proposalSignerVote},
				common.HexToAddress("0x3d3F20583c80582B5DB10724B8513e7fbc28B718"): Proposal{Block: 224695, Proposal: proposalDropVote},
				common.HexToAddress("0x6CaA34d5E113468251CD6219e3567093523E568E"): Proposal{Block: 983215, Proposal: proposalSignerVote},
				common.HexToAddress("0xDE2F4F3617Fd02EB0a7bD4d7043021ce515bf82A"): Proposal{Block: 96163, Proposal: proposalVoterVote},
				common.HexToAddress("0x4c9AF439b1A6761B8E549D8d226A468a6b2803A8"): Proposal{Block: 762002, Proposal: proposalSignerVote},
				common.HexToAddress("0xD6B7d52E15678B9195F12F3a6D6cb79dcDcCb690"): Proposal{Block: 759492, Proposal: proposalSignerVote},
				common.HexToAddress("0xE556bd254ee9a4417eDFa77822D1c43A47C895FA"): Proposal{Block: 777302, Proposal: proposalDropVote},
				common.HexToAddress("0xFC9C3a46EE1eC56536847aAb7cc0969A592B8143"): Proposal{Block: 176676, Proposal: proposalSignerVote},
				common.HexToAddress("0xF466F5886e3753d3aB6AeF9Eabb1D8E7BdE24cd6"): Proposal{Block: 710886, Proposal: proposalSignerVote},
				common.HexToAddress("0xdEF8BAF79424fc63744dD3f99b33c16a01CE7235"): Proposal{Block: 481067, Proposal: proposalVoterVote},
				common.HexToAddress("0x20b20eAE302c821b53018037B0f3c1eC90c0af5B"): Proposal{Block: 644475, Proposal: proposalSignerVote},
				common.HexToAddress("0x12755Fd8705c2c1aD3F6D363FDe68D2202b68F97"): Proposal{Block: 215348, Proposal: proposalVoterVote},
				common.HexToAddress("0x8ABDcEF84A78497416d476d3424d930D65B453Bf"): Proposal{Block: 846133, Proposal: proposalDropVote},
				common.HexToAddress("0x43a800f0fadc6aC1Dfc17986edBD4A1e4808Bb31"): Proposal{Block: 689443, Proposal: proposalDropVote},
				common.HexToAddress("0xeC8c7F9f3D7427fBB2487a579993Ac46933Bb532"): Proposal{Block: 731578, Proposal: proposalDropVote},
				common.HexToAddress("0xD27A54423C9723F8E5a2685A33C9caA0a8355101"): Proposal{Block: 909229, Proposal: proposalSignerVote},
				common.HexToAddress("0x958Ef6947b4A17dFE31cDF421463C9342159b198"): Proposal{Block: 188197, Proposal: proposalDropVote},
				common.HexToAddress("0x8ab426EB95A1C47681B80826eB9446208aAC898f"): Proposal{Block: 461654, Proposal: proposalVoterVote},
				common.HexToAddress("0x022A333F28e9fa47B13D0AdFF812F9230e4Beee9"): Proposal{Block: 477760, Proposal: proposalVoterVote},
				common.HexToAddress("0xfcFFE190Ed10b001a91441fB1482ae446dE2B619"): Proposal{Block: 568934, Proposal: proposalVoterVote},
				common.HexToAddress("0x267B30a636A4bAf53b0E788C8C4fF5C2FD4FfdC0"): Proposal{Block: 176033, Proposal: proposalDropVote},
				common.HexToAddress("0xe9AB8337CAf429E244d8bfa0E97f92d12c39FAd2"): Proposal{Block: 591100, Proposal: proposalDropVote},
				common.HexToAddress("0xaf1b5F42AC0E105F754368b43C012D199478bc07"): Proposal{Block: 706185, Proposal: proposalSignerVote},
				common.HexToAddress("0xAFa3569CdB9916F8130dA29Bd8e70F16403e1DDb"): Proposal{Block: 567995, Proposal: proposalSignerVote},
				common.HexToAddress("0x5F515F6C524B18cA30f7783Fb58Dd4bE2e9904EC"): Proposal{Block: 32504, Proposal: proposalDropVote},
				common.HexToAddress("0xfAeCD9790D80587e92F076e899e3dB1b775caB96"): Proposal{Block: 965056, Proposal: proposalVoterVote},
				common.HexToAddress("0x0d9f01809436c68FFd490821D2ECf723dd7Bf73d"): Proposal{Block: 649533, Proposal: proposalVoterVote},
				common.HexToAddress("0x65Ec775Cd4B535d517b8B1D36199BF83480672aa"): Proposal{Block: 900909, Proposal: proposalDropVote},
				common.HexToAddress("0x7359852f47d7917986E804E92a44255AD7dD63B7"): Proposal{Block: 810100, Proposal: proposalVoterVote},
			},
		},
	} {
		t.Run(test.name, test.run)
	}
}

func (a Proposals) equals(b Proposals) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v.Block != w.Block || v.Proposal != w.Proposal {
			return false
		}
	}
	return true
}

type testProposalsRlpEncoding struct {
	name      string
	proposals Proposals
}

func (test *testProposalsRlpEncoding) run(t *testing.T) {
	// RLP encode
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, test.proposals); err != nil {
		t.Fatal("failed to RLP encode proposals", err)
	}
	encoded := buf.Bytes()
	// RLP decode
	proposals := make(Proposals)
	if err := rlp.Decode(bytes.NewReader(encoded), &proposals); err != nil {
		t.Fatal("failed to RLP decode proposals", err)
	}
	// Compare
	if !test.proposals.equals(proposals) {
		t.Fatal("failed to RLP encode/decode proposals")
	}
}

// ADDED by Jakub Pajek END (rlp encoded proposals)
