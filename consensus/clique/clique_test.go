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
	"encoding/json"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"testing"
	"time"

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
func newRandomAddress() common.Address {
	return common.BytesToAddress([]byte{
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))})
}

func newRandomProposals(proposalsCount int, proposal uint64) Proposals {
	proposals := make(Proposals)
	for i := 0; i < proposalsCount; i++ {
		nextProposal := proposal
		if nextProposal != proposalSignerVote && nextProposal != proposalVoterVote && nextProposal != proposalDropVote {
			nextProposal = uint64(rand.Intn(3))
		}
		proposals[newRandomAddress()] = Proposal{Block: rand.Uint64(), Proposal: nextProposal}
	}
	return proposals
}

func mapEquals[T comparable](a, b map[common.Address]T) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func TestProposalsRlpEncoding(t *testing.T) {
	const maxCount int = 100
	for _, test := range []testProposalsRlpEncoding{
		{
			name:      "proposals/empty",
			proposals: Proposals{},
		},
		{
			name:      "proposals/singleSigner",
			proposals: newRandomProposals(1, proposalSignerVote),
		},
		{
			name:      "proposals/singleVoter",
			proposals: newRandomProposals(1, proposalVoterVote),
		},
		{
			name:      "proposals/singleDrop",
			proposals: newRandomProposals(1, proposalDropVote),
		},
		{
			name:      "proposals/multipleSigner",
			proposals: newRandomProposals(rand.Intn(maxCount)+1, proposalSignerVote),
		},
		{
			name:      "proposals/multipleVoter",
			proposals: newRandomProposals(rand.Intn(maxCount)+1, proposalVoterVote),
		},
		{
			name:      "proposals/multipleDrop",
			proposals: newRandomProposals(rand.Intn(maxCount)+1, proposalDropVote),
		},
		{
			name:      "proposals/multipleMixed",
			proposals: newRandomProposals(rand.Intn(maxCount)+1, math.MaxInt),
		},
	} {
		t.Run(test.name, test.run)
	}
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
	blob := buf.Bytes()
	// RLP decode
	proposals := make(Proposals)
	if err := rlp.Decode(bytes.NewReader(blob), &proposals); err != nil {
		t.Fatal("failed to RLP decode proposals", err)
	}
	// Compare
	if !mapEquals(test.proposals, proposals) {
		t.Fatal("failed to RLP encode/decode proposals")
	}
}

// ADDED by Jakub Pajek END (rlp encoded proposals)

// ADDED by Jakub Pajek BEG (rlp encoded snapshots)
func newRandomHash() common.Hash {
	return common.BytesToHash([]byte{
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)),
		byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))})
}

func newRandomSnapshot(votersCount, signersCount, droppedCount, votesCount, tallyCount int) *Snapshot {
	snap := &Snapshot{
		Number:    rand.Uint64(),
		Hash:      newRandomHash(),
		ConfigIdx: rand.Uint64(),
		VoterRing: rand.Intn(2)%2 == 0,
		Voting:    rand.Intn(2)%2 == 0,
		Voters:    make(map[common.Address]uint64),
		Signers:   make(map[common.Address]Signer),
		Dropped:   make(map[common.Address]uint64),
		Tally:     make(map[common.Address]Tally),
	}
	for i := 0; i < votersCount; i++ {
		snap.Voters[newRandomAddress()] = rand.Uint64()
	}
	for i := 0; i < signersCount; i++ {
		snap.Signers[newRandomAddress()] = Signer{LastSignedBlock: rand.Uint64(), SignedCount: rand.Uint64(), StrikeCount: rand.Uint64()}
	}
	for i := 0; i < droppedCount; i++ {
		snap.Dropped[newRandomAddress()] = rand.Uint64()
	}
	for i := 0; i < votesCount; i++ {
		snap.Votes = append(snap.Votes, &Vote{
			Voter:    newRandomAddress(),
			Block:    rand.Uint64(),
			Address:  newRandomAddress(),
			Proposal: uint64(rand.Intn(3)),
		})
	}
	for i := 0; i < tallyCount; i++ {
		snap.Tally[newRandomAddress()] = Tally{Proposal: uint64(rand.Intn(3)), Votes: rand.Uint64()}
	}
	return snap
}

func ptrArrayEquals[T comparable](a, b []*T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if *a[i] != *b[i] {
			return false
		}
	}
	return true
}

func (a *Snapshot) equals(b *Snapshot) bool {
	return a.Number == b.Number &&
		a.Hash == b.Hash &&
		a.ConfigIdx == b.ConfigIdx &&
		a.VoterRing == b.VoterRing &&
		a.Voting == b.Voting &&
		mapEquals(a.Voters, b.Voters) &&
		mapEquals(a.Signers, b.Signers) &&
		mapEquals(a.Dropped, b.Dropped) &&
		ptrArrayEquals(a.Votes, b.Votes) &&
		mapEquals(a.Tally, b.Tally)
}

func TestSnapshotRlpEncoding(t *testing.T) {
	const maxCount int = 100
	for _, test := range []testSnapshotRlpEncoding{
		{
			name: "snapshot/empty",
			snap: newRandomSnapshot(0, 0, 0, 0, 0),
		},
		{
			name: "snapshot/singleVoter",
			snap: newRandomSnapshot(1, 0, 0, 0, 0),
		},
		{
			name: "snapshot/singleSigner",
			snap: newRandomSnapshot(0, 1, 0, 0, 0),
		},
		{
			name: "snapshot/singleDropped",
			snap: newRandomSnapshot(0, 0, 1, 0, 0),
		},
		{
			name: "snapshot/singleVotes",
			snap: newRandomSnapshot(0, 0, 0, 1, 0),
		},
		{
			name: "snapshot/singleTally",
			snap: newRandomSnapshot(0, 0, 0, 0, 1),
		},
		{
			name: "snapshot/singleAll",
			snap: newRandomSnapshot(1, 1, 1, 1, 1),
		},
		{
			name: "snapshot/multipleVoters",
			snap: newRandomSnapshot(rand.Intn(maxCount)+1, 0, 0, 0, 0),
		},
		{
			name: "snapshot/multipleSigners",
			snap: newRandomSnapshot(0, rand.Intn(maxCount)+1, 0, 0, 0),
		},
		{
			name: "snapshot/multipleDropped",
			snap: newRandomSnapshot(0, 0, rand.Intn(maxCount)+1, 0, 0),
		},
		{
			name: "snapshot/multipleVotes",
			snap: newRandomSnapshot(0, 0, 0, rand.Intn(maxCount)+1, 0),
		},
		{
			name: "snapshot/multipleTally",
			snap: newRandomSnapshot(0, 0, 0, 0, rand.Intn(maxCount)+1),
		},
		{
			name: "snapshot/multipleAll",
			snap: newRandomSnapshot(rand.Intn(maxCount)+1, rand.Intn(maxCount)+1, rand.Intn(maxCount)+1, rand.Intn(maxCount)+1, rand.Intn(maxCount)+1),
		},
	} {
		t.Run(test.name, test.run)
	}
}

type testSnapshotRlpEncoding struct {
	name string
	snap *Snapshot
}

func (test *testSnapshotRlpEncoding) run(t *testing.T) {
	// RLP encode
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, test.snap); err != nil {
		t.Fatal("failed to RLP encode snapshot", err)
	}
	blob := buf.Bytes()
	// RLP decode
	snap := new(Snapshot)
	if err := rlp.Decode(bytes.NewReader(blob), snap); err != nil {
		t.Fatal("failed to RLP decode snapshot", err)
	}
	// Compare
	if !test.snap.equals(snap) {
		t.Fatal("failed to RLP encode/decode snapshot")
	}
}

func TestCompareSnapshotEncodings(t *testing.T) {
	const (
		votersCount  = 3
		signersCount = 1_000_000
		droppedCount = 0
		votesCount   = 0
		tallyCount   = 0
	)
	snap := newRandomSnapshot(votersCount, signersCount, droppedCount, votesCount, tallyCount)
	// RLP encode
	startTime := time.Now()
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, snap); err != nil {
		t.Fatal("failed to RLP encode snapshot", err)
	}
	rlpBlob := buf.Bytes()
	t.Logf("RLP Encode: size = %d time = %s", len(rlpBlob), time.Since(startTime))
	// RLP decode
	startTime = time.Now()
	snapFromRlp := new(Snapshot)
	if err := rlp.Decode(bytes.NewReader(rlpBlob), snapFromRlp); err != nil {
		t.Fatal("failed to RLP decode snapshot", err)
	}
	t.Logf("RLP Decode: time = %s", time.Since(startTime))
	// JSON encode
	startTime = time.Now()
	jsonBlob, err := json.Marshal(snap)
	if err != nil {
		t.Fatal("failed to JSON encode snapshot", err)
	}
	t.Logf("JSON Encode: size = %d time = %s", len(jsonBlob), time.Since(startTime))
	// JSON decode
	startTime = time.Now()
	snapFromJson := new(Snapshot)
	if err := json.Unmarshal(jsonBlob, snapFromJson); err != nil {
		t.Fatal("failed to JSON decode snapshot", err)
	}
	t.Logf("JSON Decode: time = %s", time.Since(startTime))
}

// ADDED by Jakub Pajek END (rlp encoded snapshots)
