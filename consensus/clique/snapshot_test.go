// Copyright 2017 The go-ethereum Authors
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
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// testerAccountPool is a pool to maintain currently active tester accounts,
// mapped from textual names used in the tests below to actual Ethereum private
// keys capable of signing transactions.
type testerAccountPool struct {
	accounts map[string]*ecdsa.PrivateKey
}

func newTesterAccountPool() *testerAccountPool {
	return &testerAccountPool{
		accounts: make(map[string]*ecdsa.PrivateKey),
	}
}

// checkpoint creates a Clique checkpoint signer section from the provided list
// of authorized signers and embeds it into the provided header.
func (ap *testerAccountPool) checkpoint(header *types.Header, signers []string) {
	auths := make([]common.Address, len(signers))
	for i, signer := range signers {
		auths[i] = ap.address(signer)
	}
	// MODIFIED by Jakub Pajek (clique permissions)
	//sort.Sort(signersAscending(auths))
	sort.Sort(addressesAscending(auths))
	for i, auth := range auths {
		// MODIFIED by Jakub Pajek BEG (clique permissions)
		//copy(header.Extra[extraVanity+i*common.AddressLength:], auth.Bytes())
		index := params.CliqueExtraVanity + i*(common.AddressLength+1)
		copy(header.Extra[index:], auth.Bytes())
		header.Extra[index+common.AddressLength] = params.CliqueExtraVoterMarker
		// MODIFIED by Jakub Pajek END (clique permissions)
	}
}

// address retrieves the Ethereum address of a tester account by label, creating
// a new account if no previous one exists yet.
func (ap *testerAccountPool) address(account string) common.Address {
	// Return the zero account for non-addresses
	if account == "" {
		return common.Address{}
	}
	// Ensure we have a persistent key for the account
	if ap.accounts[account] == nil {
		ap.accounts[account], _ = crypto.GenerateKey()
	}
	// Resolve and return the Ethereum address
	return crypto.PubkeyToAddress(ap.accounts[account].PublicKey)
}

// sign calculates a Clique digital signature for the given block and embeds it
// back into the header.
func (ap *testerAccountPool) sign(header *types.Header, signer string) {
	// Ensure we have a persistent key for the signer
	if ap.accounts[signer] == nil {
		ap.accounts[signer], _ = crypto.GenerateKey()
	}
	// Sign the header and embed the signature in extra data
	sig, _ := crypto.Sign(SealHash(header).Bytes(), ap.accounts[signer])
	// MODIFIED by Jakub Pajek (clique params)
	//copy(header.Extra[len(header.Extra)-extraSeal:], sig)
	copy(header.Extra[len(header.Extra)-params.CliqueExtraSeal:], sig)
}

// testerVote represents a single block signed by a particular account, where
// the account may or may not have cast a Clique vote.
type testerVote struct {
	signer     string
	voted      string
	auth       bool
	checkpoint []string
	newbatch   bool
	// ADDED by Jakub Pajek (voter ring voting)
	signersCount int64
}

type cliqueTest struct {
	epoch   uint64
	signers []string
	votes   []testerVote
	results []string
	failure error
	// ADDED by Jakub Pajek (clique config: voting rule)
	votingRule int
	// ADDED by Jakub Pajek (voter ring voting)
	privateHardFork2Block *big.Int
}

// Tests that Clique signer voting is evaluated correctly for various simple and
// complex scenarios, as well as that a few special corner cases fail correctly.
func TestClique_VotingRuleMajority(t *testing.T) {
	// Define the various voting scenarios to test
	tests := []cliqueTest{
		{
			// Single signer, no votes cast
			signers: []string{"A"},
			votes: []testerVote{
				{signer: "A", signersCount: 1},
			},
			results: []string{"A"},
		}, {
			// Single signer, voting to add two others (only accept first, second needs 2 votes)
			signers: []string{"A"},
			votes: []testerVote{
				{signer: "A", voted: "B", auth: true, signersCount: 1},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "C", auth: true, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Two signers, voting to add three others (only accept first two, third needs 3 votes already)
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", voted: "C", auth: true, signersCount: 2},
				{signer: "A", voted: "D", auth: true, signersCount: 3},
				{signer: "B", voted: "D", auth: true, signersCount: 3},
				{signer: "C", signersCount: 4},
				{signer: "A", voted: "E", auth: true, signersCount: 4},
				{signer: "B", voted: "E", auth: true, signersCount: 4},
			},
			results: []string{"A", "B", "C", "D"},
		}, {
			// Single signer, dropping itself (weird, but one less cornercase by explicitly allowing this)
			signers: []string{"A"},
			votes: []testerVote{
				{signer: "A", voted: "A", auth: false, signersCount: 1},
			},
			results: []string{},
		}, {
			// Two signers, actually needing mutual consent to drop either of them (not fulfilled)
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "B", auth: false, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Two signers, actually needing mutual consent to drop either of them (fulfilled)
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "B", auth: false, signersCount: 2},
				{signer: "B", voted: "B", auth: false, signersCount: 2},
			},
			results: []string{"A"},
		}, {
			// Three signers, two of them deciding to drop the third
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 3},
				{signer: "B", voted: "C", auth: false, signersCount: 3},
			},
			results: []string{"A", "B"},
		}, {
			// Four signers, consensus of two not being enough to drop anyone
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", voted: "C", auth: false, signersCount: 4},
			},
			results: []string{"A", "B", "C", "D"},
		}, {
			// Four signers, consensus of three already being enough to drop someone
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "D", auth: false, signersCount: 4},
				{signer: "B", voted: "D", auth: false, signersCount: 4},
				{signer: "C", voted: "D", auth: false, signersCount: 4},
			},
			results: []string{"A", "B", "C"},
		}, {
			// Authorizations are counted once per signer per target
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "C", auth: true, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Authorizing multiple accounts concurrently is permitted
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "D", auth: true, signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", signersCount: 2},
				{signer: "B", voted: "D", auth: true, signersCount: 2},
				{signer: "A", signersCount: 3},
				{signer: "B", voted: "C", auth: true, signersCount: 3},
			},
			results: []string{"A", "B", "C", "D"},
		}, {
			// Deauthorizations are counted once per signer per target
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "B", auth: false, signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "B", auth: false, signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "B", auth: false, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Deauthorizing multiple accounts concurrently is permitted
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "A", voted: "D", auth: false, signersCount: 4},
				{signer: "B", signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "A", signersCount: 4},
				{signer: "B", voted: "D", auth: false, signersCount: 4},
				{signer: "C", voted: "D", auth: false, signersCount: 4},
				{signer: "A", signersCount: 3},
				{signer: "B", voted: "C", auth: false, signersCount: 3},
			},
			results: []string{"A", "B"},
		}, {
			// Votes from deauthorized signers are discarded immediately (deauth votes)
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "C", voted: "B", auth: false, signersCount: 3},
				{signer: "A", voted: "C", auth: false, signersCount: 3},
				{signer: "B", voted: "C", auth: false, signersCount: 3},
				{signer: "A", voted: "B", auth: false, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Votes from deauthorized signers are discarded immediately (auth votes)
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "C", voted: "D", auth: true, signersCount: 3},
				{signer: "A", voted: "C", auth: false, signersCount: 3},
				{signer: "B", voted: "C", auth: false, signersCount: 3},
				{signer: "A", voted: "D", auth: true, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Cascading changes are not allowed, only the account being voted on may change
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "A", voted: "D", auth: false, signersCount: 4},
				{signer: "B", voted: "C", auth: false, signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "A", signersCount: 4},
				{signer: "B", voted: "D", auth: false, signersCount: 4},
				{signer: "C", voted: "D", auth: false, signersCount: 4},
			},
			results: []string{"A", "B", "C"},
		}, {
			// Changes reaching consensus out of bounds (via a deauth) execute on touch
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "A", voted: "D", auth: false, signersCount: 4},
				{signer: "B", voted: "C", auth: false, signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "A", signersCount: 4},
				{signer: "B", voted: "D", auth: false, signersCount: 4},
				{signer: "C", voted: "D", auth: false, signersCount: 4},
				{signer: "A", signersCount: 3},
				{signer: "C", voted: "C", auth: true, signersCount: 3},
			},
			results: []string{"A", "B"},
		}, {
			// Changes reaching consensus out of bounds (via a deauth) may go out of consensus on first touch
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "A", voted: "D", auth: false, signersCount: 4},
				{signer: "B", voted: "C", auth: false, signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "A", signersCount: 4},
				{signer: "B", voted: "D", auth: false, signersCount: 4},
				{signer: "C", voted: "D", auth: false, signersCount: 4},
				{signer: "A", signersCount: 3},
				{signer: "B", voted: "C", auth: true, signersCount: 3},
			},
			results: []string{"A", "B", "C"},
		}, {
			// Ensure that pending votes don't survive authorization status changes. This
			// corner case can only appear if a signer is quickly added, removed and then
			// re-added (or the inverse), while one of the original voters dropped. If a
			// past vote is left cached in the system somewhere, this will interfere with
			// the final signer outcome.
			signers: []string{"A", "B", "C", "D", "E"},
			votes: []testerVote{
				{signer: "A", voted: "F", auth: true, signersCount: 5}, // Authorize F, 3 votes needed
				{signer: "B", voted: "F", auth: true, signersCount: 5},
				{signer: "C", voted: "F", auth: true, signersCount: 5},
				{signer: "D", voted: "F", auth: false, signersCount: 6}, // Deauthorize F, 4 votes needed (leave A's previous vote "unchanged")
				{signer: "E", voted: "F", auth: false, signersCount: 6},
				{signer: "B", voted: "F", auth: false, signersCount: 6},
				{signer: "C", voted: "F", auth: false, signersCount: 6},
				{signer: "D", voted: "F", auth: true, signersCount: 5}, // Almost authorize F, 2/3 votes needed
				{signer: "E", voted: "F", auth: true, signersCount: 5},
				{signer: "B", voted: "A", auth: false, signersCount: 5}, // Deauthorize A, 3 votes needed
				{signer: "C", voted: "A", auth: false, signersCount: 5},
				{signer: "D", voted: "A", auth: false, signersCount: 5},
				{signer: "B", voted: "F", auth: true, signersCount: 4}, // Finish authorizing F, 3/3 votes needed
			},
			results: []string{"B", "C", "D", "E", "F"},
		}, {
			// Epoch transitions reset all votes to allow chain checkpointing
			epoch:   3,
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", checkpoint: []string{"A", "B"}, signersCount: 2},
				{signer: "B", voted: "C", auth: true, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// An unauthorized signer should not be able to sign blocks
			signers: []string{"A"},
			votes: []testerVote{
				{signer: "B", signersCount: 1},
			},
			failure: errUnauthorizedSigner,
		}, {
			// An authorized signer that signed recently should not be able to sign again
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", signersCount: 2},
				{signer: "A", signersCount: 2},
			},
			failure: errRecentlySigned,
		}, {
			// Recent signatures should not reset on checkpoint blocks imported in a batch
			epoch:   3,
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "A", signersCount: 3},
				{signer: "B", signersCount: 3},
				{signer: "A", checkpoint: []string{"A", "B", "C"}, signersCount: 3},
				{signer: "A", signersCount: 3},
			},
			failure: errRecentlySigned,
		}, {
			// Recent signatures should not reset on checkpoint blocks imported in a new
			// batch (https://github.com/ethereum/go-ethereum/issues/17593). Whilst this
			// seems overly specific and weird, it was a Rinkeby consensus split.
			// ADDED by Jakub Pajek (clique tests)
			// https://github.com/ethereum/go-ethereum/pull/17620
			epoch:   3,
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "A", signersCount: 3},
				{signer: "B", signersCount: 3},
				{signer: "A", checkpoint: []string{"A", "B", "C"}, signersCount: 3},
				{signer: "A", newbatch: true, signersCount: 3},
			},
			failure: errRecentlySigned,
		},
	}

	// Run through the scenarios and test them
	for i, tt := range tests {
		// ADDED by Jakub Pajek (clique config: voting rule)
		tt.votingRule = 2 // Majority
		t.Run(fmt.Sprint(i), tt.run)
		// ADDED by Jakub Pajek BEG (voter ring voting)
		// Run the same test post PrivateHardFork2
		tt.privateHardFork2Block = big.NewInt(0)
		t.Run(fmt.Sprint(i), tt.run)
		// ADDED by Jakub Pajek END (voter ring voting)
	}
}

// Tests that Clique signer voting is evaluated correctly for various simple and
// complex scenarios, as well as that a few special corner cases fail correctly.
func TestClique_VotingRuleSingle(t *testing.T) {
	// Define the various voting scenarios to test
	tests := []cliqueTest{
		{
			// Single signer, no votes cast
			signers: []string{"A"},
			votes: []testerVote{
				{signer: "A", signersCount: 1},
			},
			results: []string{"A"},
		}, {
			// Single signer, voting to add two others (fulfilled)
			signers: []string{"A"},
			votes: []testerVote{
				{signer: "A", voted: "B", auth: true, signersCount: 1},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "C", auth: true, signersCount: 2},
			},
			results: []string{"A", "B", "C"},
		}, {
			// Two signers, voting to add three others (fulfilled)
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", voted: "C", auth: true, signersCount: 3},
				{signer: "A", voted: "D", auth: true, signersCount: 3},
				{signer: "C", signersCount: 4},
				{signer: "B", voted: "D", auth: true, signersCount: 4},
				{signer: "D", signersCount: 4},
				{signer: "A", voted: "E", auth: true, signersCount: 4},
				{signer: "B", voted: "E", auth: true, signersCount: 5},
			},
			results: []string{"A", "B", "C", "D", "E"},
		}, {
			// Single signer, dropping itself (weird, but one less cornercase by explicitly allowing this)
			signers: []string{"A"},
			votes: []testerVote{
				{signer: "A", voted: "A", auth: false, signersCount: 1},
			},
			results: []string{},
		}, {
			// Two signers, one dropping another (fulfilled)
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "B", auth: false, signersCount: 2},
			},
			results: []string{"A"},
		}, {
			// Three signers, two of them deciding to drop the third (fulfilled)
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 3},
				{signer: "B", voted: "C", auth: false, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Four signers, consensus of one already being enough to drop anyone
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", voted: "D", auth: false, signersCount: 3},
				{signer: "A", voted: "B", auth: false, signersCount: 2},
			},
			results: []string{"A"},
		}, {
			// Authorizations are counted once per signer per target
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", signersCount: 3},
				{signer: "A", voted: "C", auth: true, signersCount: 3},
				{signer: "B", signersCount: 3},
				{signer: "A", voted: "C", auth: true, signersCount: 3},
			},
			results: []string{"A", "B", "C"},
		}, {
			// Authorizing multiple accounts concurrently is permitted
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", signersCount: 3},
				{signer: "A", voted: "D", auth: true, signersCount: 3},
				{signer: "C", signersCount: 4},
				{signer: "D", signersCount: 4},
				{signer: "B", voted: "D", auth: true, signersCount: 4},
				{signer: "A", signersCount: 4},
				{signer: "C", signersCount: 4},
				{signer: "B", voted: "C", auth: true, signersCount: 4},
			},
			results: []string{"A", "B", "C", "D"},
		}, {
			// Deauthorizations are counted once per signer per target
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "B", auth: false, signersCount: 2},
				{signer: "A", voted: "B", auth: false, signersCount: 1},
				{signer: "A", voted: "B", auth: false, signersCount: 1},
			},
			results: []string{"A"},
		}, {
			// Deauthorizing multiple accounts concurrently is permitted
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", signersCount: 3},
				{signer: "D", signersCount: 3},
				{signer: "A", voted: "D", auth: false, signersCount: 3},
				{signer: "B", signersCount: 2},
				{signer: "A", signersCount: 2},
				{signer: "B", voted: "D", auth: false, signersCount: 2},
				{signer: "A", signersCount: 2},
				{signer: "B", voted: "C", auth: false, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Votes from deauthorized signers are discarded immediately (deauth votes)
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "C", voted: "B", auth: false, signersCount: 3},
				{signer: "A", voted: "C", auth: false, signersCount: 2},
				{signer: "A", voted: "B", auth: false, signersCount: 1},
			},
			results: []string{"A"},
		}, {
			// Votes from deauthorized signers are discarded immediately (auth votes)
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "C", voted: "D", auth: true, signersCount: 3},
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", voted: "C", auth: false, signersCount: 3},
				{signer: "A", voted: "D", auth: true, signersCount: 3},
			},
			results: []string{"A", "B", "D"},
		}, {
			// Cascading changes are not allowed, only the account being voted on may change
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", signersCount: 3},
				{signer: "D", signersCount: 3},
				{signer: "A", voted: "D", auth: false, signersCount: 3},
				{signer: "B", voted: "C", auth: false, signersCount: 2},
				{signer: "A", signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "D", auth: false, signersCount: 2},
				{signer: "B", voted: "D", auth: false, signersCount: 2},
			},
			results: []string{"A", "B"},
		}, {
			// Changes reaching consensus out of bounds (via a deauth) execute on touch
			// Changes reaching consensus out of bounds (via a deauth) may go out of consensus on first touch
			signers: []string{"A", "B", "C", "D"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: false, signersCount: 4},
				{signer: "B", signersCount: 3},
				{signer: "D", signersCount: 3},
				{signer: "A", voted: "D", auth: false, signersCount: 3},
				{signer: "B", voted: "C", auth: false, signersCount: 2},
				{signer: "A", signersCount: 2},
				{signer: "B", signersCount: 2},
				{signer: "A", voted: "D", auth: false, signersCount: 2},
				{signer: "B", voted: "D", auth: false, signersCount: 2},
				{signer: "A", signersCount: 2},
				{signer: "B", voted: "C", auth: true, signersCount: 2},
			},
			results: []string{"A", "B", "C"},
		}, {
			// Ensure that pending votes don't survive authorization status changes. This
			// corner case can only appear if a signer is quickly added, removed and then
			// re-added (or the inverse), while one of the original voters dropped. If a
			// past vote is left cached in the system somewhere, this will interfere with
			// the final signer outcome.
			signers: []string{"A", "B", "C", "D", "E"},
			votes: []testerVote{
				{signer: "A", voted: "F", auth: true, signersCount: 5},
				{signer: "B", voted: "F", auth: true, signersCount: 6},
				{signer: "C", voted: "F", auth: true, signersCount: 6},
				{signer: "D", voted: "F", auth: false, signersCount: 6},
				{signer: "E", voted: "F", auth: false, signersCount: 5},
				{signer: "B", voted: "F", auth: false, signersCount: 5},
				{signer: "C", voted: "F", auth: false, signersCount: 5},
				{signer: "D", voted: "F", auth: true, signersCount: 5},
				{signer: "E", voted: "F", auth: true, signersCount: 6},
				{signer: "B", voted: "A", auth: false, signersCount: 6},
				{signer: "C", voted: "A", auth: false, signersCount: 5},
				{signer: "D", voted: "A", auth: false, signersCount: 5},
				{signer: "B", voted: "F", auth: true, signersCount: 5},
			},
			results: []string{"B", "C", "D", "E", "F"},
		}, {
			// Epoch transitions reset all votes to allow chain checkpointing
			epoch:   3,
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", voted: "C", auth: true, signersCount: 2},
				{signer: "B", signersCount: 3},
				{signer: "A", checkpoint: []string{"A", "B", "C"}, signersCount: 3},
				{signer: "B", voted: "C", auth: false, signersCount: 3},
			},
			results: []string{"A", "B"},
		}, {
			// An unauthorized signer should not be able to sign blocks
			signers: []string{"A"},
			votes: []testerVote{
				{signer: "B", signersCount: 1},
			},
			failure: errUnauthorizedSigner,
		}, {
			// An authorized signer that signed recently should not be able to sign again
			signers: []string{"A", "B"},
			votes: []testerVote{
				{signer: "A", signersCount: 2},
				{signer: "A", signersCount: 2},
			},
			failure: errRecentlySigned,
		}, {
			// Recent signatures should not reset on checkpoint blocks imported in a batch
			epoch:   3,
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "A", signersCount: 3},
				{signer: "B", signersCount: 3},
				{signer: "A", checkpoint: []string{"A", "B", "C"}, signersCount: 3},
				{signer: "A", signersCount: 3},
			},
			failure: errRecentlySigned,
		}, {
			// Recent signatures should not reset on checkpoint blocks imported in a new
			// batch (https://github.com/ethereum/go-ethereum/issues/17593). Whilst this
			// seems overly specific and weird, it was a Rinkeby consensus split.
			// ADDED by Jakub Pajek (clique tests)
			// https://github.com/ethereum/go-ethereum/pull/17620
			epoch:   3,
			signers: []string{"A", "B", "C"},
			votes: []testerVote{
				{signer: "A", signersCount: 3},
				{signer: "B", signersCount: 3},
				{signer: "A", checkpoint: []string{"A", "B", "C"}, signersCount: 3},
				{signer: "A", newbatch: true, signersCount: 3},
			},
			failure: errRecentlySigned,
		},
	}

	// Run through the scenarios and test them
	for i, tt := range tests {
		// ADDED by Jakub Pajek (clique config: voting rule)
		tt.votingRule = 1 // Single vote
		t.Run(fmt.Sprint(i), tt.run)
		// ADDED by Jakub Pajek BEG (voter ring voting)
		// Run the same test post PrivateHardFork2
		tt.privateHardFork2Block = big.NewInt(0)
		t.Run(fmt.Sprint(i), tt.run)
		// ADDED by Jakub Pajek END (voter ring voting)
	}
}

func (tt *cliqueTest) run(t *testing.T) {
	// Create the account pool and generate the initial set of signers
	accounts := newTesterAccountPool()

	signers := make([]common.Address, len(tt.signers))
	for j, signer := range tt.signers {
		signers[j] = accounts.address(signer)
	}
	for j := 0; j < len(signers); j++ {
		for k := j + 1; k < len(signers); k++ {
			if bytes.Compare(signers[j][:], signers[k][:]) > 0 {
				signers[j], signers[k] = signers[k], signers[j]
			}
		}
	}
	// Create the genesis block with the initial set of signers
	genesis := &core.Genesis{
		// MODIFIED by Jakub Pajek (clique permissions)
		//ExtraData: make([]byte, extraVanity+common.AddressLength*len(signers)+extraSeal),
		ExtraData: make([]byte, params.CliqueExtraVanity+(common.AddressLength+1)*len(signers)+params.CliqueExtraSeal),
		BaseFee:   big.NewInt(params.InitialBaseFee),
	}
	for j, signer := range signers {
		// MODIFIED by Jakub Pajek BEG (clique permissions)
		//copy(genesis.ExtraData[extraVanity+j*common.AddressLength:], signer[:])
		index := params.CliqueExtraVanity + j*(common.AddressLength+1)
		copy(genesis.ExtraData[index:], signer[:])
		genesis.ExtraData[index+common.AddressLength] = params.CliqueExtraVoterMarker
		// MODIFIED by Jakub Pajek END (clique permissions)
	}

	// Assemble a chain of headers from the cast votes
	config := *params.TestChainConfig
	// ADDED by Jakub Pajek (chain config: refundable fees)
	config.RefundableFees = true
	// ADDED by Jakub Pajek BEG (hard fork: list)
	config.PrivateHardFork1Block = big.NewInt(0)
	config.PrivateHardFork2Block = tt.privateHardFork2Block
	config.PrivateHardFork3Block = nil
	// ADDED by Jakub Pajek END (hard fork: list)
	// MODIFIED by Jakub Pajek (clique config: variable period)
	//config.Clique = &params.CliqueConfig{
	config.Clique = []params.CliqueConfigEntry{
		{
			Period: 1,
			Epoch:  tt.epoch,
			// ADDED by Jakub Pajek (clique config: block reward)
			BlockReward: params.CliqueBlockReward,
			// ADDED by Jakub Pajek (clique config: voting rule)
			VotingRule: tt.votingRule,
			// ADDED by Jakub Pajek (hard fork: HF2: voting rule change)
			VotingRulePrivHardFork2: tt.votingRule,
			// ADDED by Jakub Pajek (clique config: min stall period)
			MinStallPeriod: params.CliqueMinStallPeriod,
			// ADDED by Jakub Pajek (clique config: min offline time)
			MinOfflineTime: params.CliqueMinOfflineTime,
			// ADDED by Jakub Pajek (clique config: min strike count)
			MinStrikeCount: params.CliqueMinStrikeCount,
		},
	}
	genesis.Config = &config

	engine := New(config.Clique, rawdb.NewMemoryDatabase())
	engine.fakeDiff = true
	// ADDED by Jakub Pajek (clique static block rewards)
	engine.fakeRewards = true
	// ADDED by Jakub Pajek (voter ring voting)
	engine.fakeVoterRing = (tt.privateHardFork2Block != nil)

	_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, len(tt.votes), func(j int, gen *core.BlockGen) {
		// COMMENTED by Jakub Pajek (clique multiple votes)
		/*
			// Cast the vote contained in this block
			gen.SetCoinbase(accounts.address(tt.votes[j].voted))
			if tt.votes[j].auth {
				var nonce types.BlockNonce
				copy(nonce[:], nonceAuthVote)
				gen.SetNonce(nonce)
			}
		*/
	})
	// Iterate through the blocks and seal them individually
	for j, block := range blocks {
		// Get the header and prepare it for signing
		header := block.Header()
		if j > 0 {
			header.ParentHash = blocks[j-1].Hash()
		}
		// MODIFIED by Jakub Pajek (clique multiple votes)
		//header.Extra = make([]byte, extraVanity+extraSeal)
		header.Extra = make([]byte, params.CliqueExtraVanity)
		if auths := tt.votes[j].checkpoint; auths != nil {
			// MODIFIED by Jakub Pajek (clique permissions)
			//header.Extra = make([]byte, extraVanity+len(auths)*common.AddressLength+extraSeal)
			header.Extra = append(header.Extra, make([]byte, len(auths)*(common.AddressLength+1))...)
			accounts.checkpoint(header, auths)
		}
		// ADDED by Jakub Pajek BEG (clique multiple votes)
		// Cast the vote contained in this block
		if voted := tt.votes[j].voted; len(voted) > 0 {
			votedAddress := accounts.address(voted)
			header.Extra = append(header.Extra, votedAddress[:]...)
			if tt.votes[j].auth {
				header.Extra = append(header.Extra, params.CliqueExtraVoterVote)
			} else {
				header.Extra = append(header.Extra, params.CliqueExtraDropVote)
			}
		}
		header.Extra = append(header.Extra, make([]byte, params.CliqueExtraSeal)...)
		// ADDED by Jakub Pajek END (clique multiple votes)

		// MODIFIED by Jakub Pajek (clique 1-n scale difficulties)
		//header.Difficulty = diffInTurn // Ignored, we just need a valid number
		// MODIFIED by Jakub Pajek (voter ring voting)
		//header.Difficulty = big.NewInt(1) // Ignored, we just need a valid number
		if tt.votes[j].signersCount > 0 {
			// If signers count for a block is set, use it to estimate the difficulty
			// (It does not have to be exact, just within the current ring's allowed range)
			if engine.fakeVoterRing {
				// Set the difficulty to the maximum allowed value in the voter ring range
				header.Difficulty = big.NewInt(tt.votes[j].signersCount * 2)
			} else {
				// Set the difficulty to the maximum allowed value in the sealer ring range
				header.Difficulty = big.NewInt(tt.votes[j].signersCount)
			}
		} else {
			// If signers count for a block is not set, use the lowest allowed value in the
			// sealer ring range, which will cause all the tests in the voter ring to faild.
			header.Difficulty = big.NewInt(1)
		}

		// Generate the signature, embed it into the header and the block
		accounts.sign(header, tt.votes[j].signer)
		blocks[j] = block.WithSeal(header)
	}
	// Split the blocks up into individual import batches (cornercase testing)
	batches := [][]*types.Block{nil}
	for j, block := range blocks {
		if tt.votes[j].newbatch {
			batches = append(batches, nil)
		}
		batches[len(batches)-1] = append(batches[len(batches)-1], block)
	}
	// Pass all the headers through clique and ensure tallying succeeds
	// MODIFIED by Jakub Pajek (deterministic fork choice rules)
	//chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, nil, engine, vm.Config{}, nil, nil)
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, nil, engine, vm.Config{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create test chain: %v", err)
	}
	defer chain.Stop()

	for j := 0; j < len(batches)-1; j++ {
		if k, err := chain.InsertChain(batches[j]); err != nil {
			t.Fatalf("failed to import batch %d, block %d: %v", j, k, err)
			break
		}
	}
	if _, err = chain.InsertChain(batches[len(batches)-1]); err != tt.failure {
		t.Errorf("failure mismatch: have %v, want %v", err, tt.failure)
	}
	if tt.failure != nil {
		return
	}

	// No failure was produced or requested, generate the final voting snapshot
	head := blocks[len(blocks)-1]

	snap, err := engine.snapshot(chain, head.NumberU64(), head.Hash(), nil)
	if err != nil {
		t.Fatalf("failed to retrieve voting snapshot: %v", err)
	}
	// Verify the final list of signers against the expected ones
	signers = make([]common.Address, len(tt.results))
	for j, signer := range tt.results {
		signers[j] = accounts.address(signer)
	}
	for j := 0; j < len(signers); j++ {
		for k := j + 1; k < len(signers); k++ {
			if bytes.Compare(signers[j][:], signers[k][:]) > 0 {
				signers[j], signers[k] = signers[k], signers[j]
			}
		}
	}
	result := snap.signers()
	if len(result) != len(signers) {
		t.Fatalf("signers mismatch: have %x, want %x", result, signers)
	}
	for j := 0; j < len(result); j++ {
		if !bytes.Equal(result[j][:], signers[j][:]) {
			t.Fatalf("signer %d: signer mismatch: have %x, want %x", j, result[j], signers[j])
		}
	}
}
