// Copyright 2021 The go-ethereum Authors
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

package core

import (
	crand "crypto/rand"
	"errors"
	"math/big"
	mrand "math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// ChainReader defines a small collection of methods needed to access the local
// blockchain during header verification. It's implemented by both blockchain
// and lightchain.
type ChainReader interface {
	// Config retrieves the header chain's chain configuration.
	Config() *params.ChainConfig

	// GetTd returns the total difficulty of a local block.
	GetTd(common.Hash, uint64) *big.Int
}

// ForkChoice is the fork chooser based on the highest total difficulty of the
// chain(the fork choice used in the eth1) and the external fork choice (the fork
// choice used in the eth2). This main goal of this ForkChoice is not only for
// offering fork choice during the eth1/2 merge phase, but also keep the compatibility
// for all other proof-of-work networks.
type ForkChoice struct {
	chain ChainReader
	rand  *mrand.Rand

	// preserve is a helper function used in td fork choice.
	// Miners will prefer to choose the local mined block if the
	// local td is equal to the extern one. It can be nil for light
	// client
	preserve func(header *types.Header) bool

	// ADDED by Jakub Pajek (deterministic fork choice rules)
	// deterministic is a helper function used during fork choice.
	// Determines whether miners should use determinictic fork choice
	// rules, which is the case for clique in order to avoid deadlocks.
	// It can be nil for light client.
	deterministic func() bool
}

// MODIFIED by Jakub Pajek (deterministic fork choice rules)
// func NewForkChoice(chainReader ChainReader, preserve func(header *types.Header) bool) *ForkChoice {
func NewForkChoice(chainReader ChainReader, preserve func(header *types.Header) bool, deterministic func() bool) *ForkChoice {
	// Seed a fast but crypto originating random generator
	seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		log.Crit("Failed to initialize random seed", "err", err)
	}
	return &ForkChoice{
		chain:    chainReader,
		rand:     mrand.New(mrand.NewSource(seed.Int64())),
		preserve: preserve,
		// ADDED by Jakub Pajek (deterministic fork choice rules)
		deterministic: deterministic,
	}
}

// MODIFIED by Jakub Pajek (deterministic fork choice rules)
// ReorgNeeded returns whether the reorg should be applied
// based on the given external header and local canonical chain.
//
// In the extern mode, the trusted header is always selected as the head.
//
// In the deterministic td mode, the new head is chosen if (in order):
//   - the corresponding total difficulty is higher, or
//   - in case of a tie, if the corresponding block number is lower, or
//   - in case of a tie, if the corresponding block used more gas, of
//   - in case of a tie, if the corresponding header hash is lower.
//
// In the non-deterministic td mode, the new head is chosen if (in order):
//   - the corresponding total difficulty is higher, or
//   - in case of a tie, if the corresponding block number is lower, or
//   - in case of a tie, randomly (reduces the vulnerability to selfish mining).
//
// func (f *ForkChoice) ReorgNeeded(current *types.Header, header *types.Header) (bool, error) {
func (f *ForkChoice) ReorgNeeded(current *types.Header, header *types.Header, dummy bool) (bool, error) {
	var (
		localHash    = current.Hash()
		externHash   = header.Hash()
		localNumber  = current.Number.Uint64()
		externNumber = header.Number.Uint64()
		localTD      = f.chain.GetTd(localHash, localNumber)
		externTd     = f.chain.GetTd(externHash, externNumber)
	)
	if localTD == nil || externTd == nil {
		return false, errors.New("missing td")
	}
	// Extern mode:
	// Accept the new header as the chain head if the transition
	// is already triggered. We assume all the headers after the
	// transition come from the trusted consensus layer.
	if ttd := f.chain.Config().TerminalTotalDifficulty; ttd != nil && ttd.Cmp(externTd) <= 0 {
		return true, nil
	}
	// TD mode:
	// If the total difficulty is higher than our known, add it to the canonical chain.
	reorg := externTd.Cmp(localTD) > 0
	if !reorg && externTd.Cmp(localTD) == 0 {
		// If the total difficulty is the same, choose block with lower block number.
		if externNumber < localNumber {
			reorg = true
		} else if externNumber == localNumber {
			if f.deterministic != nil && f.deterministic() {
				// Deterministic TD mode:
				// If the block number is the same, choose block with the most gas used.
				if header.GasUsed > current.GasUsed {
					reorg = true
				} else if header.GasUsed == current.GasUsed {
					// If gas used is the same, choose block with lower hash.
					reorg = externHash.Big().Cmp(localHash.Big()) < 0
				}
			} else {
				// Non-deterministic TD mode (original):
				// Reduce the vulnerability to selfish mining.
				// Please refer to http://www.cs.cornell.edu/~ie53/publications/btcProcFC.pdf
				var currentPreserve, externPreserve bool
				if f.preserve != nil {
					currentPreserve, externPreserve = f.preserve(current), f.preserve(header)
				}
				reorg = !currentPreserve && (externPreserve || f.rand.Float64() < 0.5)
			}
		}
	}
	return reorg, nil
}
