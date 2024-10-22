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
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

// API is a user facing RPC API to allow controlling the signer
// mechanisms of the proof-of-authority scheme.
type API struct {
	chain  consensus.ChainHeaderReader
	clique *Clique
}

// GetSnapshot retrieves the state snapshot at a given block.
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSnapshotAtHash retrieves the state snapshot at a given block.
func (api *API) GetSnapshotAtHash(hash common.Hash) (*Snapshot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// IsVoterRing checks if the network operates in the voter ring at the specified block.
func (api *API) IsVoterRing(number *rpc.BlockNumber) (bool, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	return snap.VoterRing, nil
}

// IsVoterRingAtHash checks if the network operates in the voter ring at the specified block.
func (api *API) IsVoterRingAtHash(hash common.Hash) (bool, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	return snap.VoterRing, nil
}

// IsVoting checks if the network is voting at the specified block.
// Note that this function will always return false pre-PrivateHardFork2.
func (api *API) IsVoting(number *rpc.BlockNumber) (bool, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	return snap.Voting, nil
}

// IsVotingAtHash checks if the network is voting at the specified block.
// Note that this function will always return false pre-PrivateHardFork2.
func (api *API) IsVotingAtHash(hash common.Hash) (bool, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	return snap.Voting, nil
}

// GetSigners retrieves the list of authorized signers at the specified block.
func (api *API) GetSigners(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// GetSignersAtHash retrieves the list of authorized signers at the specified block.
func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// GetSignersCount retrieves the number authorized signers at the specified block.
func (api *API) GetSignersCount(number *rpc.BlockNumber) (int, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return 0, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return 0, err
	}
	return len(snap.Signers), nil
}

// GetSignersCountAtHash retrieves the number of authorized signers at the specified block.
func (api *API) GetSignersCountAtHash(hash common.Hash) (int, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return 0, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return 0, err
	}
	return len(snap.Signers), nil
}

// IsSigner checks if the address is an authorized signers at the specified block.
func (api *API) IsSigner(address common.Address, number *rpc.BlockNumber) (bool, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	_, okSigner := snap.Signers[address]
	return okSigner, nil
}

// IsSignerAtHash checks if the address is an authorized signers at the specified block.
func (api *API) IsSignerAtHash(address common.Address, hash common.Hash) (bool, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	_, okSigner := snap.Signers[address]
	return okSigner, nil
}

// GetVoters retrieves the list of authorized voters at the specified block.
func (api *API) GetVoters(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the voters from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.voters(), nil
}

// GetVotersAtHash retrieves the list of authorized voters at the specified block.
func (api *API) GetVotersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.voters(), nil
}

// GetVotersCount retrieves the number of authorized voters at the specified block.
func (api *API) GetVotersCount(number *rpc.BlockNumber) (int, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the voters from its snapshot
	if header == nil {
		return 0, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return 0, err
	}
	return len(snap.Voters), nil
}

// GetVotersCountAtHash retrieves the number of authorized voters at the specified block.
func (api *API) GetVotersCountAtHash(hash common.Hash) (int, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return 0, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return 0, err
	}
	return len(snap.Voters), nil
}

// IsVoter checks if the address is an authorized voter at the specified block.
func (api *API) IsVoter(address common.Address, number *rpc.BlockNumber) (bool, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	_, okVoter := snap.Voters[address]
	return okVoter, nil
}

// IsVoterAtHash checks if the address is an authorized voter at the specified block.
func (api *API) IsVoterAtHash(address common.Address, hash common.Hash) (bool, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return false, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return false, err
	}
	_, okVoter := snap.Signers[address]
	return okVoter, nil
}

type status struct {
	InturnPercent float64                `json:"inturnPercent"`
	SigningStatus map[common.Address]int `json:"sealerActivity"`
	NumBlocks     uint64                 `json:"numBlocks"`
}

// Status returns the status of the last N blocks,
// - the number of active signers,
// - the number of signers,
// - the percentage of in-turn blocks
func (api *API) Status(numBlocks uint64) (*status, error) {
	var (
		//numBlocks = uint64(64)
		header   = api.chain.CurrentHeader()
		diff     = uint64(0)
		optimals = 0
	)
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	var (
		signers = snap.signers()
		end     = header.Number.Uint64()
		start   = end - numBlocks
	)
	if numBlocks > end {
		start = 1
		numBlocks = end - start
	}
	signStatus := make(map[common.Address]int)
	for _, s := range signers {
		signStatus[s] = 0
	}
	for n := start; n < end; n++ {
		h := api.chain.GetHeaderByNumber(n)
		if h == nil {
			return nil, fmt.Errorf("missing block %d", n)
		}
		// MODIFIED by Jakub Pajek (clique 1-n scale difficulties)
		//if h.Difficulty.Cmp(diffInTurn) == 0 {
		if h.Difficulty.Cmp(big.NewInt(int64(len(snap.Signers)))) == 0 {
			optimals++
		}
		diff += h.Difficulty.Uint64()
		sealer, err := api.clique.Author(h)
		if err != nil {
			return nil, err
		}
		signStatus[sealer]++
	}
	return &status{
		InturnPercent: float64(100*optimals) / float64(numBlocks),
		SigningStatus: signStatus,
		NumBlocks:     numBlocks,
	}, nil
}

type blockNumberOrHashOrRLP struct {
	*rpc.BlockNumberOrHash
	RLP hexutil.Bytes `json:"rlp,omitempty"`
}

func (sb *blockNumberOrHashOrRLP) UnmarshalJSON(data []byte) error {
	bnOrHash := new(rpc.BlockNumberOrHash)
	// Try to unmarshal bNrOrHash
	if err := bnOrHash.UnmarshalJSON(data); err == nil {
		sb.BlockNumberOrHash = bnOrHash
		return nil
	}
	// Try to unmarshal RLP
	var input string
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	blob, err := hexutil.Decode(input)
	if err != nil {
		return err
	}
	sb.RLP = blob
	return nil
}

// GetSigner returns the signer for a specific clique block.
// Can be called with either a blocknumber, blockhash or an rlp encoded blob.
// The RLP encoded blob can either be a block or a header.
func (api *API) GetSigner(rlpOrBlockNr *blockNumberOrHashOrRLP) (common.Address, error) {
	if len(rlpOrBlockNr.RLP) == 0 {
		blockNrOrHash := rlpOrBlockNr.BlockNumberOrHash
		var header *types.Header
		if blockNrOrHash == nil {
			header = api.chain.CurrentHeader()
		} else if hash, ok := blockNrOrHash.Hash(); ok {
			header = api.chain.GetHeaderByHash(hash)
		} else if number, ok := blockNrOrHash.Number(); ok {
			header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
		}
		if header == nil {
			return common.Address{}, fmt.Errorf("missing block %v", blockNrOrHash.String())
		}
		return api.clique.Author(header)
	}
	block := new(types.Block)
	if err := rlp.DecodeBytes(rlpOrBlockNr.RLP, block); err == nil {
		return api.clique.Author(block.Header())
	}
	header := new(types.Header)
	if err := rlp.DecodeBytes(rlpOrBlockNr.RLP, header); err != nil {
		return common.Address{}, err
	}
	return api.clique.Author(header)
}

// VoterAPI is a user facing RPC API to allow controlling the voter
// mechanisms of the proof-of-authority scheme.
type VoterAPI struct {
	chain  consensus.ChainHeaderReader
	clique *Clique
}

type prop struct {
	Block    uint64 `json:"block"`
	Proposal string `json:"proposal"`
}

// Proposals returns the current proposals the voter node tries to uphold and vote on.
func (api *VoterAPI) Proposals() map[common.Address]prop {
	api.clique.lock.RLock()
	defer api.clique.lock.RUnlock()

	proposals := make(map[common.Address]prop)
	for address, proposal := range api.clique.proposals {
		switch proposal.Proposal {
		case proposalVoterVote:
			proposals[address] = prop{
				Proposal: "voter",
				Block:    proposal.Block,
			}
		case proposalSignerVote:
			proposals[address] = prop{
				Proposal: "signer",
				Block:    proposal.Block,
			}
		case proposalDropVote:
			proposals[address] = prop{
				Proposal: "drop",
				Block:    proposal.Block,
			}
		default:
			proposals[address] = prop{
				Proposal: "<invalid>",
				Block:    proposal.Block,
			}
		}
	}
	return proposals
}

// GetValidProposals returns a subset of current proposals that are valid at the specified block.
func (api *VoterAPI) GetValidProposals(number *rpc.BlockNumber) (map[common.Address]prop, error) {
	api.clique.lock.RLock()
	defer api.clique.lock.RUnlock()

	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}

	proposals := make(map[common.Address]prop)
	for address, proposal := range api.clique.proposals {
		// Vote should be valid, and cast after the signer was dropped for inactivity,
		// in order not to automatically vote on re-adding those dropped signers
		if !snap.validVote(address, proposal.Proposal) || snap.Dropped[address] >= proposal.Block {
			continue
		}
		switch proposal.Proposal {
		case proposalVoterVote:
			proposals[address] = prop{
				Proposal: "voter",
				Block:    proposal.Block,
			}
		case proposalSignerVote:
			proposals[address] = prop{
				Proposal: "signer",
				Block:    proposal.Block,
			}
		case proposalDropVote:
			proposals[address] = prop{
				Proposal: "drop",
				Block:    proposal.Block,
			}
		default:
			proposals[address] = prop{
				Proposal: "<invalid>",
				Block:    proposal.Block,
			}
		}
	}
	return proposals, nil
}

// GetValidProposalsAtHash returns a subset of current proposals that are valid at the specified block.
func (api *VoterAPI) GetValidProposalsAtHash(hash common.Hash) (map[common.Address]prop, error) {
	api.clique.lock.RLock()
	defer api.clique.lock.RUnlock()

	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}

	proposals := make(map[common.Address]prop)
	for address, proposal := range api.clique.proposals {
		// Vote should be valid, and cast after the signer was dropped for inactivity,
		// in order not to automatically vote on re-adding those dropped signers
		if !snap.validVote(address, proposal.Proposal) || snap.Dropped[address] >= proposal.Block {
			continue
		}
		switch proposal.Proposal {
		case proposalVoterVote:
			proposals[address] = prop{
				Proposal: "voter",
				Block:    proposal.Block,
			}
		case proposalSignerVote:
			proposals[address] = prop{
				Proposal: "signer",
				Block:    proposal.Block,
			}
		case proposalDropVote:
			proposals[address] = prop{
				Proposal: "drop",
				Block:    proposal.Block,
			}
		default:
			proposals[address] = prop{
				Proposal: "<invalid>",
				Block:    proposal.Block,
			}
		}
	}
	return proposals, nil
}

// Propose injects a new authorization proposal that the voter will attempt to
// push through.
func (api *VoterAPI) Propose(address common.Address, proposal string) error {
	api.clique.lock.Lock()
	defer api.clique.lock.Unlock()

	header := api.chain.CurrentHeader()
	switch proposal {
	case "voter":
		api.clique.proposals[address] = Proposal{
			Proposal: proposalVoterVote,
			Block:    header.Number.Uint64(),
		}
	case "signer":
		api.clique.proposals[address] = Proposal{
			Proposal: proposalSignerVote,
			Block:    header.Number.Uint64(),
		}
	case "drop":
		api.clique.proposals[address] = Proposal{
			Proposal: proposalDropVote,
			Block:    header.Number.Uint64(),
		}
	default:
		return fmt.Errorf("invalid proposal %s", proposal)
	}

	// Asynchronously save proposals to disk (non-blocking send)
	select {
	case api.clique.proposalsCh <- struct{}{}:
	default:
	}

	return nil
}

// Discard drops a currently running proposal, stopping the voter from casting
// further votes (either for or against).
func (api *VoterAPI) Discard(address common.Address) {
	api.clique.lock.Lock()
	defer api.clique.lock.Unlock()

	if _, ok := api.clique.proposals[address]; ok {
		delete(api.clique.proposals, address)

		// Asynchronously save proposals to disk (non-blocking send)
		select {
		case api.clique.proposalsCh <- struct{}{}:
		default:
		}
	}
}
