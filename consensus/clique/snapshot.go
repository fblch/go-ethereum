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
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"reflect"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
type Tally struct {
	Proposal uint64                    `json:"proposal"` // Whether the voting is about authorizing or kicking someone
	Votes    map[common.Address]uint64 `json:"votes"`    // Mapping of voters that have voted for the proposal to the block number the vote was cast in
}

type sigLRU = lru.Cache[common.Hash, common.Address]

// Signer is the state of a single authorized signer (and voter) with all the data required
// for calculating block difficulty, penalties, etc.
type Signer struct {
	LastSignedBlock uint64 `json:"lastSignedBlock"` // Last signed block number by the signer
	SignedCount     uint64 `json:"signedCount"`     // Number of blocks signed by the signer since last checked
	StrikeCount     uint64 `json:"strikeCount"`     // Number of strikes the signer has received so far (can increase and decrease)
}

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   params.CliqueConfig // Consensus engine parameters to fine tune behavior
	sigcache *sigLRU             // Cache of recent block signatures to speed up ecrecover

	Number    uint64                    `json:"number"`    // Block number where the snapshot was created
	Hash      common.Hash               `json:"hash"`      // Block hash where the snapshot was created
	ConfigIdx uint64                    `json:"configIdx"` // Index of the current config entry inside the config array
	VoterRing bool                      `json:"voterRing"` // Flag to indicate the ring in which blocks are signed (the sealer ring or the voter ring)
	Voting    bool                      `json:"voting"`    // Flag to indicate voting activity (heuristic)
	Voters    map[common.Address]uint64 `json:"voters"`    // Set of authorized voters at this moment and their state (most recently signed block only)
	Signers   map[common.Address]Signer `json:"signers"`   // Set of authorized signers at this moment and their state
	Dropped   map[common.Address]uint64 `json:"dropped"`   // Set of authorized signers dropped due to inactivity and their state (droppd block number only)
	Tally     map[common.Address]Tally  `json:"tally"`     // Current vote tally
}

var (
	uint64Size         = int(reflect.TypeOf(uint64(0)).Size())
	mapKeyHashSize     = int(8) // Map key's hash value size, 8 bytes
	signerStructSize   = int(reflect.TypeOf(Signer{}).Size())
	tallyStructSize    = int(reflect.TypeOf(Tally{}).Size())
	snapshotStructSize = int(reflect.TypeOf(Snapshot{}).Size())
)

// Size implements lru.SizeType, returning the approximate memory used by all internal contents
// of the snapshot. It is used to approximate and limit the memory consumption of snapshot cache.
func (s *Snapshot) Size() int {
	// Assume majority voting rule in which case the number of votes for a given proposal will never exceed half of the number of voters
	tallyVotesAvgSize := (len(s.Voters)/2 + 1) * (mapKeyHashSize + common.AddressLength + uint64Size) // s.Tally.Votes
	return snapshotStructSize +
		(len(s.Voters) * (mapKeyHashSize + common.AddressLength + uint64Size)) + // s.Voters
		(len(s.Signers) * (mapKeyHashSize + common.AddressLength + signerStructSize)) + // s.Signers
		(len(s.Dropped) * (mapKeyHashSize + common.AddressLength + uint64Size)) + // s.Dropped
		(len(s.Tally) * (mapKeyHashSize + common.AddressLength + tallyStructSize + tallyVotesAvgSize)) // s.Tally
}

// EncodeRLP implements rlp.Encoder.
func (s *Snapshot) EncodeRLP(w io.Writer) error {
	version := uint64(1)
	if err := rlp.Encode(w, version); err != nil {
		return err
	}
	if err := rlp.Encode(w, s.Number); err != nil {
		return err
	}
	if err := rlp.Encode(w, s.Hash); err != nil {
		return err
	}
	if err := rlp.Encode(w, s.ConfigIdx); err != nil {
		return err
	}
	if err := rlp.Encode(w, s.VoterRing); err != nil {
		return err
	}
	if err := rlp.Encode(w, s.Voting); err != nil {
		return err
	}
	// Voters
	if err := rlp.Encode(w, uint64(len(s.Voters))); err != nil {
		return err
	}
	for address := range s.Voters {
		if err := rlp.Encode(w, address); err != nil {
			return err
		}
		if err := rlp.Encode(w, s.Voters[address]); err != nil {
			return err
		}
	}
	// Signers
	if err := rlp.Encode(w, uint64(len(s.Signers))); err != nil {
		return err
	}
	for address := range s.Signers {
		if err := rlp.Encode(w, address); err != nil {
			return err
		}
		if err := rlp.Encode(w, s.Signers[address]); err != nil {
			return err
		}
	}
	// Dropped
	if err := rlp.Encode(w, uint64(len(s.Dropped))); err != nil {
		return err
	}
	for address := range s.Dropped {
		if err := rlp.Encode(w, address); err != nil {
			return err
		}
		if err := rlp.Encode(w, s.Dropped[address]); err != nil {
			return err
		}
	}
	// Tally
	if err := rlp.Encode(w, uint64(len(s.Tally))); err != nil {
		return err
	}
	for address, tally := range s.Tally {
		if err := rlp.Encode(w, address); err != nil {
			return err
		}
		if err := rlp.Encode(w, tally.Proposal); err != nil {
			return err
		}
		if err := rlp.Encode(w, uint64(len(tally.Votes))); err != nil {
			return err
		}
		for voter, blockNumber := range tally.Votes {
			if err := rlp.Encode(w, voter); err != nil {
				return err
			}
			if err := rlp.Encode(w, blockNumber); err != nil {
				return err
			}
		}
	}
	return nil
}

// DecodeRLP implements rlp.Decoder.
func (s *Snapshot) DecodeRLP(stream *rlp.Stream) error {
	var version uint64
	if err := stream.Decode(&version); err != nil {
		return err
	}
	if err := stream.Decode(&s.Number); err != nil {
		return err
	}
	if err := stream.Decode(&s.Hash); err != nil {
		return err
	}
	if err := stream.Decode(&s.ConfigIdx); err != nil {
		return err
	}
	if err := stream.Decode(&s.VoterRing); err != nil {
		return err
	}
	if err := stream.Decode(&s.Voting); err != nil {
		return err
	}
	// Voters
	var len uint64
	if err := stream.Decode(&len); err != nil {
		return err
	}
	s.Voters = make(map[common.Address]uint64, len)
	for i := uint64(0); i < len; i++ {
		var address common.Address
		if err := stream.Decode(&address); err != nil {
			return err
		}
		var voter uint64
		if err := stream.Decode(&voter); err != nil {
			return err
		}
		s.Voters[address] = voter
	}
	// Signers
	if err := stream.Decode(&len); err != nil {
		return err
	}
	s.Signers = make(map[common.Address]Signer, len)
	for i := uint64(0); i < len; i++ {
		var address common.Address
		if err := stream.Decode(&address); err != nil {
			return err
		}
		var signer Signer
		if err := stream.Decode(&signer); err != nil {
			return err
		}
		s.Signers[address] = signer
	}
	// Dropped
	if err := stream.Decode(&len); err != nil {
		return err
	}
	s.Dropped = make(map[common.Address]uint64, len)
	for i := uint64(0); i < len; i++ {
		var address common.Address
		if err := stream.Decode(&address); err != nil {
			return err
		}
		var dropped uint64
		if err := stream.Decode(&dropped); err != nil {
			return err
		}
		s.Dropped[address] = dropped
	}
	// Tally
	if err := stream.Decode(&len); err != nil {
		return err
	}
	s.Tally = make(map[common.Address]Tally, len)
	for i := uint64(0); i < len; i++ {
		var address common.Address
		if err := stream.Decode(&address); err != nil {
			return err
		}
		var tally Tally
		if err := stream.Decode(&tally.Proposal); err != nil {
			return err
		}
		var votes uint64
		if err := stream.Decode(&votes); err != nil {
			return err
		}
		tally.Votes = make(map[common.Address]uint64, votes)
		for j := uint64(0); j < votes; j++ {
			var voter common.Address
			if err := stream.Decode(&voter); err != nil {
				return err
			}
			var blockNumber uint64
			if err := stream.Decode(&blockNumber); err != nil {
				return err
			}
			tally.Votes[voter] = blockNumber
		}
		s.Tally[address] = tally
	}
	return nil
}

// addressesAscending implements the sort interface to allow sorting a list of addresses
type addressesAscending []common.Address

func (s addressesAscending) Len() int           { return len(s) }
func (s addressesAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s addressesAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// newGenesisSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the signers most recently signed blocks (nor other custom
// fields added to Signer and Snapshot structs), so only ever use it for the genesis block.
func newGenesisSnapshot(config params.CliqueConfig, sigcache *sigLRU, number uint64, hash common.Hash, voters []common.Address, signers []common.Address, fakeVoterRing bool) *Snapshot {
	// Set the initial config entry index based on the initial sealer count.
	// The last entry's MaxSealerCount is always MaxInt, so the for loop will always break.
	var configIndex uint64
	for i := range config {
		if len(signers) <= config[i].MaxSealerCount {
			configIndex = uint64(i)
			break
		}
	}
	snap := &Snapshot{
		config:    config,
		sigcache:  sigcache,
		Number:    number,
		Hash:      hash,
		ConfigIdx: configIndex,
		VoterRing: fakeVoterRing,
		Voting:    false,
		Voters:    make(map[common.Address]uint64, len(voters)),
		Signers:   make(map[common.Address]Signer, len(signers)),
		Dropped:   make(map[common.Address]uint64),
		Tally:     make(map[common.Address]Tally),
	}
	for i := 0; i < len(voters); i++ {
		snap.Voters[voters[i]] = 0
	}
	for i := 0; i < len(signers); i++ {
		snap.Signers[signers[i]] = Signer{LastSignedBlock: 0, SignedCount: 0, StrikeCount: 0}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config params.CliqueConfig, sigcache *sigLRU, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	// Migrate from JSON encoded snapshot to RLP encoded snapshot
	has, err := db.Has(append(rawdb.CliqueSnapshotJsonPrefix, hash[:]...))
	if err != nil {
		return nil, err
	}
	// Snapshot is RLP encoded
	if !has {
		return loadSnapshotRlp(config, sigcache, db, hash)
	} else
	// Snapshot is JSON encoded
	{
		// Load JSON encoded snapshot
		snap, err := loadSnapshotJson(config, sigcache, db, hash)
		if err != nil {
			return nil, err
		}
		// Migrate to RLP encoded snapshot
		buf := new(bytes.Buffer)
		if err := rlp.Encode(buf, snap); err != nil {
			return nil, err
		}
		if err := db.Put(append(rawdb.CliqueSnapshotRlpPrefix, hash[:]...), buf.Bytes()); err != nil {
			return nil, err
		}
		// Remove JSON encoded snapshot
		if err := db.Delete(append(rawdb.CliqueSnapshotJsonPrefix, hash[:]...)); err != nil {
			return nil, err
		}
		return snap, nil
	}
}

// loadSnapshotJson loads an existing snapshot from the database
// and decodes it using JSON encoding.
func loadSnapshotJson(config params.CliqueConfig, sigcache *sigLRU, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append(rawdb.CliqueSnapshotJsonPrefix, hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	if snap.ConfigIdx >= uint64(len(config)) {
		return nil, errors.New("config index out of range")
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// loadSnapshotRlp loads an existing snapshot from the database
// and decodes it using RLP encoding.
func loadSnapshotRlp(config params.CliqueConfig, sigcache *sigLRU, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append(rawdb.CliqueSnapshotRlpPrefix, hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := rlp.Decode(bytes.NewReader(blob), snap); err != nil {
		return nil, err
	}
	if snap.ConfigIdx >= uint64(len(config)) {
		return nil, errors.New("config index out of range")
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store encodes the snapshot using RLP encoding
// and inserts the encoded snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, s); err != nil {
		return err
	}
	return db.Put(append(rawdb.CliqueSnapshotRlpPrefix, s.Hash[:]...), buf.Bytes())
}

// copy creates a deep copy of the snapshot, though not the config nor the recent block signatures cache.
// Note on performance: BenchmarkCopyV1 and BenchmarkCopyV2 proved that using range with values
// (the below implementation) is slightly faster compared to using range with keys.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:    s.config,
		sigcache:  s.sigcache,
		Number:    s.Number,
		Hash:      s.Hash,
		ConfigIdx: s.ConfigIdx,
		VoterRing: s.VoterRing,
		Voting:    s.Voting,
		Voters:    make(map[common.Address]uint64, len(s.Voters)),
		Signers:   make(map[common.Address]Signer, len(s.Signers)),
		Dropped:   make(map[common.Address]uint64, len(s.Dropped)),
		Tally:     make(map[common.Address]Tally, len(s.Tally)),
	}
	for voter, signed := range s.Voters {
		cpy.Voters[voter] = signed
	}
	for signer, signed := range s.Signers {
		cpy.Signers[signer] = signed
	}
	for signer, dropped := range s.Dropped {
		cpy.Dropped[signer] = dropped
	}
	for address, tally := range s.Tally {
		tallyCpy := Tally{
			Proposal: tally.Proposal,
			Votes:    make(map[common.Address]uint64, len(tally.Votes)),
		}
		for voter, blockNumber := range tally.Votes {
			tallyCpy.Votes[voter] = blockNumber
		}
		cpy.Tally[address] = tallyCpy
	}

	return cpy
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context (e.g. don't try to add an already authorized signer).
func (s *Snapshot) validVote(address common.Address, proposal uint64) bool {
	_, sealer := s.Signers[address]
	switch proposal {
	case proposalVoterVote, proposalSignerVote:
		return !sealer
	case proposalDropVote:
		return sealer
	default:
		return false
	}
}

// alreadyVoted returns whether a given voter has already cast a vote on the specified
// proposal in the given snapshot context (e.g. don't cast the same vote multiple times).
func (s *Snapshot) alreadyVoted(voter common.Address, address common.Address, proposal uint64) bool {
	if tally, okTally := s.Tally[address]; okTally && tally.Proposal == proposal {
		_, okVoter := tally.Votes[voter]
		return okVoter
	}
	return false
}

// cast adds a new vote into the tally.
func (s *Snapshot) cast(voter, address common.Address, proposal, blockNumber uint64) bool {
	// Ensure the vote is meaningful
	if !s.validVote(address, proposal) {
		return false
	}
	// Cast the vote into an existing or new tally
	if tally, ok := s.Tally[address]; ok {
		// Don't count votes that go against the existing tally
		// (e.g. tally is proposalVoterVote, vote is proposalSignerVote)
		if tally.Proposal != proposal {
			return false
		}
		tally.Votes[voter] = blockNumber
	} else {
		tally = Tally{
			Proposal: proposal,
			Votes:    make(map[common.Address]uint64, len(s.Voters)/2+1),
		}
		tally.Votes[voter] = blockNumber
		s.Tally[address] = tally
	}
	return true
}

// uncast removes a previously cast vote from the tally.
func (s *Snapshot) uncast(voter, address common.Address) bool {
	// If there's no tally, it's a dangling vote, just drop
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	if _, okVoter := tally.Votes[voter]; !okVoter {
		return false
	}
	// Otherwise revert the vote
	if len(tally.Votes) > 1 {
		delete(tally.Votes, voter)
	} else {
		delete(s.Tally, address)
	}
	return true
}

// apply creates a new authorization snapshot by applying the given headers to the original one.
// For each applied header, the processing order is as follows:
//   - If necessary, switch between the sealer and the voter ring
//   - For post-PrivateHardFork2 blocks, update the voting activity heuristic
//   - If in the sealer ring, apply offline penalties (drop inactive signers)
//   - If any votes are cast, process the votes
//   - Update the current config entry index based on the final sealer count
//
// Note:
// We assume that headers passed to apply are already verified by the function caller and valid.
// Thanks to this we do not need to repeat all the verification checks already done by Consensus.VerifyHeader,
// in particular: header hashes, times, difficulties, sealer ring votes post-PrivateHardFork2, etc.
func (s *Snapshot) apply(config *params.ChainConfig, headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}

	// Iterate through the headers and create a new snapshot
	var (
		snap   = s.copy()
		start  = time.Now()
		logged = time.Now()
	)
	for i, header := range headers {
		var (
			currConfig     = snap.CurrentConfig()
			number         = header.Number.Uint64()
			checkpoint     = number%currConfig.Epoch == 0
			headerHasVotes bool
			okVoter        bool
		)

		// Remove any votes on checkpoint blocks
		if checkpoint {
			snap.Tally = make(map[common.Address]Tally)
			// For post-PrivateHardFork3 blocks, also clear the dropped signers list, otherwise the list
			// will continue to grow indefinitely.
			if config.IsPrivateHardFork3(header.Number) {
				snap.Dropped = make(map[common.Address]uint64)
			}
		}
		// Resolve the authorization key and check against signers
		signer, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if signed, ok := snap.Signers[signer]; !ok {
			return nil, errUnauthorizedSigner
		} else {
			var (
				nextNumber uint64
				voterRing  bool
			)

			// If any votes are cast, check the signer against voters (only voters can vote)
			headerHasVotes = !checkpoint && len(header.Extra)-params.CliqueExtraVanity-params.CliqueExtraSeal > 0
			_, okVoter = snap.Voters[signer]
			if headerHasVotes && !okVoter {
				return nil, errUnauthorizedVoter
			}
			// Check in which ring we are currently signing blocks in
			if !snap.VoterRing {
				// We are currently signing blocks in the sealer ring.
				// Check the diffuculty to determine if we want to stay
				// in the sealer ring or switch to the voter ring.
				if header.Difficulty.Cmp(snap.maxSealerRingDifficulty()) <= 0 {
					// We want to stay in the sealer ring
					nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
					voterRing = false
				} else if header.Difficulty.Cmp(snap.maxVoterRingDifficulty()) <= 0 {
					// We want to switch to the voter ring
					// Check the signer against voters (only voters can switch to the voter ring)
					if !okVoter {
						return nil, errUnauthorizedVoter
					}
					nextNumber = snap.nextVoterRingSignableBlockNumber(signed.LastSignedBlock)
					voterRing = true
				} else if header.Difficulty.Cmp(snap.maxRingBreakerDifficulty()) <= 0 {
					// We want to preemptively prevent switching to the voter ring
					// Check the signer against voters (only non-voters can prevent the voter ring)
					if okVoter {
						return nil, errUnauthorizedVoter
					}
					nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
					voterRing = false
				} else {
					// Difficulties above maxRingBreakerDifficulty are not allowed
					return nil, errWrongDifficultySealerRing
				}
			} else {
				// We are currently signing blocks in the voter ring.
				// Check the difficulty to determine if we want to stay
				// in the voter ring or return to the sealer ring.
				if header.Difficulty.Cmp(snap.maxSealerRingDifficulty()) <= 0 {
					// Difficulties from the sealer ring range are not allowed in the voter ring
					return nil, errWrongDifficultyVoterRing
				} else if header.Difficulty.Cmp(snap.maxVoterRingDifficulty()) <= 0 {
					// We want to stay in the voter ring
					// Check the signer against voters (only voters can sign blocks in the voter ring)
					if !okVoter {
						return nil, errUnauthorizedVoter
					}
					nextNumber = snap.nextVoterRingSignableBlockNumber(signed.LastSignedBlock)
					voterRing = true
				} else if header.Difficulty.Cmp(snap.maxRingBreakerDifficulty()) <= 0 {
					// We want to return to the sealer ring
					// Check the signer against voters (only non-voters can disband the voter ring)
					if okVoter {
						return nil, errUnauthorizedVoter
					}
					nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
					voterRing = false
				} else {
					// Difficulties above maxRingBreakerDifficulty are not allowed
					return nil, errWrongDifficultyVoterRing
				}
			}
			if signed.LastSignedBlock > 0 {
				// Check against recent signers
				if nextNumber > number {
					return nil, errRecentlySigned
				}
			}
			// Update last signed block numbers
			if okVoter {
				snap.Voters[signer] = number
			}
			signed.LastSignedBlock = number
			signed.SignedCount++
			snap.Signers[signer] = signed
			// Update the ring state
			snap.VoterRing = voterRing
			// For post-PrivateHardFork2 blocks, update the voting activity heuristic
			if config.IsPrivateHardFork2(header.Number) {
				// Assume voting is active if:
				// - current header has votes, or
				// - previous header had votes and current header could not include votes because it is a checkpoint header.
				snap.Voting = headerHasVotes || (snap.Voting && checkpoint)
			}
		}

		// If in the sealer ring, apply offline penalties (drop inactive signers)
		if !snap.VoterRing {
			// Select the next signer in turn based on the current block number, and check it's activity
			address := snap.signers()[number%uint64(len(snap.Signers))]
			if signed := snap.Signers[address]; signed.SignedCount > 0 {
				// The signer signed at least one new block since the last check.
				// Decrease the strike count, zero out the signed block count, save the state.
				if config.IsPrivateHardFork1(header.Number) || signed.StrikeCount <= signed.SignedCount {
					// For post-PrivateHardFork1 blocks, zero out the strike count
					signed.StrikeCount = 0
				} else {
					// For pre-PrivateHardFork1 blocks, decrease the strike count by the signed block count
					signed.StrikeCount -= signed.SignedCount
				}
				signed.SignedCount = 0
				snap.Signers[address] = signed
			} else {
				// The signer did not sign any new blocks since the last check.
				// Increase the strike count and save the state.
				signed.StrikeCount++
				snap.Signers[address] = signed
				// If the strike count exceeded threshold, drop the signer from authorized signers.
				// This does not apply to voters. Voters can only be removed thru explicit voting.
				// Note:
				// A constant strike threshold value should be used during a single header processing.
				// It is ok to call the calcStrikeThreshold here (which accesses the sealer count)
				// without caching the returend value, because we use it only once during the header
				// processing. Even if the sealer count changes due to offline penalties or voting,
				// a new strike threshold value will not be used.
				if _, ok := snap.Voters[address]; !ok && signed.StrikeCount > snap.calcStrikeThreshold() {
					// Delete the signer from authorized signers
					delete(snap.Signers, address)
					// Add the signer to dropped signers
					snap.Dropped[address] = number
					// Discard any previous votes the deauthorized voter cast
					// (...not needed for non-voters)
					// Discard any previous votes around the just changed account
					delete(snap.Tally, address)
				}
			}
		}

		// If any votes are cast, process the votes
		if headerHasVotes {
			// Calculate the effective vote threshold at the beginning of vote processing
			// (Voter count might change later due to passed votes)
			// Effective vote threshold: vote_threshold = voter_count / voting_rule
			var voteThreshold int
			if config.IsPrivateHardFork2(header.Number) {
				voteThreshold = len(snap.Voters) / currConfig.VotingRulePrivHardFork2
			} else {
				voteThreshold = len(snap.Voters) / currConfig.VotingRule
			}
			// Process every vote
			// Note that the protocol forbids casting other votes when voting on dropping self.
			extraBytes := len(header.Extra) - params.CliqueExtraVanity - params.CliqueExtraSeal
			voteCount := extraBytes / (common.AddressLength + 1)
			for voteIdx := 0; voteIdx < voteCount; voteIdx++ {
				index := params.CliqueExtraVanity + voteIdx*(common.AddressLength+1)
				var address common.Address
				copy(address[:], header.Extra[index:])

				// Discard any previous votes from the voter
				snap.uncast(signer, address)
				// Tally up the new vote from the voter
				var proposal uint64
				switch header.Extra[index+common.AddressLength] {
				case params.CliqueExtraVoterVote:
					proposal = proposalVoterVote
				case params.CliqueExtraSignerVote:
					proposal = proposalSignerVote
				case params.CliqueExtraDropVote:
					proposal = proposalDropVote
				default:
					return nil, errInvalidVote
				}
				snap.cast(signer, address, proposal, number)
				// If the vote passed, update the list of voters/signers.
				// Vote passes if the number of proposals exceeds the effective vote threshold.
				if tally := snap.Tally[address]; len(tally.Votes) > voteThreshold {
					if tally.Proposal == proposalVoterVote {
						snap.Voters[address] = 0
						snap.Signers[address] = Signer{LastSignedBlock: 0, SignedCount: 0, StrikeCount: 0}
						// Delete the signer from dropped signers
						delete(snap.Dropped, address)
					} else if tally.Proposal == proposalSignerVote {
						snap.Signers[address] = Signer{LastSignedBlock: 0, SignedCount: 0, StrikeCount: 0}
						// Delete the signer from dropped signers
						delete(snap.Dropped, address)
					} else {
						delete(snap.Voters, address)
						delete(snap.Signers, address)
						// Delete the signer from dropped signers
						// (the case when signer was voted out at the same block it was dropped?)
						delete(snap.Dropped, address)

						// Discard any previous votes the deauthorized voter cast
						for addr := range snap.Tally {
							// Uncast the vote from the cached tally
							snap.uncast(address, addr)
						}
					}
					// Discard any previous votes around the just changed account
					delete(snap.Tally, address)
				}
			}
		}

		// Update the current config entry index based on the final sealer count.
		// The last entry's MaxSealerCount is always MaxInt, so the for loop will always break.
		for i := range snap.config {
			if len(snap.Signers) <= snap.config[i].MaxSealerCount {
				snap.ConfigIdx = uint64(i)
				break
			}
		}

		// If we're taking too much time (ecrecover), notify the user once a while
		if time.Since(logged) > 8*time.Second {
			log.Info("Reconstructing voting history", "processed", i, "total", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	if time.Since(start) > 8*time.Second {
		log.Info("Reconstructed voting history", "processed", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// CurrentConfig implements consensus.PoASnapshot,
// returning the current config entry of a consensus engine.
func (s *Snapshot) CurrentConfig() *params.CliqueConfigEntry {
	return &s.config[s.ConfigIdx]
}

// voters retrieves the list of authorized voters in ascending order.
// Note on performance: BenchmarkAddressMapToArrayV1 and BenchmarkAddressMapToArrayV2 proved that there
// is no significant difference between appending (the below implementation) and assigning using indexes.
func (s *Snapshot) voters() []common.Address {
	vtrs := make([]common.Address, 0, len(s.Voters))
	for vtr := range s.Voters {
		vtrs = append(vtrs, vtr)
	}
	sort.Sort(addressesAscending(vtrs))
	return vtrs
}

// signers retrieves the list of authorized signers in ascending order.
// Note on performance: BenchmarkAddressMapToArrayV1 and BenchmarkAddressMapToArrayV2 proved that there
// is no significant difference between appending (the below implementation) and assigning using indexes.
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	sort.Sort(addressesAscending(sigs))
	return sigs
}

// maxSealerRingDifficulty returns maximum possible difficulty for a signer during the sealer ring.
func (s *Snapshot) maxSealerRingDifficulty() *big.Int {
	return new(big.Int).SetUint64(uint64(len(s.Signers)))
}

// maxVoterRingDifficulty returns maximum possible difficulty for a voter during the voter ring.
func (s *Snapshot) maxVoterRingDifficulty() *big.Int {
	return new(big.Int).SetUint64(uint64(len(s.Signers)) + uint64(len(s.Voters)))
}

// maxRingBreakerDifficulty returns maximum possible difficulty for a signer preventing/disbanding the voter ring.
func (s *Snapshot) maxRingBreakerDifficulty() *big.Int {
	return new(big.Int).SetUint64(uint64(2*len(s.Signers)) + uint64(len(s.Voters)))
}

// calcSealerRingDifficulty returns the difficulty for a signer during the sealer ring, given all
// the signers and their most recently signed block numbers, with 0 meaning 'has not signed yet'.
// With N signers, it will always return values from 1 to N inclusive for an authorized signer,
// 0 otherwise.
//
// Sealer ring difficulty is defined as 1 plus the number of lower priority sealers, with more
// recent sealers having lower priority. If multiple sealers have not yet signed (0), then addresses
// which lexicographically sort later have lower priority.
//
// Note on performance: BenchmarkCalcSealerRingDifficultyV1 and BenchmarkCalcSealerRingDifficultyV2 proved that
// using range with values (the below implementation) is faster compared to using range with keys.
func (s *Snapshot) calcSealerRingDifficulty(signer common.Address) *big.Int {
	difficulty := uint64(1)
	// Note that signer's entry is implicitly skipped by the condition in both loops, so it never counts itself.
	if signerSigned, ok := s.Signers[signer]; !ok {
		return big.NewInt(0)
	} else if signerSigned.LastSignedBlock > 0 {
		for _, signed := range s.Signers {
			if signed.LastSignedBlock > signerSigned.LastSignedBlock {
				difficulty++
			}
		}
	} else {
		// Haven't signed yet. If there are others, fall back to address sort.
		for addr, signed := range s.Signers {
			if signed.LastSignedBlock > 0 || bytes.Compare(addr[:], signer[:]) > 0 {
				difficulty++
			}
		}
	}
	return new(big.Int).SetUint64(difficulty)
}

// calcVoterRingDifficulty returns the difficulty for a voter during the voter ring, given the sealer count,
// all the voters and their most recently signed block numbers, with 0 meaning 'has not signed yet'.
// With N sealers and M voters, it will always return values from N+1 to N+M inclusive for an authorized
// voter, 0 otherwise. Thus, block difficulties in the voter ring for authorized voters are always higher
// than block difficulties in the sealer ring. This is to prioritize the voter ring over the sealer ring.
//
// Voter ring difficulty for voters is defined as a maximum sealer ring difficulty N plus 1 plus the number
// of lower priority voters, with more recent voters having lower priority. If multiple voters have not yet
// signed (0), then addresses which lexicographically sort later have lower priority.
//
// Note on performance: BenchmarkCalcVoterRingDifficultyV1 and BenchmarkCalcVoterRingDifficultyV2 proved that
// using range with values (the below implementation) is faster compared to using range with keys.
func (s *Snapshot) calcVoterRingDifficulty(voter common.Address) *big.Int {
	difficulty := uint64(len(s.Signers)) + 1
	// Note that signer's entry is implicitly skipped by the condition in both loops, so it never counts itself.
	if lastSignedBlock, ok := s.Voters[voter]; !ok {
		return big.NewInt(0)
	} else if lastSignedBlock > 0 {
		for _, signed := range s.Voters {
			if signed > lastSignedBlock {
				difficulty++
			}
		}
	} else {
		// Haven't signed yet. If there are others, fall back to address sort.
		for addr, signed := range s.Voters {
			if signed > 0 || bytes.Compare(addr[:], voter[:]) > 0 {
				difficulty++
			}
		}
	}
	return new(big.Int).SetUint64(difficulty)
}

// calcRingBreakerDifficulty returns the difficulty for a signer preventing/disbanding the voter ring, given
// the voter count, all the sealers and their most recently signed block numbers, with 0 meaning 'has not signed yet'.
// With N sealers and M voters, it will always return values from N+M+1 to N+M+N inclusive for an authorized
// signer, 0 otherwise. Thus, block difficulties in the voter ring for authorized signers are always higher
// than block difficulties for voters in the voter ring. This is to prioritize preventing/disbanding the voter
// ring by signers.
//
// Voter ring difficulty for signers is defined as a maximum voter ring difficulty N+M plus 1 plus the number
// of lower priority sealers, with more recent sealers having lower priority. If multiple sealers have not yet
// signed (0), then addresses which lexicographically sort later have lower priority.
//
// Note on performance: BenchmarkCalcSealerRingDifficultyV1 and BenchmarkCalcSealerRingDifficultyV2 proved that
// using range with values (the below implementation) is faster compared to using range with keys.
func (s *Snapshot) calcRingBreakerDifficulty(signer common.Address) *big.Int {
	difficulty := uint64(len(s.Signers)+len(s.Voters)) + 1
	// Note that signer's entry is implicitly skipped by the condition in both loops, so it never counts itself.
	if signerSigned, ok := s.Signers[signer]; !ok {
		return big.NewInt(0)
	} else if signerSigned.LastSignedBlock > 0 {
		for _, signed := range s.Signers {
			if signed.LastSignedBlock > signerSigned.LastSignedBlock {
				difficulty++
			}
		}
	} else {
		// Haven't signed yet. If there are others, fall back to address sort.
		for addr, signed := range s.Signers {
			if signed.LastSignedBlock > 0 || bytes.Compare(addr[:], signer[:]) > 0 {
				difficulty++
			}
		}
	}
	return new(big.Int).SetUint64(difficulty)
}

// nextSealerRingSignableBlockNumber returns the number of the next block legal for signature
// in the sealer ring by the signer of lastSignedBlockNumber, based on the current number of sealers.
func (s *Snapshot) nextSealerRingSignableBlockNumber(lastSignedBlockNumber uint64) uint64 {
	return lastSignedBlockNumber + uint64(len(s.Signers))/2 + 1
}

// nextVoterRingSignableBlockNumber returns the number of the next block legal for signature
// in the voter ring by the signer of lastSignedBlockNumber, based on the current number of voters.
func (s *Snapshot) nextVoterRingSignableBlockNumber(lastSignedBlockNumber uint64) uint64 {
	return lastSignedBlockNumber + uint64(len(s.Voters))/2 + 1
}

// calcStrikeThreshold returns the strike threshold above which inactive signers are excluded
// from the authorized signers. The value of this threshold depends on the current config and
// the current signer count.
//
// The lower the signer count, the higher the threshold value, in order to assure that we do not
// drop the offline signer too soon. The signer must be offline for at least MinOfflineTime
// seconds before it can be dropped.
// The higher the signer count, the lower the threshold value, however the threshold value will
// not drop below MinStrikeCount in order to assure that enough samples are gathered before
// we decide to drop the signer.
func (s *Snapshot) calcStrikeThreshold() uint64 {
	currConfig := s.CurrentConfig()
	signerCount := uint64(len(s.Signers))
	strikeThreshold := uint64(math.MaxUint64)
	if currConfig.Period > 0 {
		strikeThreshold = currConfig.MinOfflineTime / currConfig.Period / signerCount
	}
	if strikeThreshold < currConfig.MinStrikeCount {
		return currConfig.MinStrikeCount
	}
	return strikeThreshold
}

// calcProposalPurgeThreshold returns the number of blocks after which proposals can be safely
// purged. This value is equal to the effective number of blocks it takes for an authorized
// signers to be dropped due to inactivity by the offline penalties mechanism, but is not greater
// than the ligh immutability threshold.
// Proposal purge threshold:
// purge_threshold = MIN(MAX(min_offline_time / block_period, min_strike_count * signer_count), light_immutability_threshold)
// For TONE Chain Mainnet the threshold changes with the number of joined signers as follows:
// https://www.desmos.com/calculator/gltrtgaoht
func (s *Snapshot) calcProposalPurgeThreshold() uint64 {
	currConfig := s.CurrentConfig()
	signerCount := uint64(len(s.Signers))
	purgeThreshold := uint64(math.MaxUint64)
	if currConfig.Period > 0 {
		purgeThreshold = currConfig.MinOfflineTime / currConfig.Period
	}
	if purgeThreshold < currConfig.MinStrikeCount*signerCount {
		purgeThreshold = currConfig.MinStrikeCount * signerCount
	}
	if purgeThreshold > params.LightImmutabilityThreshold {
		return params.LightImmutabilityThreshold
	}
	return purgeThreshold
}
