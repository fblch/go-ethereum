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
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
)

// Vote represents a single vote that an authorized voter made to modify the
// list of permissions.
type Vote struct {
	Voter    common.Address `json:"voter"`    // Authorized voter that cast this vote
	Block    uint64         `json:"block"`    // Block number the vote was cast in (expire old votes)
	Address  common.Address `json:"address"`  // Account being voted on to change its authorization
	Proposal uint64         `json:"proposal"` // Whether to authorize or deauthorize the voted account
}

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
type Tally struct {
	Proposal uint64 `json:"proposal"` // Whether the vote is about authorizing or kicking someone
	Votes    int    `json:"votes"`    // Number of votes until now wanting to pass the proposal
}

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.CliqueConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache        // Cache of recent block signatures to speed up ecrecover

	Number  uint64                      `json:"number"`  // Block number where the snapshot was created
	Hash    common.Hash                 `json:"hash"`    // Block hash where the snapshot was created
	Voters  map[common.Address]struct{} `json:"voters"`  // Set of authorized voters at this moment
	Signers map[common.Address]struct{} `json:"signers"` // Set of authorized signers at this moment
	Recents map[uint64]common.Address   `json:"recents"` // Set of recent signers for spam protections
	Votes   []*Vote                     `json:"votes"`   // List of votes cast in chronological order
	Tally   map[common.Address]Tally    `json:"tally"`   // Current vote tally to avoid recalculating
}

// addressesAscending implements the sort interface to allow sorting a list of addresses
type addressesAscending []common.Address

func (s addressesAscending) Len() int           { return len(s) }
func (s addressesAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s addressesAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.
func newSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, voters []common.Address, signers []common.Address) *Snapshot {
	snap := &Snapshot{
		config:   config,
		sigcache: sigcache,
		Number:   number,
		Hash:     hash,
		Voters:   make(map[common.Address]struct{}),
		Signers:  make(map[common.Address]struct{}),
		Recents:  make(map[uint64]common.Address),
		Tally:    make(map[common.Address]Tally),
	}
	for _, voter := range voters {
		snap.Voters[voter] = struct{}{}
	}
	for _, signer := range signers {
		snap.Signers[signer] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("clique-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("clique-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:   s.config,
		sigcache: s.sigcache,
		Number:   s.Number,
		Hash:     s.Hash,
		Voters:   make(map[common.Address]struct{}),
		Signers:  make(map[common.Address]struct{}),
		Recents:  make(map[uint64]common.Address),
		Votes:    make([]*Vote, len(s.Votes)),
		Tally:    make(map[common.Address]Tally),
	}
	for voter := range s.Voters {
		cpy.Voters[voter] = struct{}{}
	}
	for signer := range s.Signers {
		cpy.Signers[signer] = struct{}{}
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}
	for address, tally := range s.Tally {
		cpy.Tally[address] = tally
	}
	copy(cpy.Votes, s.Votes)

	return cpy
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context (e.g. don't try to add an already authorized signer).
func (s *Snapshot) validVote(address common.Address, proposal uint64) bool {
	_, voter := s.Voters[address]
	_, signer := s.Signers[address]
	switch proposal {
	case proposalVoterVote, proposalSignerVote:
		return (!voter && !signer)
	case proposalDropVote:
		return (voter || signer)
	default:
		return false
	}
}

// cast adds a new vote into the tally.
func (s *Snapshot) cast(address common.Address, proposal uint64) bool {
	// Ensure the vote is meaningful
	if !s.validVote(address, proposal) {
		return false
	}
	// Cast the vote into an existing or new tally
	if old, ok := s.Tally[address]; ok {
		// Don't count votes that go against the existing tally
		// (e.g. tally is proposalVoterVote, vote is proposalSignerVote)
		if old.Proposal != proposal {
			return false
		}
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Proposal: proposal, Votes: 1}
	}
	return true
}

// uncast removes a previously cast vote from the tally.
func (s *Snapshot) uncast(address common.Address, proposal uint64) bool {
	// If there's no tally, it's a dangling vote, just drop
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	if tally.Proposal != proposal {
		return false
	}
	// Otherwise revert the vote
	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address)
	}
	return true
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
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
	snap := s.copy()

	var (
		start  = time.Now()
		logged = time.Now()
	)
	for i, header := range headers {
		// Remove any votes on checkpoint blocks
		number := header.Number.Uint64()
		if number%s.config.Epoch == 0 {
			snap.Votes = nil
			snap.Tally = make(map[common.Address]Tally)
		}
		// Delete the oldest signer from the recent list to allow it signing again
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against signers
		signer, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Signers[signer]; !ok {
			return nil, errUnauthorizedSigner
		}
		for _, recent := range snap.Recents {
			if recent == signer {
				return nil, errRecentlySigned
			}
		}
		snap.Recents[number] = signer

		// If a vote is cast...
		extraBytes := len(header.Extra) - extraVanity - extraSeal
		if number%s.config.Epoch != 0 && extraBytes > 0 {
			// ...check the signer against voters
			if _, ok := snap.Voters[signer]; !ok {
				return nil, errUnauthorizedVoter
			}

			// TODOJAKUB what if vote/vote, vote/drop, drop/vote, etc
			// For every vote...
			voteCount := extraBytes / (common.AddressLength + 1)
			for voteIdx := 0; voteIdx < voteCount; voteIdx++ {
				index := extraVanity + voteIdx*(common.AddressLength+1)
				var address common.Address
				copy(address[:], header.Extra[index:])

				// Header authorized, discard any previous votes from the voter
				for i, vote := range snap.Votes {
					if vote.Voter == signer && vote.Address == address {
						// Uncast the vote from the cached tally
						snap.uncast(vote.Address, vote.Proposal)

						// Uncast the vote from the chronological list
						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
						break // only one vote allowed
					}
				}
				// Tally up the new vote from the voter
				var proposal uint64
				switch header.Extra[index+common.AddressLength] {
				case ExtraVoterVote:
					proposal = proposalVoterVote
				case ExtraSignerVote:
					proposal = proposalSignerVote
				case ExtraDropVote:
					proposal = proposalDropVote
				default:
					return nil, errInvalidVote
				}
				if snap.cast(address, proposal) {
					snap.Votes = append(snap.Votes, &Vote{
						Voter:    signer,
						Block:    number,
						Address:  address,
						Proposal: proposal,
					})
				}
				// If the vote passed, update the list of voters/signers
				if tally := snap.Tally[address]; tally.Votes > len(snap.Voters)/2 {
					if tally.Proposal == proposalVoterVote {
						snap.Voters[address] = struct{}{}
						snap.Signers[address] = struct{}{}
					} else if tally.Proposal == proposalSignerVote {
						snap.Signers[address] = struct{}{}
					} else {
						delete(snap.Voters, address)
						delete(snap.Signers, address)

						// Signer list shrunk, delete any leftover recent caches
						if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
							delete(snap.Recents, number-limit)
						}
						// Discard any previous votes the deauthorized voter cast
						for i := 0; i < len(snap.Votes); i++ {
							if snap.Votes[i].Voter == address {
								// Uncast the vote from the cached tally
								snap.uncast(snap.Votes[i].Address, snap.Votes[i].Proposal)

								// Uncast the vote from the chronological list
								snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)

								i--
							}
						}
					}
					// Discard any previous votes around the just changed account
					for i := 0; i < len(snap.Votes); i++ {
						if snap.Votes[i].Address == address {
							snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
							i--
						}
					}
					delete(snap.Tally, address)
				}
			}
			// If we're taking too much time (ecrecover), notify the user once a while
			if time.Since(logged) > 8*time.Second {
				log.Info("Reconstructing voting history", "processed", i, "total", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
				logged = time.Now()
			}
		}
	}
	if time.Since(start) > 8*time.Second {
		log.Info("Reconstructed voting history", "processed", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// voters retrieves the list of authorized voters in ascending order.
func (s *Snapshot) voters() []common.Address {
	vtrs := make([]common.Address, 0, len(s.Voters))
	for vtr := range s.Voters {
		vtrs = append(vtrs, vtr)
	}
	sort.Sort(addressesAscending(vtrs))
	return vtrs
}

// signers retrieves the list of authorized signers in ascending order.
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	sort.Sort(addressesAscending(sigs))
	return sigs
}

// calcDifficulty returns a diffuculty for a signer at a given block height.
//
// Returned difficulty values are between 0 and SIGNER_COUNT inclusive.
// * The in-turn signer for a given block (marked in pharenthesis below) gets
//   the highest difficulty equal to SIGNER_COUNT.
// * Unauthorized addresses get difficulty 0.
// * The closer a succeeding signer is to the in-turn signer for a given block,
//   the higher the difficulty.
// * The closer a preceding signer is to the in-turn signer for a given block,
//   the lower the difficulty.
//
// Assuming five signers, denoted as s0...s4, the difficulty matrix is as follows:
//
// 		s0	s1	s2	s3	s4
// ---+-------------------
//	0 |	(5)	4	3	2	1
//	1 |	1	(5)	4	3	2
//	2 |	2	1	(5)	4	3
//	3 |	3	2	1	(5)	4
//	4 |	4	3	2	1	(5)
func (s *Snapshot) calcDifficulty(number uint64, signer common.Address) uint64 {
	signers, offset := s.signers(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	if offset == len(signers) {
		// Unauthorized address
		return 0
	}
	if x := offset - int(number%uint64(len(signers))); x >= 0 {
		// In-turn signer, or a succeeding signer
		return uint64(len(signers) - x)
	} else {
		// Preceding signer
		return uint64(-x)
	}
}
