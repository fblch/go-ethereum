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
	"math/big"
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

// Signer is the state of a single authorized signer (and voter) with all the data required
// for calculating block difficulty, penalties, etc.
type Signer struct {
	LastSignedBlock uint64 `json:"lastSignedBlock"` // Last signed block number by the signer
	SignedCount     uint64 `json:"signedCount"`     // Number of blocks signed by the signer since last checked
	StrikeCount     uint64 `json:"strikeCount"`     // Number of strikes the signer has received so far (can increase and decrease)
}

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.CliqueConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache        // Cache of recent block signatures to speed up ecrecover

	Number    uint64                    `json:"number"`    // Block number where the snapshot was created
	Hash      common.Hash               `json:"hash"`      // Block hash where the snapshot was created
	VoterRing bool                      `json:"voterRing"` // Flag to indicate the ring in which blocks are signed (the sealer ring or the voter ring)
	Voters    map[common.Address]uint64 `json:"voters"`    // Set of authorized voters at this moment and their most recently signed block
	Signers   map[common.Address]Signer `json:"signers"`   // Set of authorized signers at this moment and their state
	Dropped   map[common.Address]uint64 `json:"dropped"`   // Set of authorized signers dropped due to inactivity and their drop block number
	Votes     []*Vote                   `json:"votes"`     // List of votes cast in chronological order
	Tally     map[common.Address]Tally  `json:"tally"`     // Current vote tally to avoid recalculating
}

// addressesAscending implements the sort interface to allow sorting a list of addresses
type addressesAscending []common.Address

func (s addressesAscending) Len() int           { return len(s) }
func (s addressesAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s addressesAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the signers most recently signed blocks, so only ever
// use it for the genesis block.
func newGenesisSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, voters []common.Address, signers []common.Address) *Snapshot {
	snap := &Snapshot{
		config:    config,
		sigcache:  sigcache,
		Number:    number,
		Hash:      hash,
		VoterRing: false,
		Voters:    make(map[common.Address]uint64),
		Signers:   make(map[common.Address]Signer),
		Dropped:   make(map[common.Address]uint64),
		Tally:     make(map[common.Address]Tally),
	}
	for _, voter := range voters {
		snap.Voters[voter] = 0
	}
	for _, signer := range signers {
		snap.Signers[signer] = Signer{LastSignedBlock: 0, SignedCount: 0, StrikeCount: 0}
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
		config:    s.config,
		sigcache:  s.sigcache,
		Number:    s.Number,
		Hash:      s.Hash,
		VoterRing: s.VoterRing,
		Voters:    make(map[common.Address]uint64),
		Signers:   make(map[common.Address]Signer),
		Dropped:   make(map[common.Address]uint64),
		Votes:     make([]*Vote, len(s.Votes)),
		Tally:     make(map[common.Address]Tally),
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
		// Resolve the authorization key and check against signers
		signer, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if signed, ok := snap.Signers[signer]; !ok {
			return nil, errUnauthorizedSigner
		} else {
			var (
				_, okVoter = snap.Voters[signer]
				nextNumber uint64
				voterRing  bool
			)
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
		}

		// If in the sealer ring, apply offline penalties (drop inactive signers)
		if !snap.VoterRing {
			// Select the next signer in turn based on the current block number, and check it's activity
			signerCount := uint64(len(snap.Signers))
			address := snap.signers()[number%signerCount]
			if signed, _ := snap.Signers[address]; signed.SignedCount > 0 {
				// The signer signed at least one new block since the last check.
				// Decrease the strike count, zero out the signed block count, save the state.
				if signed.StrikeCount > signed.SignedCount {
					signed.StrikeCount -= signed.SignedCount
				} else {
					signed.StrikeCount = 0
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
				if _, ok := snap.Voters[address]; !ok && signed.StrikeCount > snap.calcStrikeThreshold(signerCount) {
					// Delete the signer from authorized signers
					delete(snap.Signers, address)
					// Add the signer to dropped signers
					snap.Dropped[address] = number
					// Discard any previous votes the deauthorized voter cast
					// (...not needed for non-voters)
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
		}

		// If a vote is cast...
		extraBytes := len(header.Extra) - ExtraVanity - ExtraSeal
		if number%s.config.Epoch != 0 && extraBytes > 0 {
			// ...check the signer against voters
			if _, ok := snap.Voters[signer]; !ok {
				return nil, errUnauthorizedVoter
			}

			// For every vote...
			voteCount := extraBytes / (common.AddressLength + 1)
			for voteIdx := 0; voteIdx < voteCount; voteIdx++ {
				index := ExtraVanity + voteIdx*(common.AddressLength+1)
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
// from the authorized signers. The value of this threshold depends on the current signer count.
//
// The lower the signer count, the higher the threshold value, in order to assure that we do not
// drop the offline signer too soon. The signer must be offline for at least minStrikeThreshold
// seconds before it can be dropped.
// The higher the signer count, the lower the threshold value, however the threshold value will
// not drop below minStrikeThreshold in order to assure that enough samples are gathered before
// we decide to drop the signer.
func (s *Snapshot) calcStrikeThreshold(signerCount uint64) uint64 {
	strikeThreshold := minOfflineTime / s.config.Period / signerCount
	if strikeThreshold < minStrikeCount {
		return minStrikeCount
	}
	return strikeThreshold
}
