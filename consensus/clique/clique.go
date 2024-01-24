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

// Package clique implements the proof-of-authority consensus engine.
package clique

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	lru "github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory

	wiggleTime = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
)

// Clique proof-of-authority protocol constants.
var (
	proposalVoterVote  = uint64(params.CliqueExtraVoterVote)  // Magic proposal number to vote on adding a new voter
	proposalSignerVote = uint64(params.CliqueExtraSignerVote) // Magic proposal number to vote on adding a new signer
	proposalDropVote   = uint64(params.CliqueExtraDropVote)   // Magic proposal number to vote on removing a voter/signer

	nonceNone = hexutil.MustDecode("0x0000000000000000") // Nonce field reserved for future use

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW

	diffInvalid = big.NewInt(0) // Block difficulty must be greater than zero
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errInvalidVotes is returned if a non-checkpoint block contains
	// an invalid list of votes (i.e. non divisible by 20+1 bytes).
	errInvalidVotes = errors.New("invalid votes list in extra-data")

	// errOverflowVotes is returned if a post-PrivateHardFork2 non-checkpoint block contains
	// a too long list of votes  (i.e. the number of votes exceeds params.CliqueMaxVoteCount).
	errOverflowVotes = errors.New("too long votes list in extra-data")

	// errForbiddenVotes is returned if a votes list in extra contains a forbidden combination
	// of votes (i.e. vote on dropping self, as wel as other votes)
	errForbiddenVotes = errors.New("forbidden votes combination in extra-data")

	// errSealerRingVotes is returned if a post-PrivateHardFork2 non-checkpoint block in the sealer
	// ring contains votes (post PrivateHardFork2, voting is allowed only in the voter ring).
	errSealerRingVotes = errors.New("sealer ring block contains votes")

	// errInvalidVote is returned if a vote marker value in extra is something else than the three
	// allowed constants of 0x00, 0x01, 0x02.
	errInvalidVote = errors.New("invalid vote marker in extra-data")

	// errDuplicateVote is returned if a votes list in extra contains more than one
	// vote on any given address.
	errDuplicateVote = errors.New("duplicate vote in extra-data")

	// errInvalidCheckpointPermissions is returned if a checkpoint block contains
	// an invalid list of permissions (i.e. non divisible by 20+1 bytes).
	errInvalidCheckpointPermissions = errors.New("invalid permissions list on checkpoint block")

	// errMismatchingCheckpointPermissions is returned if a checkpoint block contains
	// a list of permissions different than the one the local node calculated.
	errMismatchingCheckpointPermissions = errors.New("mismatching permissions list on checkpoint block")

	// errInvalidBeneficiary is returned if a block's beneficiary is non-zero.
	errInvalidBeneficiary = errors.New("non-zero beneficiary")

	// errInvalidNonce is returned if a block's nonce is non-zero.
	errInvalidNonce = errors.New("non-zero nonce")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is nil, zero or negative.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errWrongDifficultySealerRing is returned if the difficulty of a block in the sealer ring
	// is out of range of allowed difficulties in that ring.
	errWrongDifficultySealerRing = errors.New("out of range difficulty for the sealer ring")

	// errWrongDifficultyVoterRing is returned if the difficulty of a block in the voter ring
	// is out of range of allowed difficulties in that ring.
	errWrongDifficultyVoterRing = errors.New("out of range difficulty for the voter ring")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if a permissions list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedVoter is returned if a vote is cast by a non-authorized entity.
	errUnauthorizedVoter = errors.New("unauthorized voter")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")
)

// SignerFn hashes and signs the data to be signed by a backing account.
type SignerFn func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *sigLRU) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address, nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < params.CliqueExtraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-params.CliqueExtraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// Proposal represents a single proposal that an authorized voter will vote on
// to modify the list of permissions.
type Proposal struct {
	Block    uint64 `json:"block"`    // Block number the proposal came in (expire old proposals)
	Proposal uint64 `json:"proposal"` // Whether to authorize or deauthorize the voted account
}

// Clique is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type Clique struct {
	config params.CliqueConfig // Consensus engine configuration parameters
	db     ethdb.Database      // Database to store and retrieve snapshot checkpoints

	recents    *lru.Cache[common.Hash, *Snapshot] // Snapshots for recent block to speed up reorgs
	signatures *sigLRU                            // Signatures of recent blocks to speed up mining

	proposals map[common.Address]Proposal // Current list of proposals we are pushing

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the signer and proposals fields

	// The fields below are for testing only
	fakeDiff      bool // Skip difficulty verifications
	fakeRewards   bool // Skip accumulating the block rewards
	fakeVoterRing bool // Set the ring for the genesis block (the sealer ring or the voter ring)
}

// loadProposals loads existing proposals from the database.
func loadProposals(db ethdb.Database) (map[common.Address]Proposal, error) {
	blob, err := db.Get([]byte("clique-proposals"))
	if err != nil {
		return nil, err
	}
	var proposals map[common.Address]Proposal
	if err := json.Unmarshal(blob, &proposals); err != nil {
		return nil, err
	}
	return proposals, nil
}

// storeProposals inserts existing proposals into the database.
// (assumes that the lock mutex is locked!)
func (c *Clique) storeProposals() error {
	blob, err := json.Marshal(c.proposals)
	if err != nil {
		return err
	}
	return c.db.Put([]byte("clique-proposals"), blob)
}

// New creates a Clique proof-of-authority consensus engine with the initial
// permissions set to the ones provided by the user.
func New(config params.CliqueConfig, db ethdb.Database) *Clique {
	if len(config) <= 0 {
		panic("empty clique config")
	}
	// Set any missing consensus parameters to their defaults
	conf := append([]params.CliqueConfigEntry{}, config...)
	if conf[0].MaxSealerCount == 0 {
		conf[0].MaxSealerCount = math.MaxInt
	}
	if conf[0].Epoch == 0 {
		conf[0].Epoch = params.CliqueEpoch
	}
	if conf[0].BlockReward == nil {
		conf[0].BlockReward = params.CliqueBlockReward
	}
	if conf[0].VotingRule < 1 {
		conf[0].VotingRule = params.CliqueVotingRule
	} else if conf[0].VotingRule == 1 {
		conf[0].VotingRule = math.MaxInt
	}
	if conf[0].VotingRulePrivHardFork2 < 1 {
		conf[0].VotingRulePrivHardFork2 = params.CliqueVotingRule
	} else if conf[0].VotingRulePrivHardFork2 == 1 {
		conf[0].VotingRulePrivHardFork2 = math.MaxInt
	}
	if conf[0].MinStallPeriod == 0 {
		conf[0].MinStallPeriod = params.CliqueMinStallPeriod
	}
	if conf[0].MinOfflineTime == 0 {
		conf[0].MinOfflineTime = params.CliqueMinOfflineTime
	}
	if conf[0].MinStrikeCount == 0 {
		conf[0].MinStrikeCount = params.CliqueMinStrikeCount
	}
	for i := 1; i < len(conf); i++ {
		if conf[i].MaxSealerCount == 0 {
			conf[i].MaxSealerCount = math.MaxInt
		}
		if conf[i].MaxSealerCount <= conf[i-1].MaxSealerCount {
			panic("maximum sealer count in clique config must be strictly increasing")
		}
		if conf[i].Epoch == 0 {
			conf[i].Epoch = conf[i-1].Epoch
		}
		if conf[i].Epoch != conf[i-1].Epoch {
			panic("variable epoch not supported yet")
		}
		if conf[i].BlockReward == nil {
			conf[i].BlockReward = conf[i-1].BlockReward
		}
		if conf[i].VotingRule < 1 {
			conf[i].VotingRule = conf[i-1].VotingRule
		} else if conf[i].VotingRule == 1 {
			conf[i].VotingRule = math.MaxInt
		}
		if conf[i].VotingRulePrivHardFork2 < 1 {
			conf[i].VotingRulePrivHardFork2 = conf[i-1].VotingRulePrivHardFork2
		} else if conf[i].VotingRulePrivHardFork2 == 1 {
			conf[i].VotingRulePrivHardFork2 = math.MaxInt
		}
		if conf[i].MinStallPeriod == 0 {
			conf[i].MinStallPeriod = conf[i-1].MinStallPeriod
		}
		if conf[i].MinOfflineTime == 0 {
			conf[i].MinOfflineTime = conf[i-1].MinOfflineTime
		}
		if conf[i].MinStrikeCount == 0 {
			conf[i].MinStrikeCount = conf[i-1].MinStrikeCount
		}
	}
	if conf[len(conf)-1].MaxSealerCount != math.MaxInt {
		panic("last clique config entry's MaxSealerCount must be set to MaxInt")
	}

	// Allocate the snapshot caches and create the engine
	recents := lru.NewCache[common.Hash, *Snapshot](inmemorySnapshots)
	signatures := lru.NewCache[common.Hash, common.Address](inmemorySignatures)

	// If an on-disk proposals can be found, use that
	proposals, err := loadProposals(db)
	if err != nil {
		log.Warn("Failed to load clique proposals from disk", "err", err)
		proposals = make(map[common.Address]Proposal)
	} else {
		log.Trace("Loaded clique proposals from disk")
	}

	return &Clique{
		config:     conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
		proposals:  proposals,
	}
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (c *Clique) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, c.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *Clique) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return c.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *Clique) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules. The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *Clique) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < params.CliqueExtraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < params.CliqueExtraVanity+params.CliqueExtraSeal {
		return errMissingSignature
	}
	// Beneficiary must be zero
	if header.Coinbase != (common.Address{}) {
		return errInvalidBeneficiary
	}
	// Nonce must be zero
	if !bytes.Equal(header.Nonce[:], nonceNone) {
		return errInvalidNonce
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || header.Difficulty.Cmp(diffInvalid) <= 0 {
			return errInvalidDifficulty
		}
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	if chain.Config().IsShanghai(header.Time) {
		return fmt.Errorf("clique does not support shanghai fork")
	}
	// Verify the non-existence of withdrawalsHash.
	if header.WithdrawalsHash != nil {
		return fmt.Errorf("invalid withdrawalsHash: have %x, expected nil", header.WithdrawalsHash)
	}
	if chain.Config().IsCancun(header.Time) {
		return fmt.Errorf("clique does not support cancun fork")
	}
	// Verify the non-existence of excessDataGas
	if header.ExcessDataGas != nil {
		return fmt.Errorf("invalid excessDataGas: have %d, expected nil", header.ExcessDataGas)
	}
	// All basic checks passed, verify cascading fields
	return c.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (c *Clique) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Assemble the snapshot needed to access the current config
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	currConfig := snap.CurrentConfig()
	// Ensure that the block's timestamp isn't too close to its parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+currConfig.Period > header.Time {
		return errInvalidTimestamp
	}
	// Verify BaseFee and GasLimit
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, want <nil>", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}
	// Ensure that the extra-data contains permissions list on checkpoint, optional votes list otherwise
	checkpoint := number%currConfig.Epoch == 0
	extraBytes := len(header.Extra) - params.CliqueExtraVanity - params.CliqueExtraSeal
	if checkpoint && extraBytes%(common.AddressLength+1) != 0 {
		return errInvalidCheckpointPermissions
	}
	if !checkpoint {
		if extraBytes%(common.AddressLength+1) != 0 {
			return errInvalidVotes
		}
		if chain.Config().IsPrivateHardFork2(header.Number) {
			// For post-PrivateHardFork2 blocks, verify that the number of votes
			// included in the header does not exceed the maximum allowance.
			if voteCount := extraBytes / (common.AddressLength + 1); voteCount > params.CliqueMaxVoteCount {
				return errOverflowVotes
			}
		}
	}
	// If the block is a checkpoint block, verify the permissions list
	if checkpoint {
		permissions := make([]byte, len(snap.Signers)*(common.AddressLength+1))
		authorizedSigners := snap.signers()
		for i := 0; i < len(authorizedSigners); i++ {
			index := i * (common.AddressLength + 1)
			copy(permissions[index:], authorizedSigners[i][:])
			if _, ok := snap.Voters[authorizedSigners[i]]; ok {
				permissions[index+common.AddressLength] = params.CliqueExtraVoterMarker
			} else {
				permissions[index+common.AddressLength] = params.CliqueExtraSignerMarker
			}
		}
		extraSuffix := len(header.Extra) - params.CliqueExtraSeal
		if !bytes.Equal(header.Extra[params.CliqueExtraVanity:extraSuffix], permissions) {
			return errMismatchingCheckpointPermissions
		}
	}
	// All basic checks passed, verify the seal and return
	return c.verifySeal(chain, snap, header, parent)
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (c *Clique) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := c.recents.Get(hash); ok {
			snap = s
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(c.config, c.signatures, c.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at the genesis, snapshot the initial state. Alternatively if we're
		// at a checkpoint block without a parent (light client CHT), or we have piled
		// up more headers than allowed to be reorged (chain reinit from a freezer),
		// consider the checkpoint trusted and snapshot it.
		// MEMO by Jakub Pajek (clique config: variable period)
		// How to handle variable epoch changing with the number of sealers?
		// MODIFIED by Jakub Pajek (clique bug: incomplete state in checkpoint)
		//
		// Problem:
		// - Risk of consensus split due to incomplete snapshot state being stored in checkpoint blocks.
		//
		// Background:
		// - When new state was added to the snapshot (Voter ring, Offline penalties, etc.),
		//   required logic to save it to checkpoint blocks was omitted.
		// - Geth can recreate a snapshot from either the genesis block or one of the checkpoint blocks.
		// - If a snapshot is recreated from one of the checkpoint block, it will be incomplete,
		//   thus the state will diverge eventually causing a consensus split.
		//
		// Solutions:
		// - Hotfix:
		//   - Disable the logic to recreate snapshots from checkpoint blocks.
		//     - This will drop the light sync support (which is already corrupt due to incomplete checkpoints)
		//     - Might also have inpact on performance when reinitializing chain from a freezer?
		// - Bugfix:
		//   - Fix the logic around generating checkpoint blocks (requires a hard fork to deploy)
		//
		// References:
		// https://github.com/fblch/go-ethereum/commit/9f036647e4b3e7c3aa8941dc239f85326a5e5ecd
		// https://github.com/fblch/go-ethereum/commit/bcfb7f58b93e6fb5f3da0000672adee80fd6a485
		// https://github.com/fblch/go-ethereum/commit/536b3b416c6ff53ea11a0d29dcc351a6d7919901
		// https://github.com/fblch/go-ethereum/commit/6eef141aef618afa6bfad885b544f25b68f77cc2
		//
		//if number == 0 || (number%c.config[0].Epoch == 0 && (len(headers) > params.FullImmutabilityThreshold || chain.GetHeaderByNumber(number-1) == nil)) {
		if number == 0 {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()

				signers := make([]common.Address, (len(checkpoint.Extra)-params.CliqueExtraVanity-params.CliqueExtraSeal)/(common.AddressLength+1))
				voters := make([]common.Address, 0, len(signers))
				for i := 0; i < len(signers); i++ {
					index := params.CliqueExtraVanity + i*(common.AddressLength+1)
					copy(signers[i][:], checkpoint.Extra[index:])
					if checkpoint.Extra[index+common.AddressLength] == params.CliqueExtraVoterMarker {
						voters = append(voters, signers[i])
					}
				}
				snap = newGenesisSnapshot(c.config, c.signatures, number, hash, voters, signers, c.fakeVoterRing)
				if err := snap.store(c.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(chain.Config(), headers)
	if err != nil {
		return nil, err
	}
	c.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(c.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *Clique) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements.
func (c *Clique) verifySeal(chain consensus.ChainHeaderReader, snap *Snapshot, header *types.Header, parent *types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Get the current config
	var (
		currConfig     = snap.CurrentConfig()
		headerHasVotes bool
		okVoter        bool
	)

	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, c.signatures)
	if err != nil {
		return err
	}
	if signed, ok := snap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	} else {
		var (
			nextNumber uint64
			nextDiff   *big.Int
		)

		// If any votes are cast, check the signer against voters (only voters can vote)
		headerHasVotes = number%currConfig.Epoch != 0 && len(header.Extra)-params.CliqueExtraVanity-params.CliqueExtraSeal > 0
		_, okVoter = snap.Voters[signer]
		if headerHasVotes && !okVoter {
			return errUnauthorizedVoter
		}
		// Check in which ring we are currently signing blocks in
		if !snap.VoterRing {
			// We are currently signing blocks in the sealer ring.
			// Check the diffuculty to determine if we want to stay
			// in the sealer ring or switch to the voter ring.
			if header.Difficulty.Cmp(snap.maxSealerRingDifficulty()) <= 0 {
				// We want to stay in the sealer ring
				// For post-PrivateHardFork2 blocks, check if no votes are cast
				// (voting is no longer allowed in the sealer ring)
				if chain.Config().IsPrivateHardFork2(header.Number) && headerHasVotes {
					return errSealerRingVotes
				}
				// Calculate the next signable block number and difficulty for the signer
				nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
				nextDiff = snap.calcSealerRingDifficulty(signer)
			} else if header.Difficulty.Cmp(snap.maxVoterRingDifficulty()) <= 0 {
				// We want to switch to the voter ring
				// Check the signer against voters (only voters can switch to the voter ring)
				if !okVoter {
					return errUnauthorizedVoter
				}
				if chain.Config().IsPrivateHardFork2(header.Number) {
					// For post-PrivateHardFork2 blocks, the switch is allowed if:
					// - votes are cast, or
					// - a sufficiently long stall in block creation occurred
					if !headerHasVotes &&
						(currConfig.Period == 0 || header.Time < parent.Time+(currConfig.MinStallPeriod*currConfig.Period)) {
						return errWrongDifficultySealerRing
					}
				} else {
					// For pre-PrivateHardFork2 blocks, the switch is allowed if:
					// - a sufficiently long stall in block creation occurred
					if currConfig.Period == 0 || header.Time < parent.Time+(currConfig.MinStallPeriod*currConfig.Period) {
						return errWrongDifficultySealerRing
					}
				}
				// Calculate the next signable block number and difficulty for the signer
				nextNumber = snap.nextVoterRingSignableBlockNumber(signed.LastSignedBlock)
				nextDiff = snap.calcVoterRingDifficulty(signer)
			} else if header.Difficulty.Cmp(snap.maxRingBreakerDifficulty()) <= 0 {
				// We want to preemptively prevent switching to the voter ring
				// Check the signer against voters (only non-voters can prevent the voter ring)
				if okVoter {
					return errUnauthorizedVoter
				}
				// Check if a sufficiently long stall in block creation occurred
				if currConfig.Period == 0 || header.Time < parent.Time+(currConfig.MinStallPeriod*currConfig.Period) {
					return errWrongDifficultySealerRing
				}
				// Calculate the next signable block number and difficulty for the signer
				nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
				nextDiff = snap.calcRingBreakerDifficulty(signer)
			} else {
				// Difficulties above maxRingBreakerDifficulty are not allowed
				return errWrongDifficultySealerRing
			}
		} else {
			// We are currently signing blocks in the voter ring.
			// Check the difficulty to determine if we want to stay
			// in the voter ring or return to the sealer ring.
			if header.Difficulty.Cmp(snap.maxSealerRingDifficulty()) <= 0 {
				// Difficulties from the sealer ring range are not allowed in the voter ring
				return errWrongDifficultyVoterRing
			} else if header.Difficulty.Cmp(snap.maxVoterRingDifficulty()) <= 0 {
				// We want to stay in the voter ring
				// Check the signer against voters (only voters can sign blocks in the voter ring)
				if !okVoter {
					return errUnauthorizedVoter
				}
				// Calculate the next signable block number and difficulty for the signer
				nextNumber = snap.nextVoterRingSignableBlockNumber(signed.LastSignedBlock)
				nextDiff = snap.calcVoterRingDifficulty(signer)
			} else if header.Difficulty.Cmp(snap.maxRingBreakerDifficulty()) <= 0 {
				// We want to return to the sealer ring
				// Check the signer against voters (only non-voters can disband the voter ring)
				if okVoter {
					return errUnauthorizedVoter
				}
				if chain.Config().IsPrivateHardFork2(header.Number) {
					// For post-PrivateHardFork2 blocks, the switch is allowed if:
					// - voting has not started, or
					// - a sufficiently long stall in block creation occurred
					if snap.Voting &&
						(currConfig.Period == 0 || header.Time < parent.Time+(currConfig.MinStallPeriod*currConfig.Period)) {
						return errWrongDifficultyVoterRing
					}
				} else {
					// For pre-PrivateHardFork2 blocks, the switch is allowed if:
					// - always
				}
				// Calculate the next signable block number and difficulty for the signer
				nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
				nextDiff = snap.calcRingBreakerDifficulty(signer)
			} else {
				// Difficulties above maxRingBreakerDifficulty are not allowed
				return errWrongDifficultyVoterRing
			}
		}
		if signed.LastSignedBlock > 0 {
			// Check against recent signers
			if nextNumber > number {
				return errRecentlySigned
			}
		}
		// Ensure that the difficulty corresponds to the turn-ness of the signer
		if !c.fakeDiff {
			if header.Difficulty.Cmp(nextDiff) != 0 {
				return errWrongDifficulty
			}
		}
	}
	// If any votes are cast, verify the votes
	if headerHasVotes {
		// Verify the votes list
		extraBytes := len(header.Extra) - params.CliqueExtraVanity - params.CliqueExtraSeal
		votesCast := make(map[common.Address]struct{})
		voteCount := extraBytes / (common.AddressLength + 1)
		for voteIdx := 0; voteIdx < voteCount; voteIdx++ {
			index := params.CliqueExtraVanity + voteIdx*(common.AddressLength+1)
			var address common.Address
			copy(address[:], header.Extra[index:])

			// Only one vote for any given address allowed
			if _, ok := votesCast[address]; ok {
				return errDuplicateVote
			}
			votesCast[address] = struct{}{}
			// Check whether the vote is valid
			index += common.AddressLength
			if header.Extra[index] != params.CliqueExtraVoterVote &&
				header.Extra[index] != params.CliqueExtraSignerVote &&
				header.Extra[index] != params.CliqueExtraDropVote {
				return errInvalidVote
			}
			// If voting on dropping self, no other votes are allowed
			if address == signer &&
				header.Extra[index] == params.CliqueExtraDropVote &&
				voteCount > 1 {
				return errForbiddenVotes
			}
		}
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *Clique) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()
	// Assemble the snapshot needed to access the current config
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	currConfig := snap.CurrentConfig()

	// Check if we are an authorized voter, for future use...
	c.lock.RLock()
	signer := c.signer
	c.lock.RUnlock()
	_, okVoter := snap.Voters[signer]

	// Ensure the extra data has all its components
	if len(header.Extra) < params.CliqueExtraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, params.CliqueExtraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:params.CliqueExtraVanity]

	// If the block is a checkpoint, include permissions list.
	// Otherwise, if the signer is a voter, cast all valid votes.
	if number%currConfig.Epoch == 0 {
		authorizedSigners := snap.signers()
		for i := 0; i < len(authorizedSigners); i++ {
			header.Extra = append(header.Extra, authorizedSigners[i][:]...)
			if _, ok := snap.Voters[authorizedSigners[i]]; ok {
				header.Extra = append(header.Extra, params.CliqueExtraVoterMarker)
			} else {
				header.Extra = append(header.Extra, params.CliqueExtraSignerMarker)
			}
		}
	} else if okVoter {
		// Write lock needed for proposal purging
		c.lock.Lock() //c.lock.RLock()

		// Gather all the proposals that make sense voting on
		// On that occasion, also purge already passed and old proposals
		addresses, purged, dropSelf := make([]common.Address, 0, len(c.proposals)), 0, false
		for address, proposal := range c.proposals {
			// Proposal should be valid, and created after the signer was dropped for inactivity,
			// in order not to automatically vote on re-adding those dropped signers
			if snap.validVote(address, proposal.Proposal) && snap.Dropped[address] < proposal.Block {
				if address == signer && proposal.Proposal == proposalDropVote {
					dropSelf = true
				}
				addresses = append(addresses, address)
			} else if number > proposal.Block && number-proposal.Block > params.CliqueEpoch {
				delete(c.proposals, address)
				purged++
			}
		}
		// If there are any purged proposals, save to disk
		if purged > 0 {
			log.Trace("Purged old clique proposals", "total", len(c.proposals), "purged", purged)
			if err := c.storeProposals(); err != nil {
				log.Error("Failed to store clique proposals to disk", "err", err)
			} else {
				log.Trace("Stored clique proposals disk")
			}
		}
		// If there's pending proposals, cast votes on them
		// Note that the protocol forbids casting other votes when voting on dropping self.
		if !dropSelf {
			// For pre-PrivateHardFork2 blocks, and post-PrivateHardFork2 blocks when the number of pending
			// proposals does not exceed the maximum vote allowance, cast votes on all pending proposals
			proposalCount := len(addresses)
			if chain.Config().IsPrivateHardFork2(header.Number) && proposalCount > params.CliqueMaxVoteCount {
				// For post-PrivateHardFork2 blocks, when the number of pending proposals exceeds the maximum vote allowance,
				// cast the maximum allowed number of votes on proposals randomly selected from all pending proposals.
				// Note: Since go1.20, the math/rand package automatically seeds the global random number generator
				// with a random value, and the top-level Seed function has been deprecated: https://tip.golang.org/doc/go1.20
				rand.Shuffle(len(addresses), func(i, j int) { addresses[i], addresses[j] = addresses[j], addresses[i] })
				proposalCount = params.CliqueMaxVoteCount
			}
			for i := 0; i < proposalCount; i++ {
				header.Extra = append(header.Extra, addresses[i][:]...)
				switch c.proposals[addresses[i]].Proposal {
				case proposalVoterVote:
					header.Extra = append(header.Extra, params.CliqueExtraVoterVote)
				case proposalSignerVote:
					header.Extra = append(header.Extra, params.CliqueExtraSignerVote)
				case proposalDropVote:
					header.Extra = append(header.Extra, params.CliqueExtraDropVote)
				}
			}
		} else {
			header.Extra = append(header.Extra, signer[:]...)
			header.Extra = append(header.Extra, params.CliqueExtraDropVote)
		}
		// Write lock needed for proposal purging
		c.lock.Unlock() //c.lock.RUnlock()
	}
	header.Extra = append(header.Extra, make([]byte, params.CliqueExtraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = parent.Time + currConfig.Period
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}

	// Check in which ring we are currently signing blocks in
	if !snap.VoterRing {
		// We are currently signing blocks in the sealer ring.
		if okVoter {
			// If we are a voter, switch to the voter ring if:
			// - we are post-PrivateHardFork2 and want to cast votes, or
			// - a sufficiently long stall in block creation occurred
			// Continue in the sealer ring otherwise.
			headerHasVotes := number%currConfig.Epoch != 0 && len(header.Extra)-params.CliqueExtraVanity-params.CliqueExtraSeal > 0
			if (chain.Config().IsPrivateHardFork2(header.Number) && headerHasVotes) ||
				(currConfig.Period > 0 && header.Time >= parent.Time+(currConfig.MinStallPeriod*currConfig.Period)) {
				// Set the correct difficulty for the voter ring
				header.Difficulty = snap.calcVoterRingDifficulty(signer)
			} else {
				// Set the correct difficulty for the sealer ring
				header.Difficulty = snap.calcSealerRingDifficulty(signer)
			}
		} else {
			// If we are not a voter, preemptively prevent switching to the voter ring if:
			// - a sufficiently long stall in block creation occurred
			// Continue in the sealer ring otherwise.
			if currConfig.Period > 0 && header.Time >= parent.Time+(currConfig.MinStallPeriod*currConfig.Period) {
				// Set the correct difficulty for preventing switching to the voter ring
				header.Difficulty = snap.calcRingBreakerDifficulty(signer)
			} else {
				// Set the correct difficulty for the sealer ring
				header.Difficulty = snap.calcSealerRingDifficulty(signer)
			}
		}
	} else {
		// We are currently signing blocks in the voter ring.
		if okVoter {
			// If we are a voter, continue in the voter ring.
			// Set the correct difficulty for the voter ring
			header.Difficulty = snap.calcVoterRingDifficulty(signer)
		} else {
			// If we are not a voter, ...
			if chain.Config().IsPrivateHardFork2(header.Number) {
				// For post-PrivateHardFork2 blocks, try returning to the sealer ring by disbanding the voter ring if:
				// - voting has not started, or
				// - a sufficiently long stall in block creation occurred
				// Withold sealing the block otherwise.
				if !snap.Voting ||
					(currConfig.Period > 0 && header.Time >= parent.Time+(currConfig.MinStallPeriod*currConfig.Period)) {
					// Set the correct difficulty for disbanding the voter ring
					header.Difficulty = snap.calcRingBreakerDifficulty(signer)
				} else {
					// Set the invalid difficulty to withold sealing the block
					header.Difficulty = diffInvalid
				}
			} else {
				// For pre-PrivateHardFork2 blocks, try returning to the sealer ring by disbanding the voter ring if:
				// - always
				// Set the correct difficulty for disbanding the voter ring
				header.Difficulty = snap.calcRingBreakerDifficulty(signer)
			}
		}
	}
	return nil
}

// Finalize implements consensus.Engine, accumulating the block rewards.
// MODIFIED by Jakub Pajek (clique static block rewards)
// MODIFIED by Jakub Pajek (clique config: variable period)
// func (c *Clique) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) {
func (c *Clique) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal, dummy bool) error {
	if !c.fakeRewards {
		// Resolve the authorization key
		signer, err := ecrecover(header, c.signatures)
		if err != nil {
			return err
		}
		// Accumulate any block rewards (excluding uncle rewards).
		if signer != (common.Address{}) {
			if err := c.accumulateRewards(chain, state, header, uncles, signer); err != nil {
				return err
			}
		}
	}
	return nil
}

// FinalizeAndAssemble implements consensus.Engine, accumulating the block rewards,
// setting the final state and assembling the block.
// MODIFIED by Jakub Pajek (clique static block rewards)
// func (c *Clique) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
func (c *Clique) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal, dummy bool) (*types.Block, error) {
	if len(withdrawals) > 0 {
		return nil, errors.New("clique does not support withdrawals")
	}

	// Finalize block
	//c.Finalize(chain, header, state, txs, uncles, nil)
	if !c.fakeRewards {
		c.lock.RLock()
		signer := c.signer
		c.lock.RUnlock()
		if signer == (common.Address{}) {
			return nil, errors.New("signer not set")
		}
		// Accumulate any block rewards (excluding uncle rewards)
		if signer != (common.Address{}) {
			if err := c.accumulateRewards(chain, state, header, uncles, signer); err != nil {
				return nil, err
			}
		}
	}

	// Assign the final state root to header.
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Assemble and return the final block for sealing.
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// AccumulateRewards credits the signer of the given block with the mining
// reward. The total reward consists of the static block reward only.
func (c *Clique) accumulateRewards(chain consensus.ChainHeaderReader, state *state.StateDB, header *types.Header, uncles []*types.Header, signer common.Address) error {
	number := header.Number.Uint64()

	// Assemble the snapshot needed to access the current config
	var currConfig *params.CliqueConfigEntry
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		// MEMO by Jakub Pajek (clique config: variable period)
		// Are we running tests using a chain header reader stub?
		if !chain.IsStub() {
			return err
		}
		currConfig = &c.config[0]
	} else {
		currConfig = snap.CurrentConfig()
	}

	// Accumulate the rewards for the miner
	if currConfig.BlockReward.Cmp(big.NewInt(0)) > 0 {
		state.AddBalance(signer, currConfig.BlockReward)
	}
	return nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *Clique) Authorize(signer common.Address, signFn SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *Clique) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For post-PrivateHardFork2 blocks, withold sealing blocks if the difficulty is set to an invalid value.
	// This happens when a non-voter can't try to switch the network back to the sealer ring because:
	// - voting has started, and
	// - not a sufficiently long stall in block creation occurred
	if chain.Config().IsPrivateHardFork2(header.Number) && header.Difficulty.Cmp(diffInvalid) == 0 {
		return errors.New("sealing paused while waiting for voting to finish")
	}
	// Assemble the snapshot needed to access the current config
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	currConfig := snap.CurrentConfig()
	// MODIFIED by Jakub Pajek (clique empty blocks)
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if currConfig.Period == 0 && len(block.Transactions()) == 0 {
		// MODIFIED by Jakub Pajek (clique empty blocks, clique voter ring)
		// For any-period chains, refuse to seal empty blocks, unless disbanding the voter ring
		//if len(block.Transactions()) == 0 && !(snap.VoterRing && header.Difficulty.Cmp(snap.maxVoterRingDifficulty()) > 0) {
		// MODIFIED by Jakub Pajek (clique empty blocks, clique voter ring)
		// For any-period chains, refuse to seal empty blocks (no reward but would spin sealing)
		//if len(block.Transactions()) == 0 {
		return errors.New("sealing paused while waiting for transactions")
	}
	// Don't hold the signer fields for the entire sealing procedure
	c.lock.RLock()
	signer, signFn := c.signer, c.signFn
	c.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	var (
		nextNumber uint64
		inturnDiff *big.Int
	)
	if signed, ok := snap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	} else {
		// Check in which ring we are currently signing blocks in
		if !snap.VoterRing {
			// We are currently signing blocks in the sealer ring.
			// Check the diffuculty to determine if we want to stay
			// in the sealer ring or switch to the voter ring.
			if inturnDiff = snap.maxSealerRingDifficulty(); header.Difficulty.Cmp(inturnDiff) <= 0 {
				// We want to stay in the sealer ring
				nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
			} else if inturnDiff = snap.maxVoterRingDifficulty(); header.Difficulty.Cmp(inturnDiff) <= 0 {
				// We want to switch to the voter ring
				nextNumber = snap.nextVoterRingSignableBlockNumber(signed.LastSignedBlock)
				// Since, unlike mobile signers, voters are most likely to always be online,
				// they will sign in-turn most of the time while trying to switch to the voter ring.
				if headerHasVotes := number%currConfig.Epoch != 0 && len(header.Extra)-params.CliqueExtraVanity-params.CliqueExtraSeal > 0; !headerHasVotes {
					// Set in-turn difficulty value to 0, in order to treat all non-voting voters trying to switch
					// to the voter ring because of a network stall as out-of-turn. This will result in their block
					// being broadcast with a delay and will allow some of the in-turnish online signers to broadcast
					// their blocks faster, which in consequence will allow to prevent switching to the voter ring.
					inturnDiff = big.NewInt(0)
				}
			} else {
				// We want to preemptively prevent switching to the voter ring
				nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
				inturnDiff = snap.maxRingBreakerDifficulty()
			}
		} else {
			// We are currently signing blocks in the voter ring.
			// Check the difficulty to determine if we want to stay
			// in the voter ring or return to the sealer ring.
			if inturnDiff = snap.maxVoterRingDifficulty(); header.Difficulty.Cmp(inturnDiff) <= 0 {
				// We want to stay in the voter ring
				nextNumber = snap.nextVoterRingSignableBlockNumber(signed.LastSignedBlock)
				// Since, unlike mobile signers, voters are most likely to always be online,
				// they will sign in-turn most of the time while in the voter ring.
				if headerHasVotes := number%currConfig.Epoch != 0 && len(header.Extra)-params.CliqueExtraVanity-params.CliqueExtraSeal > 0; !headerHasVotes {
					// Set in-turn difficulty value to 0, in order to treat all non-voting voters in the voter ring
					// as out-of-turn, thus broadcast their blocks with a delay. This will allow some of the in-turnish
					// online signers to broadcast their blocks faster, which in consequence will allow to disband
					// the voter ring.
					inturnDiff = big.NewInt(0)
				}
			} else {
				// We want to return to the sealer ring
				nextNumber = snap.nextSealerRingSignableBlockNumber(signed.LastSignedBlock)
				inturnDiff = snap.maxRingBreakerDifficulty()
			}
		}
		if signed.LastSignedBlock > 0 {
			// Check against recent signers
			if nextNumber > number {
				// If we're amongst the recent signers, wait for the next block
				return errors.New("signed recently, must wait for others")
			}
		}
	}
	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Unix(int64(header.Time), 0).Sub(time.Now()) // nolint: gosimple
	if header.Difficulty.Cmp(inturnDiff) != 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
		delay += time.Duration(rand.Int63n(int64(wiggle)))

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	}
	// Sign all the things!
	sighash, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeClique, CliqueRLP(header))
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-params.CliqueExtraSeal:], sighash)
	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have.
func (c *Clique) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	number := big.NewInt(0).Add(parent.Number, big.NewInt(1))

	// Assemble the snapshot needed to access the current config
	snap, err := c.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		// MEMO by Jakub Pajek (clique config: variable period)
		// Are we running tests using a chain header reader stub?
		if !chain.IsStub() {
			log.Error("Failed to assemble the snapshot for difficulty calculation", "err", err)
		}
		return nil
	}
	currConfig := snap.CurrentConfig()

	// Check if we are an authorized voter, for future use...
	c.lock.RLock()
	signer := c.signer
	c.lock.RUnlock()
	_, okVoter := snap.Voters[signer]

	// Check in which ring we are currently signing blocks in
	if !snap.VoterRing {
		// We are currently signing blocks in the sealer ring.
		if okVoter {
			// If we are a voter, switch to the voter ring if:
			// - we are post-PrivateHardFork2 and want to cast votes, or
			// - a sufficiently long stall in block creation occurred
			// Continue in the sealer ring otherwise.
			headerHasVotes := false
			if (chain.Config().IsPrivateHardFork2(number) && headerHasVotes) ||
				(currConfig.Period > 0 && time >= parent.Time+(currConfig.MinStallPeriod*currConfig.Period)) {
				// Set the correct difficulty for the voter ring
				return snap.calcVoterRingDifficulty(signer)
			} else {
				// Set the correct difficulty for the sealer ring
				return snap.calcSealerRingDifficulty(signer)
			}
		} else {
			// If we are not a voter, preemptively prevent switching to the voter ring if:
			// - a sufficiently long stall in block creation occurred
			// Continue in the sealer ring otherwise.
			if currConfig.Period > 0 && time >= parent.Time+(currConfig.MinStallPeriod*currConfig.Period) {
				// Set the correct difficulty for preventing switching to the voter ring
				return snap.calcRingBreakerDifficulty(signer)
			} else {
				// Set the correct difficulty for the sealer ring
				return snap.calcSealerRingDifficulty(signer)
			}
		}
	} else {
		// We are currently signing blocks in the voter ring.
		if okVoter {
			// If we are a voter, continue in the voter ring.
			// Set the correct difficulty for the voter ring
			return snap.calcVoterRingDifficulty(signer)
		} else {
			// If we are not a voter, ...
			if chain.Config().IsPrivateHardFork2(number) {
				// For post-PrivateHardFork2 blocks, try returning to the sealer ring by disbanding the voter ring if:
				// - voting has not started, or
				// - a sufficiently long stall in block creation occurred
				// Withold sealing the block otherwise.
				if !snap.Voting ||
					(currConfig.Period > 0 && time >= parent.Time+(currConfig.MinStallPeriod*currConfig.Period)) {
					// Set the correct difficulty for disbanding the voter ring
					return snap.calcRingBreakerDifficulty(signer)
				} else {
					// Set the invalid difficulty to withold sealing the block
					return diffInvalid
				}
			} else {
				// For pre-PrivateHardFork2 blocks, try returning to the sealer ring by disbanding the voter ring if:
				// - always
				// Set the correct difficulty for disbanding the voter ring
				return snap.calcRingBreakerDifficulty(signer)
			}
		}
	}
}

// SealHash returns the hash of a block prior to it being sealed.
func (c *Clique) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// Close implements consensus.Engine. It's a noop for clique as there are no background threads.
func (c *Clique) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *Clique) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "clique",
		Service:   &API{chain: chain, clique: c},
	}}
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

// Snapshot implements consensus.PoA, returning the authorization snapshot
// at a given point in time.
func (c *Clique) Snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (consensus.PoASnapshot, error) {
	return c.snapshot(chain, number, hash, parents)
}

// CliqueRLP returns the rlp bytes which needs to be signed for the proof-of-authority
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func CliqueRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header)
	return b.Bytes()
}

func encodeSigHeader(w io.Writer, header *types.Header) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		panic("unexpected withdrawal hash value in clique")
	}
	if header.ExcessDataGas != nil {
		panic("unexpected excess data gas value in clique")
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}
