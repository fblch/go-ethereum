// Copyright 2016 The go-ethereum Authors
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

// Contains all the wrappers from the node package to support client side node
// management on mobile platforms.

package geth

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	// ADDED by Jakub Pajek BEG
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/log"

	// ADDED by Jakub Pajek END

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethstats"
	"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/les"

	// ADDED by Jakub Pajek BEG
	"github.com/ethereum/go-ethereum/eth"
	// ADDED by Jakub Pajek END

	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/params"
)

// ADDED by Jakub Pajek BEG
const (
	// Sync mode defaults to light sync (not full sync!)
	SyncModeDefault int64 = int64(downloader.FullSync)

	// Quickly download the headers, full sync only at the chain
	SyncModeFast = int64(downloader.FastSync)

	// Download the chain and the state via compact snapshots
	SyncModeSnap = int64(downloader.SnapSync)

	// Download only the headers and terminate afterwards
	SyncModeLight = int64(downloader.LightSync)
)

// ADDED by Jakub Pajek END

// NodeConfig represents the collection of configuration values to fine tune the Geth
// node embedded into a mobile process. The available values are a subset of the
// entire API provided by go-ethereum to reduce the maintenance surface and dev
// complexity.
type NodeConfig struct {
	// Bootstrap nodes used to establish connectivity with the rest of the network.
	BootstrapNodes *Enodes

	// MaxPeers is the maximum number of peers that can be connected. If this is
	// set to zero, then only the configured static and trusted peers can connect.
	MaxPeers int

	// EthereumEnabled specifies whether the node should run the Ethereum protocol.
	EthereumEnabled bool

	// EthereumNetworkID is the network identifier used by the Ethereum protocol to
	// decide if remote peers should be accepted or not.
	EthereumNetworkID int64 // uint64 in truth, but Java can't handle that...

	// EthereumGenesis is the genesis JSON to use to seed the blockchain with. An
	// empty genesis state is equivalent to using the mainnet's state.
	EthereumGenesis string

	// EthereumDatabaseCache is the system memory in MB to allocate for database caching.
	// A minimum of 16MB is always reserved.
	EthereumDatabaseCache int

	// EthereumNetStats is a netstats connection string to use to report various
	// chain, transaction and node stats to a monitoring server.
	//
	// It has the form "nodename:secret@host:port"
	EthereumNetStats string

	// Listening address of pprof server.
	PprofAddress string

	// ADDED by Jakub Pajek
	// UserIdent, if set, is used as an additional component in the devp2p node identifier.
	UserIdent string

	// ADDED by Jakub Pajek
	// SyncMode represents the synchronisation mode of the blockchain downloader.
	SyncMode int64 // uint32 in truth, but Java can't handle that...

	// ADDED by Jakub Pajek
	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	NoDiscovery bool

	// ADDED by Jakub Pajek
	// DiscoveryV5 specifies whether the new topic-discovery based V5 discovery
	// protocol should be started or not.
	DiscoveryV5 bool

	// ADDED by Jakub Pajek
	// UseLightweightKDF lowers the memory and CPU requirements of the key store
	// scrypt KDF at the expense of security.
	UseLightweightKDF bool

	// ADDED by Jakub Pajek
	// MinerGasLimit sets target gas ceiling for mined blocks.
	MinerGasLimit int64 // uint64 in truth, but Java can't handle that...

	// ADDED by Jakub Pajek
	// MinerGasPrice sets minimum gas price for mining a transaction.
	MinerGasPrice *BigInt

	// ADDED by Jakub Pajek
	// MinerGasPrice sets block extra data set by the miner (default = client version).
	// Maximum size is 32 bytes.
	MinerExtraData string
}

// defaultNodeConfig contains the default node configuration values to use if all
// or some fields are missing from the user's specified list.
var defaultNodeConfig = &NodeConfig{
	BootstrapNodes:        FoundationBootnodes(),
	MaxPeers:              25,
	EthereumEnabled:       true,
	EthereumNetworkID:     1,
	EthereumDatabaseCache: 16,
	// ADDED by Jakub Pajek BEG
	UserIdent:         "",
	SyncMode:          int64(downloader.LightSync),
	NoDiscovery:       true,
	DiscoveryV5:       true,
	UseLightweightKDF: false,
	MinerGasLimit:     int64(ethconfig.Defaults.Miner.GasCeil),
	MinerGasPrice:     NewBigInt(ethconfig.Defaults.Miner.GasPrice.Int64()),
	MinerExtraData:    "",
	// ADDED by Jakub Pajek END
}

// NewNodeConfig creates a new node option set, initialized to the default values.
func NewNodeConfig() *NodeConfig {
	config := *defaultNodeConfig
	return &config
}

// AddBootstrapNode adds an additional bootstrap node to the node config.
func (conf *NodeConfig) AddBootstrapNode(node *Enode) {
	conf.BootstrapNodes.Append(node)
}

// EncodeJSON encodes a NodeConfig into a JSON data dump.
func (conf *NodeConfig) EncodeJSON() (string, error) {
	data, err := json.Marshal(conf)
	return string(data), err
}

// String returns a printable representation of the node config.
func (conf *NodeConfig) String() string {
	return encodeOrError(conf)
}

// Node represents a Geth Ethereum node instance.
type Node struct {
	node *node.Node
	// ADDED by Jakub Pajek
	eth *eth.Ethereum
}

// NewNode creates and configures a new Geth node.
func NewNode(datadir string, config *NodeConfig) (stack *Node, _ error) {
	// If no or partial configurations were specified, use defaults
	if config == nil {
		config = NewNodeConfig()
	}
	if config.MaxPeers == 0 {
		config.MaxPeers = defaultNodeConfig.MaxPeers
	}
	if config.BootstrapNodes == nil || config.BootstrapNodes.Size() == 0 {
		config.BootstrapNodes = defaultNodeConfig.BootstrapNodes
	}

	if config.PprofAddress != "" {
		debug.StartPProf(config.PprofAddress, true)
	}
	// ADDED by Jakub Pajek BEG
	if config.UserIdent == "" {
		config.UserIdent = defaultNodeConfig.UserIdent
	}
	if config.SyncMode == SyncModeDefault {
		config.SyncMode = defaultNodeConfig.SyncMode
	}
	if config.MinerGasLimit <= 0 {
		config.MinerGasLimit = defaultNodeConfig.MinerGasLimit
	}
	if config.MinerGasPrice == nil || config.MinerGasPrice.Sign() <= 0 {
		config.MinerGasPrice = defaultNodeConfig.MinerGasPrice
	}
	// ADDED by Jakub Pajek END

	// Create the empty networking stack
	nodeConf := &node.Config{
		Name: clientIdentifier,
		// ADDED by Jakub Pajek BEG
		UserIdent: config.UserIdent,
		// ADDED by Jakub Pajek END
		Version:     params.VersionWithMeta,
		DataDir:     datadir,
		KeyStoreDir: filepath.Join(datadir, "keystore"), // Mobile should never use internal keystores!
		// ADDED by Jakub Pajek BEG
		UseLightweightKDF: config.UseLightweightKDF,
		// ADDED by Jakub Pajek END
		P2P: p2p.Config{
			// MODIFIED by Jakub Pajek BEG
			//NoDiscovery:      true,
			//DiscoveryV5:      true,
			NoDiscovery:    config.NoDiscovery,
			DiscoveryV5:    config.DiscoveryV5,
			BootstrapNodes: config.BootstrapNodes.nodes,
			// MODIFIED by Jakub Pajek END
			BootstrapNodesV5: config.BootstrapNodes.nodes,
			ListenAddr:       ":0",
			NAT:              nat.Any(),
			MaxPeers:         config.MaxPeers,
		},
	}

	rawStack, err := node.New(nodeConf)
	if err != nil {
		return nil, err
	}

	// ADDED by Jakub Pajek BEG
	// Node doesn't by default populate account manager backends
	if err := setAccountManagerBackends(rawStack); err != nil {
		return nil, fmt.Errorf("Failed to set account manager backends: %v", err)
	}
	// ADDED by Jakub Pajek END

	debug.Memsize.Add("node", rawStack)

	var genesis *core.Genesis
	if config.EthereumGenesis != "" {
		// Parse the user supplied genesis spec if not mainnet
		genesis = new(core.Genesis)
		if err := json.Unmarshal([]byte(config.EthereumGenesis), genesis); err != nil {
			return nil, fmt.Errorf("invalid genesis spec: %v", err)
		}
		// If we have the Ropsten testnet, hard code the chain configs too
		if config.EthereumGenesis == RopstenGenesis() {
			genesis.Config = params.RopstenChainConfig
			if config.EthereumNetworkID == 1 {
				config.EthereumNetworkID = 3
			}
		}
		// If we have the Rinkeby testnet, hard code the chain configs too
		if config.EthereumGenesis == RinkebyGenesis() {
			genesis.Config = params.RinkebyChainConfig
			if config.EthereumNetworkID == 1 {
				config.EthereumNetworkID = 4
			}
		}
		// If we have the Goerli testnet, hard code the chain configs too
		if config.EthereumGenesis == GoerliGenesis() {
			genesis.Config = params.GoerliChainConfig
			if config.EthereumNetworkID == 1 {
				config.EthereumNetworkID = 5
			}
		}
	}
	// Register the Ethereum protocol if requested
	// ADDED by Jakub Pajek BEG
	var ethBackend *eth.Ethereum = nil
	// ADDED by Jakub Pajek END
	if config.EthereumEnabled {
		ethConf := ethconfig.Defaults
		ethConf.Genesis = genesis
		// MODIFIED by Jakub Pajek BEG
		//ethConf.SyncMode = downloader.LightSync
		ethConf.SyncMode = downloader.SyncMode(config.SyncMode)
		// MODIFIED by Jakub Pajek END
		ethConf.NetworkId = uint64(config.EthereumNetworkID)
		ethConf.DatabaseCache = config.EthereumDatabaseCache
		// ADDED by Jakub Pajek BEG
		ethConf.Miner.GasCeil = uint64(config.MinerGasLimit)
		ethConf.Miner.GasPrice = new(big.Int).SetBytes(config.MinerGasPrice.GetBytes())
		ethConf.Miner.ExtraData = []byte(config.MinerExtraData)
		// ADDED by Jakub Pajek END
		// MODIFIED by Jakub Pajek BEG
		/*
			lesBackend, err := les.New(rawStack, &ethConf)
			if err != nil {
				return nil, fmt.Errorf("ethereum init: %v", err)
			}
			// If netstats reporting is requested, do it
			if config.EthereumNetStats != "" {
				if err := ethstats.New(rawStack, lesBackend.ApiBackend, lesBackend.Engine(), config.EthereumNetStats); err != nil {
					return nil, fmt.Errorf("netstats init: %v", err)
				}
			}
		*/
		if ethConf.SyncMode == downloader.LightSync {
			lesBackend, err := les.New(rawStack, &ethConf)
			if err != nil {
				return nil, fmt.Errorf("ethereum init: %v", err)
			}
			// If netstats reporting is requested, do it
			if config.EthereumNetStats != "" {
				if err := ethstats.New(rawStack, lesBackend.ApiBackend, lesBackend.Engine(), config.EthereumNetStats); err != nil {
					return nil, fmt.Errorf("netstats init: %v", err)
				}
			}
		} else {
			backend, err := eth.New(rawStack, &ethConf)
			if err != nil {
				return nil, fmt.Errorf("ethereum init: %v", err)
			}
			ethBackend = backend
			// If netstats reporting is requested, do it
			if config.EthereumNetStats != "" {
				if err := ethstats.New(rawStack, backend.APIBackend, backend.Engine(), config.EthereumNetStats); err != nil {
					return nil, fmt.Errorf("netstats init: %v", err)
				}
			}
		}
		// MODIFIED by Jakub Pajek END
	}
	// MODIFIED by Jakub Pajek
	//return &Node{rawStack}, nil
	return &Node{rawStack, ethBackend}, nil
}

// Close terminates a running node along with all it's services, tearing internal state
// down. It is not possible to restart a closed node.
func (n *Node) Close() error {
	return n.node.Close()
}

// Start creates a live P2P node and starts running it.
func (n *Node) Start() error {
	// TODO: recreate the node so it can be started multiple times
	return n.node.Start()
}

// ADDED by Jakub Pajek
// Start creates a live P2P sealer node and starts running it.
func (n *Node) StartSealer() error {
	// Check if n is a configured as a full node
	if n.eth == nil {
		return errors.New("Light clients do not support mining")
	}
	// Check if the sealer account exists
	if !n.HasSealerAccount() {
		return errors.New("sealer account does not exist")
	}
	// Unlock the sealer account
	if err := n.UnlockSealerAccount(); err != nil {
		return err
	}
	// Start up the node itself
	if err := n.node.Start(); err != nil {
		return err
	}
	// Start mining
	threads := 0
	if err := n.eth.StartMining(threads); err != nil {
		log.Error("Failed to start mining", "err", err)
		n.node.Close()
		return err
	}

	// From cmd/geth/main.go:startNode()
	/*
		// Register wallet event handlers to open and auto-derive wallets
		events := make(chan accounts.WalletEvent, 16)
		stack.AccountManager().Subscribe(events)

		// Create a client to interact with local geth node.
		rpcClient, err := stack.Attach()
		if err != nil {
			utils.Fatalf("Failed to attach to self: %v", err)
		}
		ethClient := ethclient.NewClient(rpcClient)

		go func() {
			// Open any wallets already attached
			for _, wallet := range stack.AccountManager().Wallets() {
				if err := wallet.Open(""); err != nil {
					log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
				}
			}
			// Listen for wallet event till termination
			for event := range events {
				switch event.Kind {
				case accounts.WalletArrived:
					if err := event.Wallet.Open(""); err != nil {
						log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
					}
				case accounts.WalletOpened:
					status, _ := event.Wallet.Status()
					log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

					var derivationPaths []accounts.DerivationPath
					if event.Wallet.URL().Scheme == "ledger" {
						derivationPaths = append(derivationPaths, accounts.LegacyLedgerBaseDerivationPath)
					}
					derivationPaths = append(derivationPaths, accounts.DefaultBaseDerivationPath)

					event.Wallet.SelfDerive(derivationPaths, ethClient)

				case accounts.WalletDropped:
					log.Info("Old wallet dropped", "url", event.Wallet.URL())
					event.Wallet.Close()
				}
			}
		}()

		// Spawn a standalone goroutine for status synchronization monitoring,
		// close the node when synchronization is complete if user required.
		if ctx.GlobalBool(utils.ExitWhenSyncedFlag.Name) {
			go func() {
				sub := stack.EventMux().Subscribe(downloader.DoneEvent{})
				defer sub.Unsubscribe()
				for {
					event := <-sub.Chan()
					if event == nil {
						continue
					}
					done, ok := event.Data.(downloader.DoneEvent)
					if !ok {
						continue
					}
					if timestamp := time.Unix(int64(done.Latest.Time), 0); time.Since(timestamp) < 10*time.Minute {
						log.Info("Synchronisation completed", "latestnum", done.Latest.Number, "latesthash", done.Latest.Hash(),
							"age", common.PrettyAge(timestamp))
						stack.Close()
					}
				}
			}()
		}

		// Start auxiliary services if enabled
		if ctx.GlobalBool(utils.MiningEnabledFlag.Name) || ctx.GlobalBool(utils.DeveloperFlag.Name) {
			// Mining only makes sense if a full Ethereum node is running
			if ctx.GlobalString(utils.SyncModeFlag.Name) == "light" {
				utils.Fatalf("Light clients do not support mining")
			}
			ethBackend, ok := backend.(*eth.EthAPIBackend)
			if !ok {
				utils.Fatalf("Ethereum service not running: %v", err)
			}
			// Set the gas price to the limits from the CLI and start mining
			gasprice := utils.GlobalBig(ctx, utils.MinerGasPriceFlag.Name)
			ethBackend.TxPool().SetGasPrice(gasprice)
			// start mining
			threads := ctx.GlobalInt(utils.MinerThreadsFlag.Name)
			if err := ethBackend.StartMining(threads); err != nil {
				utils.Fatalf("Failed to start mining: %v", err)
			}
		}
	*/

	return nil
}

// Stop terminates a running node along with all its services. If the node was not started,
// an error is returned. It is not possible to restart a stopped node.
//
// Deprecated: use Close()
func (n *Node) Stop() error {
	return n.node.Close()
}

// GetEthereumClient retrieves a client to access the Ethereum subsystem.
func (n *Node) GetEthereumClient() (client *EthereumClient, _ error) {
	rpc, err := n.node.Attach()
	if err != nil {
		return nil, err
	}
	return &EthereumClient{ethclient.NewClient(rpc)}, nil
}

// GetNodeInfo gathers and returns a collection of metadata known about the host.
func (n *Node) GetNodeInfo() *NodeInfo {
	return &NodeInfo{n.node.Server().NodeInfo()}
}

// GetPeersInfo returns an array of metadata objects describing connected peers.
func (n *Node) GetPeersInfo() *PeerInfos {
	return &PeerInfos{n.node.Server().PeersInfo()}
}

// ADDED by Jakub Pajek
// TODOJAKUB stop using hardcoded password for the sealer account.
var sealerAccountPassword string = "fbdc1234"

// ADDED by Jakub Pajek
// HasSealerAccount reports whether the sealer account (first account) is present.
func (n *Node) HasSealerAccount() bool {
	ks := n.node.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	return len(ks.Accounts()) > 0
}

// ADDED by Jakub Pajek
// GetSealerAccount returns the sealser account (first account).
func (n *Node) GetSealerAccount() (account *Account, _ error) {
	ks := n.node.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	accounts := ks.Accounts()
	if len(accounts) <= 0 {
		return nil, errors.New("sealer account does not exist")
	}
	return &Account{accounts[0]}, nil
}

// ADDED by Jakub Pajek
// DeleteSealerAccount deletes the sealer account (first account) if the passphrase is correct.
func (n *Node) DeleteSealerAccount() error {
	ks := n.node.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	accounts := ks.Accounts()
	if len(accounts) <= 0 {
		return errors.New("sealer account does not exist")
	}
	return ks.Delete(accounts[0], sealerAccountPassword)
}

// ADDED by Jakub Pajek
// CreateSealerAccount generates a new sealer key and stores it into the key directory
// in node's internal keystore, encrypting it with the passphrase.
func (n *Node) CreateSealerAccount() (*Account, error) {
	ks := n.node.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	if len(ks.Accounts()) > 0 {
		return nil, errors.New("sealer account already exists")
	}
	account, err := ks.NewAccount(sealerAccountPassword)
	if err != nil {
		return nil, err
	}
	return &Account{account}, nil
}

// ADDED by Jakub Pajek
// UnlockSealerAccount unlocks the sealer account (first account).
func (n *Node) UnlockSealerAccount() error {
	ks := n.node.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	accounts := ks.Accounts()
	if len(accounts) <= 0 {
		return errors.New("sealer account does not exist")
	}
	err := ks.Unlock(accounts[0], sealerAccountPassword)
	if err == nil {
		log.Info("Unlocked account", "address", accounts[0].Address.Hex())
	}
	return err
}

// ADDED by Jakub Pajek
// Copied from cmd/geth/config.go:setAccountManagerBackends()
func setAccountManagerBackends(stack *node.Node) error {
	conf := stack.Config()
	am := stack.AccountManager()
	keydir := stack.KeyStoreDir()
	scryptN := keystore.StandardScryptN
	scryptP := keystore.StandardScryptP
	if conf.UseLightweightKDF {
		scryptN = keystore.LightScryptN
		scryptP = keystore.LightScryptP
	}

	// Assemble the supported backends
	/*
		if len(conf.ExternalSigner) > 0 {
			log.Info("Using external signer", "url", conf.ExternalSigner)
			if extapi, err := external.NewExternalBackend(conf.ExternalSigner); err == nil {
				am.AddBackend(extapi)
				return nil
			} else {
				return fmt.Errorf("error connecting to external signer: %v", err)
			}
		}
	*/

	// For now, we're using EITHER external signer OR local signers.
	// If/when we implement some form of lockfile for USB and keystore wallets,
	// we can have both, but it's very confusing for the user to see the same
	// accounts in both externally and locally, plus very racey.
	am.AddBackend(keystore.NewKeyStore(keydir, scryptN, scryptP))
	/*
		if conf.USB {
			// Start a USB hub for Ledger hardware wallets
			if ledgerhub, err := usbwallet.NewLedgerHub(); err != nil {
				log.Warn(fmt.Sprintf("Failed to start Ledger hub, disabling: %v", err))
			} else {
				am.AddBackend(ledgerhub)
			}
			// Start a USB hub for Trezor hardware wallets (HID version)
			if trezorhub, err := usbwallet.NewTrezorHubWithHID(); err != nil {
				log.Warn(fmt.Sprintf("Failed to start HID Trezor hub, disabling: %v", err))
			} else {
				am.AddBackend(trezorhub)
			}
			// Start a USB hub for Trezor hardware wallets (WebUSB version)
			if trezorhub, err := usbwallet.NewTrezorHubWithWebUSB(); err != nil {
				log.Warn(fmt.Sprintf("Failed to start WebUSB Trezor hub, disabling: %v", err))
			} else {
				am.AddBackend(trezorhub)
			}
		}
		if len(conf.SmartCardDaemonPath) > 0 {
			// Start a smart card hub
			if schub, err := scwallet.NewHub(conf.SmartCardDaemonPath, scwallet.Scheme, keydir); err != nil {
				log.Warn(fmt.Sprintf("Failed to start smart card hub, disabling: %v", err))
			} else {
				am.AddBackend(schub)
			}
		}
	*/

	return nil
}
