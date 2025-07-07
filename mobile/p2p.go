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

// Contains wrappers for the p2p package.

package geth

import (
	"errors"

	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
)

// NodeInfo represents pi short summary of the information known about the host.
type NodeInfo struct {
	info *p2p.NodeInfo
}

func (ni *NodeInfo) GetID() string              { return ni.info.ID }
func (ni *NodeInfo) GetName() string            { return ni.info.Name }
func (ni *NodeInfo) GetEnode() string           { return ni.info.Enode }
func (ni *NodeInfo) GetENR() string             { return ni.info.ENR }
func (ni *NodeInfo) GetIP() string              { return ni.info.IP }
func (ni *NodeInfo) GetDiscoveryPort() int      { return ni.info.Ports.Discovery }
func (ni *NodeInfo) GetListenerPort() int       { return ni.info.Ports.Listener }
func (ni *NodeInfo) GetListenerAddress() string { return ni.info.ListenAddr }
func (ni *NodeInfo) GetProtocols() *Strings {
	protos := []string{}
	for proto := range ni.info.Protocols {
		protos = append(protos, proto)
	}
	return &Strings{protos}
}

// PeerInfo represents pi short summary of the information known about pi connected peer.
type PeerInfo struct {
	info *p2p.PeerInfo
}

func (pi *PeerInfo) GetID() string            { return pi.info.ID }
func (pi *PeerInfo) GetName() string          { return pi.info.Name }
func (pi *PeerInfo) GetEnode() string         { return pi.info.Enode }
func (pi *PeerInfo) GetENR() string           { return pi.info.ENR }
func (pi *PeerInfo) GetCaps() *Strings        { return &Strings{pi.info.Caps} }
func (pi *PeerInfo) GetLocalAddress() string  { return pi.info.Network.LocalAddress }
func (pi *PeerInfo) GetRemoteAddress() string { return pi.info.Network.RemoteAddress }
func (pi *PeerInfo) GetIsInbound() bool       { return pi.info.Network.Inbound }
func (pi *PeerInfo) GetIsTrusted() bool       { return pi.info.Network.Trusted }
func (pi *PeerInfo) GetIsStatic() bool        { return pi.info.Network.Static }
func (pi *PeerInfo) GetProtocols() *Strings {
	protos := []string{}
	for proto := range pi.info.Protocols {
		protos = append(protos, proto)
	}
	return &Strings{protos}
}

// PeerInfos represents a slice of infos about remote peers.
type PeerInfos struct {
	infos []*p2p.PeerInfo
}

// Size returns the number of peer info entries in the slice.
func (pi *PeerInfos) Size() int {
	return len(pi.infos)
}

// Get returns the peer info at the given index from the slice.
func (pi *PeerInfos) Get(index int) (info *PeerInfo, _ error) {
	if index < 0 || index >= len(pi.infos) {
		return nil, errors.New("index out of bounds")
	}
	return &PeerInfo{pi.infos[index]}, nil
}

// DiscoveryNode represents a node entry in the discovery table.
type DiscoveryNode struct {
	node discover.BucketNode
}

func (dn *DiscoveryNode) GetNode() string          { return dn.node.Node.String() }
func (dn *DiscoveryNode) GetNodeID() string        { return dn.node.Node.ID().String() }
func (dn *DiscoveryNode) GetNodeHostname() string  { return dn.node.Node.Hostname() }
func (dn *DiscoveryNode) GetNodeIP() string        { return dn.node.Node.IPAddr().String() }
func (dn *DiscoveryNode) GetNodeUDP() int          { return dn.node.Node.UDP() }
func (dn *DiscoveryNode) GetNodeTCP() int          { return dn.node.Node.TCP() }
func (dn *DiscoveryNode) GetAddedToTable() string  { return dn.node.AddedToTable.String() }
func (dn *DiscoveryNode) GetAddedToBucket() string { return dn.node.AddedToBucket.String() }
func (dn *DiscoveryNode) GetChecks() int           { return dn.node.Checks }
func (dn *DiscoveryNode) GetLive() bool            { return dn.node.Live }

// DiscoveryBucket represents a slice of nodes in a discovery bucket.
type DiscoveryBucket struct {
	nodes []discover.BucketNode
}

// Size returns the number of node entries in the discovery bucket.
func (db *DiscoveryBucket) Size() int {
	return len(db.nodes)
}

// Get returns the node at the given index from the discovery bucket.
func (db *DiscoveryBucket) Get(index int) (node *DiscoveryNode, _ error) {
	if index < 0 || index >= len(db.nodes) {
		return nil, errors.New("index out of bounds")
	}
	return &DiscoveryNode{db.nodes[index]}, nil
}

// DiscoveryTable represents a slice of buckets in a discovery table.
type DiscoveryTable struct {
	buckets [][]discover.BucketNode
}

// Size returns the number of bucket entries in the discovery table.
func (dt *DiscoveryTable) Size() int {
	return len(dt.buckets)
}

// Get returns the bucket at the given index from the discovery table.
func (dt *DiscoveryTable) Get(index int) (nodes *DiscoveryBucket, _ error) {
	if index < 0 || index >= len(dt.buckets) {
		return nil, errors.New("index out of bounds")
	}
	return &DiscoveryBucket{dt.buckets[index]}, nil
}
