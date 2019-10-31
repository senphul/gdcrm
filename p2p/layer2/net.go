// Copyright 2014 The go-ethereum Authors
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

package layer2

import (
	"net"
	"sync"
	"sync/atomic"

	mapset "github.com/deckarep/golang-set"
	"github.com/fusion/go-fusion/p2p"
	"github.com/fusion/go-fusion/p2p/discover"
)

//TODO
const (
	DcrmProtocol_type = discover.Dcrmprotocol_type
	Xprotocol_type   = discover.Xprotocol_type
	Sdkprotocol_type   = discover.Sdkprotocol_type
	ProtocolName     = "dcrm"
	Xp_ProtocolName  = "xp"
	peerMsgCode      = iota
	Dcrm_msgCode
	Sdk_msgCode
	Xp_msgCode

	ProtocolVersion      = 1
	ProtocolVersionStr   = "1"
	NumberOfMessageCodes = 8 + iota // msgLength

	maxKnownTxs = 30 // Maximum transactions hashes to keep in the known list (prevent DOS)

	broatcastFailTimes = 0 //30 Redo Send times( 30 * 2s = 60 s)
	broatcastFailOnce  = 2
)

var (
	bootNodeIP *net.UDPAddr
	callback   func(interface{}, string)
	Dcrm_callback   func(interface{}) <-chan string
	Sdk_callback   func(interface{}, string)
	Xp_callback   func(interface{})
	emitter    *Emitter
	dccpGroup  *Group
	xpGroup    *Group
	selfid     discover.NodeID
	sdkGroup   map[discover.NodeID]*Group = make(map[discover.NodeID]*Group)
)

type Dcrm struct {
	protocol p2p.Protocol
	//peers     map[discover.NodeID]*Peer
	peers     map[discover.NodeID]*peer
	dccpPeers map[discover.NodeID]bool
	peerMu    sync.Mutex    // Mutex to sync the active peer set
	quit      chan struct{} // Channel used for graceful exit
	cfg       *Config
}

type Xp struct {
	protocol p2p.Protocol
	//peers     map[discover.NodeID]*Peer
	peers     map[discover.NodeID]*peer
	dccpPeers map[discover.NodeID]bool
	peerMu    sync.Mutex    // Mutex to sync the active peer set
	quit      chan struct{} // Channel used for graceful exit
	cfg       *Config
}

type Config struct {
	Nodes    []*discover.Node
	DataPath string
}

var DefaultConfig = Config{
	Nodes: make([]*discover.Node, 0),
}

type DcrmAPI struct {
	dcrm *Dcrm
}

type XpAPI struct {
	xp *Xp
}

type peerInfo struct {
	Version int `json:"version"`
	//Head     string   `json:"head"`
}

type peer struct {
	peer     *p2p.Peer
	ws       p2p.MsgReadWriter
	peerInfo *peerInfo

	knownTxs  mapset.Set // Set of transaction hashes known to be known by this peer
	queuedTxs []*Transaction
}

type Emitter struct {
	peers map[discover.NodeID]*peer
	sync.Mutex
}
type group struct {
	id    discover.NodeID
	ip    net.IP
	port  uint16
	enode string
}
type Group struct {
	sync.Mutex
	group map[string]*group
}

type Transaction struct {
	Payload []byte
	Hash    atomic.Value
}
