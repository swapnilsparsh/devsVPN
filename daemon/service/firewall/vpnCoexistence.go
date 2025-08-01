// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package firewall

import (
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/shell"
)

const (
	MIN_BRAND_FIRST_WORD_LEN = 4 // first word must be at least 4 characters long to be a candidate for brand name
	// MAX_WINDOWS_SERVICE_CANDIDATES = 10

	MAX_WAIT = 10 * time.Second

	VPN_REDETECT_PERIOD = 5 * time.Second
)

var (
	FirstWordRE                = regexp.MustCompilePOSIX("^[^[:space:]_\\.-]+")         // regexp for the 1st word: "^[^[:space:]_\.-]+"
	commonStatusConnectedRE    = regexp.MustCompile("^Connect(ed|ing)([^a-zA-Z0-9]|$)") // must be 1st line
	commonStatusDisconnectedRE = regexp.MustCompile("^Disconnected([^a-zA-Z0-9]|$)")

	// Must contain all the other VPNs profiles, initialized in platform-specific init()
	knownOtherVpnProfiles = []*OtherVpnInfo{}

	// Index (DB) of other VPNs by name, must be initialized in platform-specific init() to avoid initialization cycles
	otherVpnsByName = map[string]*OtherVpnInfo{}

	otherVpnsLastDetectionTimestamp time.Time // if we last re-detected other VPNs less than 5s ago, usually no reason to re-detect again
)

type otherVpnCliCmds struct {
	cmdStatus               string
	checkCliConnectedStatus bool
	statusConnectedRE       *regexp.Regexp
	statusDisconnectedRE    *regexp.Regexp

	cmdConnect    string
	cmdDisconnect string

	cmdEnableSplitTun                          []string
	cmdAddOurBinaryPathToSplitTunWhitelist     []string
	cmdAddOurBinaryPidToSplitTunWhitelist      []string // used for Mullvad on Linux
	cmdDeleteOurBinaryPidFromSplitTunWhitelist []string // used for Mullvad on Linux

	// i.e., ExpressVPN CLI cmd to add our app to splittunnel bypass: expressvpnctl set split-app bypass:/usr/bin/privateline-connect-svc
	// so the add prefix for it would be "bypass:"
	cmdSplitTunnelOurBinaryPathPrefixAdd string
	// and the remove prefix for it would be "remove:"
	cmdSplitTunnelOurBinaryPathPrefixRemove string

	cmdAddAllowlistOption    []string // used for NordVPN on Linux
	cmdRemoveAllowlistOption []string // used for NordVPN on Linux

	cmdLockdownMode []string // used by Mullvad on Linux, Windows
	cmdAllowLan     []string // used by ExpressVPN on Linux, and by Mullvad on Linux, Windows
}

type otherVpnCoexistenceLegacyHelper func() (err error)
type otherVpnCoexistenceNftHelper func() (err error)

// Contains all the information about another VPN that we need to configure interoperability
type OtherVpnInfo struct {
	name       string // display name of another VPN
	namePrefix string // name prefix used to match sublayer, provider names, and Windows service names

	recommendedOurMTU                    int  // MTU we set on our wgprivateline interface if other VPN is present
	incompatWithTotalShieldWhenConnected bool // set to true if Total Shield cannot work when this VPN is connected (network interface is up)
	isConnectedConnecting                bool // whether the other VPN is connected or connecting

	networkInterfaceNames []string // names of network interfaces associated with this VPN

	changesNftables               bool // used on Linux
	nftablesChain                 string
	nftablesChainNamePrefix       string         // used on Linux by ExpressVPN, for nft monitor to try and detect when ExpressVPN is connecting
	nftablesChainNameExclusionsRE *regexp.Regexp // exclusions
	nftablesHelper                otherVpnCoexistenceNftHelper

	changesIptablesLegacy bool // used on Linux
	iptablesLegacyChain   string
	iptablesLegacyHelper  otherVpnCoexistenceLegacyHelper // if changesIptablesLegacy=true, then iptablesLegacyHelper must be set to some func ptr

	cli                    string // CLI command of that VPN, used to add our binaries & IP ranges to their exception list. If left blank - that means this VPN doesn't have a useful CLI.
	cliPathResolved        string // resolved at runtime
	otherVpnCliFound       bool
	cliCmds                otherVpnCliCmds
	runVpnCliCommandsMutex sync.Mutex // used to protect RunVpnCliCommands()
}

// CheckVpnConnectedConnecting checks whether other VPN was connected by running its CLI. Logic is common to Windows and Linux.
func (otherVpn *OtherVpnInfo) CheckVpnConnectedConnecting() (isConnected bool, retErr error) {
	if len(otherVpn.networkInterfaceNames) > 0 { // check by interface name 1st, whether one of their interfaces exists
		for _, ifaceName := range otherVpn.networkInterfaceNames {
			if _, err := net.InterfaceByName(ifaceName); err == nil {
				return true, nil
			}
		}
	}

	if !otherVpn.cliCmds.checkCliConnectedStatus { // next check via CLI command
		return false, nil
	}

	var otherVpnCli string
	if otherVpn.cliPathResolved != "" {
		otherVpnCli = otherVpn.cliPathResolved
	} else {
		otherVpnCli = otherVpn.cli
	}

	_isConnected := false
	const maxErrBufSize int = 1024
	strErr := strings.Builder{}
	outProcessFunc := func(text string, isError bool) {
		if len(text) == 0 {
			return
		}
		if isError {
			if strErr.Len() > maxErrBufSize {
				return
			}
			strErr.WriteString(text)
		} else {
			if otherVpn.cliCmds.statusConnectedRE.MatchString(text) {
				_isConnected = true
			}
		}
	}

	if retErr = shell.ExecAndProcessOutput(log, outProcessFunc, "", otherVpnCli, otherVpn.cliCmds.cmdStatus); retErr != nil {
		return false, log.ErrorFE("error matching '%s': %s", otherVpn.cliCmds.statusConnectedRE, strErr.String())
	}

	otherVpn.isConnectedConnecting = _isConnected
	return otherVpn.isConnectedConnecting, nil
}

func BestWireguardMtuForConditions() (recommendedMTU int, retErr error) {
	return implBestWireguardMtuForConditions()
}

func ReDetectOtherVpns(forceRedetection, detectOnlyByInterfaceName, updateCurrentMTU bool) (recommendedNewMTU int, err error) {
	return reDetectOtherVpnsImpl(forceRedetection, detectOnlyByInterfaceName, updateCurrentMTU)
}
