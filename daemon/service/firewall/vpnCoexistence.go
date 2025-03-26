// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package firewall

import (
	"regexp"
	"time"
)

const (
	MIN_BRAND_FIRST_WORD_LEN = 4 // first word must be at least 4 characters long to be a candidate for brand name
	// MAX_WINDOWS_SERVICE_CANDIDATES = 10

	MAX_WAIT = 10 * time.Second
)

var (
	FirstWordRE *regexp.Regexp = regexp.MustCompilePOSIX("^[^[:space:]_\\.-]+") // regexp for the 1st word: "^[^[:space:]_\.-]+"
)

type otherVpnCliCmds struct {
	cmdStatus string

	statusConnectedRE    string
	statusDisconnectedRE string

	cmdEnableSplitTun                  []string
	cmdAddOurBinaryToSplitTunWhitelist []string
	cmdAddAllowlistOption              []string // used only on Linux
	cmdRemoveAllowlistOption           []string // used only on Linux
	cmdConnect                         string
	cmdDisconnect                      string
}

type otherVpnCoexistenceLegacyHelper func() (err error)

// Contains all the information about another VPN that we need to configure interoperability
type OtherVpnInfo struct {
	name       string // display name of another VPN
	namePrefix string // name prefix used to match sublayer, provider names, and Windows service names

	cli             string // CLI command of that VPN, used to add our binaries & IP ranges to their exception list. If left blank - that means this VPN doesn't have a useful CLI.
	cliPathResolved string // resolved at runtime
	cliCmds         otherVpnCliCmds

	changesNftables       bool
	changesIptablesLegacy bool
	iptablesLegacyChain   string
	iptablesLegacyHelper  otherVpnCoexistenceLegacyHelper // if changesIptablesLegacy=true, then iptablesLegacyHelper must be set to some func ptr

	recommendedOurMTU int // MTU we set on our wgprivateline interface if other VPN is present
}

func BestWireguardMtuForConditions() (recommendedMTU int, retErr error) {
	return implBestWireguardMtuForConditions()
}
