// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package vpncoexistence

import (
	"regexp"
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
	"github.com/swapnilsparsh/devsVPN/daemon/service/preferences"
)

const (
	MIN_BRAND_FIRST_WORD_LEN = 4 // first word must be at least 4 characters long to be a candidate for brand name
	// MAX_WINDOWS_SERVICE_CANDIDATES = 10

	MAX_WAIT = 10 * time.Second
)

var (
	FirstWordRE *regexp.Regexp = regexp.MustCompilePOSIX("^[^[:space:]_\\.-]+") // regexp for the 1st word: "^[^[:space:]_\.-]+"

	log *logger.Logger
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

// Contains all the information about another VPN that we need to configure interoperability
type OtherVpnInfo struct {
	name       string // display name of another VPN
	namePrefix string // name prefix used to match sublayer, provider names, and Windows service names

	hasCLI  bool
	cliPath string // full or relative path to CLI of that VPN, used to start connection and add our binaries to their split-tunnel whitelist
	cliCmds otherVpnCliCmds

	needsResolvectlDnsConfig bool

	ourMTU int // MTU we set on our wgprivateline interface if other VPN is present
}

func init() {
	log = logger.NewLogger("vpncoe")
}

func EnableCoexistenceWithOtherVpns(prefs preferences.Preferences, vpnConnectedOrConnectingCallback types.VpnConnectedCallback) (retErr error) {
	return implEnableCoexistenceWithOtherVpns(prefs, vpnConnectedOrConnectingCallback)
}

func BestWireguardMtuForConditions() int {
	return implBestWireguardMtuForConditions()
}
