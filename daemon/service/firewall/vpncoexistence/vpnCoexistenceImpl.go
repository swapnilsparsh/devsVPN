// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

//go:build windows
// +build windows

package vpncoexistence

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/windows/svc/mgr"
)

type OtherVpnInfoParsed struct {
	otherVpnKnown bool // true - other VPN known from our DB, false - we guessed service name from other VPN sublayer name

	otherVpnCliFound     bool
	otherVpnWasConnected bool

	scmgr                   *scmanager
	servicesThatWereRunning []*mgr.Service // Windows services, that we know/think belong to the other VPN, that were running at the time of checking

	OtherVpnInfo
}

var ( // TODO FIXME: test
	invalidServiceNamePrefixes mapset.Set[string] = mapset.NewSet[string]("Microsoft", "windefend", "Edge", "Intel")

	FirstWordRE *regexp.Regexp = regexp.MustCompilePOSIX("^[^\\s_\\.-]+") // regexp for the 1st word: "^[^[:space:]_\.-]+"

)

func (otherVpn *OtherVpnInfoParsed) Close() {
	for idx, otherVpnSvc := range otherVpn.servicesThatWereRunning {
		if otherVpnSvc != nil {
			otherVpnSvc.Close()
			otherVpn.servicesThatWereRunning[idx] = nil
		}
	}

	if otherVpn.scmgr != nil {
		otherVpn.scmgr.Close()
		otherVpn.scmgr = nil
	}

	log.Debug("Close() finished for " + otherVpn.name)
}

func (otherVpn *OtherVpnInfoParsed) validateCliPath() (bool, error) {
	if ProgramFiles := os.Getenv("ProgramFiles"); len(ProgramFiles) > 0 {
		otherVpn.cliPath = strings.ReplaceAll(otherVpn.cliPath, "ProgramFiles", ProgramFiles)
		otherVpn.cliPath = strings.ReplaceAll(otherVpn.cliPath, "/", "\\")
	} else {
		return false, log.ErrorE(errors.New("error resolving %ProgramFiles% environment variable"), 0)
	}

	// Check whether CLI .exe exists
	if _, err := os.Stat(otherVpn.cliPath); os.IsNotExist(err) {
		log.Warning(fmt.Sprintf("other VPN '%s' CLI '%s' not found", otherVpn.name, otherVpn.cliPath), 0)
		return false, nil
	}

	return true, nil
}

func OtherVpnIsKnownToUs(otherSublayerGUID syscall.GUID) bool {
	_, found := OtherVpnsBySublayerGUID[otherSublayerGUID]
	return found
}

// ParseOtherVpn returns parsed info for the other VPN, if that other VPN is known to us - otherwise returns nil, nil.
// If otherSublayerGUID is not in our database of other VPNs known to us, but otherSublayerName is provided - we try guessing Windows services that belong to other VPN.
// If otherSublayerName is "", we don't try guessing service names.
func ParseOtherVpn(otherSublayerName string, otherSublayerGUID syscall.GUID) (otherVpn *OtherVpnInfoParsed, err error) {
	var (
		otherVpnInfoParsed *OtherVpnInfoParsed
		firstWord          string
		serviceNameRE      *regexp.Regexp
	)

	otherVpnReadonly, found := OtherVpnsBySublayerGUID[otherSublayerGUID]
	if found {
		otherVpnInfoParsed = &OtherVpnInfoParsed{true, false, false, nil, []*mgr.Service{}, otherVpnReadonly}
	} else if otherSublayerName != "" {
		if firstWord = FirstWordRE.FindString(otherSublayerName); firstWord == "" {
			return nil, nil
		}
		if len(firstWord) <= 4 {
			return nil, log.ErrorE(fmt.Errorf("error - trying to guess service name for other VPN sublayer '%s', but first word '%s' is too short",
				otherSublayerName, firstWord), 0)
		}
		if invalidServiceNamePrefixes.Contains(firstWord) {
			return nil, log.ErrorE(fmt.Errorf("error - first word in the other VPN sublayer name, '%s', is in forbidden list; not using it to guess service names",
				firstWord), 0)
		}
		otherVpnInfoParsed = &OtherVpnInfoParsed{false, false, false, nil, []*mgr.Service{}, OtherVpnInfo{name: otherSublayerName}}
	} else { // VPN is neither known, nor do we have sublayer name to try guessing
		return nil, nil
	}

	// check CLI binary exists
	if otherVpnInfoParsed.otherVpnKnown {
		if otherVpnInfoParsed.otherVpnCliFound, err = otherVpnInfoParsed.validateCliPath(); err != nil {
			return otherVpnInfoParsed, err
		}
	}

	// check whether Windows service(s) exist
	if otherVpnInfoParsed.scmgr, err = OpenSCManager(); err != nil {
		return otherVpnInfoParsed, err
	}
	if otherVpnInfoParsed.otherVpnKnown {
		if service, err := otherVpnInfoParsed.scmgr.OpenServiceIfRunning(otherVpnInfoParsed.serviceName); err != nil {
			return otherVpnInfoParsed, err
		} else if service != nil { // service would be nil if it's not running
			otherVpnInfoParsed.servicesThatWereRunning = append(otherVpnInfoParsed.servicesThatWereRunning, service)
		}
	} else { // other VPN not in our db, so try guessing the Windows service names from the 1st word of the other VPN sublayer name
		if serviceNameRE, err = regexp.CompilePOSIX("(?i)^" + firstWord + ".*"); err != nil { // (?i) for case-insensitive matching
			return otherVpnInfoParsed, log.ErrorE(fmt.Errorf("error compiling regular expression from first word '%s'", firstWord), 0)
		}
		if otherVpnInfoParsed.servicesThatWereRunning, err = otherVpnInfoParsed.scmgr.FindRunningServicesMatchingRegex(serviceNameRE); err != nil {
			return otherVpnInfoParsed, log.ErrorE(fmt.Errorf("error matching service names via regular expression '%s'", serviceNameRE), 0)
		}
	}

	// check whether other VPN was connected
	if otherVpnInfoParsed.otherVpnKnown && otherVpnInfoParsed.otherVpnCliFound {
		otherVpnWasConnectedRegex := regexp.MustCompile(otherVpnInfoParsed.cliCmds.statusConnectedRE)

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
				if otherVpnWasConnectedRegex.MatchString(text) {
					otherVpnInfoParsed.otherVpnWasConnected = true
				}
			}
		}

		if err = shell.ExecAndProcessOutput(log, outProcessFunc, "", otherVpnInfoParsed.cliPath, otherVpnInfoParsed.cliCmds.cmdStatus); err != nil {
			return otherVpnInfoParsed, log.ErrorE(fmt.Errorf("error matching '%s': %s", otherVpnInfoParsed.cliCmds.statusConnectedRE, strErr.String()), 0)
		}
	}

	return otherVpnInfoParsed, nil
}

func (otherVpn *OtherVpnInfoParsed) PreSteps() (retErr error) {
	log.Debug("PreSteps() started for " + otherVpn.name)
	var retErr2 error = nil

	// try to disconnect the other VPN, regardless of the previous state we recorded for it
	// if retErr := shell.Exec(log, otherVpn.cliPath, otherVpn.cliCmds.cmdDisconnect); retErr != nil {
	// 	log.Error(fmt.Errorf("error sending disconnect command to the other VPN '%s': %w", otherVpn.name, retErr))
	// }

	// try to stop the other VPN service(s) that were running
	for _, otherVpnSvc := range otherVpn.servicesThatWereRunning {
		if retErr = StopService(otherVpnSvc); retErr != nil {
			retErr2 = log.ErrorE(fmt.Errorf("error stopping service '%s': %w", otherVpnSvc.Name, retErr), 0)
		} else {
			log.Debug("stopped service '" + otherVpnSvc.Name + "'")
		}
	}

	log.Debug("PreSteps() ended for " + otherVpn.name)

	if retErr != nil {
		return retErr
	} else {
		return retErr2
	}
}

// TODO FIXME: Vlad - implement a deterministic callback for post-steps. WFP transaction starts at implReregisterFirewallAtTopPriority()
func (otherVpn *OtherVpnInfoParsed) PostSteps() {
	log.Debug("PostSteps() started for " + otherVpn.name)

	// func (otherVpn *OtherVpnInfoParsed) postStepsAsync() {
	defer otherVpn.Close()

	// log all the errors here, because the caller won't process them

	// try to stop the other VPN service(s) that were running
	for _, otherVpnSvc := range otherVpn.servicesThatWereRunning {
		if retErr := StartService(otherVpnSvc); retErr != nil {
			log.Error(fmt.Errorf("error starting service '%s': %w", otherVpnSvc.Name, retErr))
		} else {
			log.Debug("started service '" + otherVpnSvc.Name + "'")
		}
	}

	if otherVpn.otherVpnCliFound {
		if retErr := shell.Exec(log, otherVpn.cliPath, otherVpn.cliCmds.cmdEnableSplitTun...); retErr != nil {
			log.Error(fmt.Errorf("error enabling Split Tunnel in other VPN '%s': %w", otherVpn.name, retErr))
		}

		for _, svcExe := range platform.PLServiceBinariesForFirewallToUnblock() {
			cmdWhitelistOurSvcExe := append(otherVpn.cliCmds.cmdAddOurBinaryToSplitTunWhitelist, svcExe)
			if retErr := shell.Exec(log, otherVpn.cliPath, cmdWhitelistOurSvcExe...); retErr != nil {
				log.Error(fmt.Errorf("error adding '%s' to Split Tunnel in other VPN '%s': %w", svcExe, otherVpn.name, retErr))
			}
		}

		if retErr := shell.Exec(log, otherVpn.cliPath, otherVpn.cliCmds.cmdConnect); retErr != nil {
			log.Error(fmt.Errorf("error sending connect command to the other VPN '%s': %w", otherVpn.name, retErr))
		}
	}

	log.Debug("PostSteps() ending for " + otherVpn.name)
}
