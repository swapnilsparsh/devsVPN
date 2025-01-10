// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

//go:build windows
// +build windows

package vpncoexistence

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall/winlib"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

type OtherVpnInfoParsed struct {
	OtherVpnKnown bool // true - other VPN known from our DB, false - we guessed Windows service name from the other VPN sublayer name

	otherVpnCliFound     bool
	otherVpnWasConnected bool

	scmgr                   *scmanager
	servicesThatWereRunning []*mgr.Service // Windows services, that we know/think belong to the other VPN, that were running at the time of checking

	OtherVpnInfo
}

var (
	FirstWordRE *regexp.Regexp = regexp.MustCompilePOSIX("^[^[:space:]_\\.-]+") // regexp for the 1st word: "^[^[:space:]_\.-]+"
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
		log.Warning(fmt.Errorf("other VPN '%s' CLI '%s' not found: %w", otherVpn.name, otherVpn.cliPath, err))
		return false, nil
	}

	return true, nil
}

// parseFirstWordOfAName - will try to extract 1st word of a name, will return it lowercased. Will return "" on error.
func parseFirstWordOfAName(name, label string) (firstWord string) {
	if firstWord = strings.ToLower(FirstWordRE.FindString(name)); firstWord == "" { // extract 1st word of sublayer name
		log.ErrorFE("error parsing 1st word from other VPN %s name '%s'", label, name)
		return ""
	}
	if len(firstWord) < MIN_BRAND_FIRST_WORD_LEN {
		log.Warning("warning - trying to guess service name for other VPN " + label + " name '" + name + "', but first word '" + firstWord + "' is too short, ignoring")
		return ""
	}
	if invalidServiceNamePrefixes.Contains(firstWord) {
		log.Warning("warning - first word in the other VPN " + label + " name, '" + firstWord + "', is in forbidden list, ignoring")
		return ""
	}
	return firstWord
}

func lookupOtherVpnProvider(otherVpnProviderKey syscall.GUID, manager *winlib.Manager) (otherVpnProviderFound bool, otherVpnProvider winlib.ProviderInfo, otherVpnProviderName1stWord string) {
	var err error

	if reflect.DeepEqual(otherVpnProviderKey, ZeroGUID) {
		log.Warning(errors.New("warning - provider key/UUID is zeroes, ignoring it"))
		return false, winlib.ProviderInfo{}, ""
	}

	if otherVpnProviderFound, otherVpnProvider, err = manager.GetProviderInfo(otherVpnProviderKey); err != nil { // lookup provider under which other VPN's sublayer is installed
		log.ErrorFE("error looking up info for provider of the other VPN by its key '%s': %w", windows.GUID(otherVpnProviderKey).String(), err) // and continue
	} else if otherVpnProviderFound { // try to extract 1st word of provider name
		otherVpnProviderName1stWord = parseFirstWordOfAName(otherVpnProvider.Name, "provider")
	}

	return otherVpnProviderFound, otherVpnProvider, otherVpnProviderName1stWord
}

// otherSublayer.Key must be populated with other sublayer GUID, regardless of whether otherSublayerFound is true or not
//
// Windows service matching logic:
// (1) Try to find the other VPN in our DB via sublayer GUID, or sublayer name, or provider name. Also try to make use of provider.serviceName.
// (2) Else look for Windows services whose names start with name prefix of any VPN known to us. Also try to make use of provider.serviceName.
// (3) Else try the list of default service name prefixes, contanining common VPN name brand names.
func ParseOtherVpn(otherSublayerFound bool, otherSublayer *winlib.SubLayer, manager *winlib.Manager) (otherVpn *OtherVpnInfoParsed /*, err error*/) {
	var (
		err                                      error
		otherVpnReadonly                         *OtherVpnInfo
		found                                    bool
		otherVpnProvider                         winlib.ProviderInfo
		otherVpnProviderFound                    bool
		otherVpnInfoParsed                       *OtherVpnInfoParsed
		providerName1stWord, sublayerName1stWord string // used to try to match Windows service names
		serviceNameRegex                         *regexp.Regexp
	)

	if otherVpnReadonly, found = otherVpnsBySublayerGUID[otherSublayer.Key]; found { // other VPN found by sublayer ID
		otherVpnInfoParsed = &OtherVpnInfoParsed{true, false, false, nil, []*mgr.Service{}, *otherVpnReadonly}
		_, otherVpnProvider, providerName1stWord = lookupOtherVpnProvider(otherSublayer.ProviderKey, manager) // lookup the other VPN provider for its serviceName
		goto ParseOtherVpn_CheckingStage1_serviceNameRegexPrep
	}

	if !otherSublayerFound { // if VPN is neither known by GUID, nor do we have sublayer (to try guessing by its name and/or its provider name) - we can only try default service names
		log.Error(errors.New("other VPN '" + windows.GUID(otherSublayer.Key).String() + "' is not known to us"))
		otherVpnInfoParsed = &OtherVpnInfoParsed{false, false, false, nil, []*mgr.Service{}, OtherVpnInfo{name: windows.GUID(otherSublayer.Key).String()}}
		serviceNameRegex = otherVpnDefaultServiceNamePrefixesRE
		goto ParseOtherVpn_CheckingStage2_FindRunningMatchingServices
	}

	otherVpnProviderFound, otherVpnProvider, providerName1stWord = lookupOtherVpnProvider(otherSublayer.ProviderKey, manager) // try to lookup the other VPN provider

	for _, otherVpnReadonly := range otherVpnsBySublayerGUID { // try matching the name of sublayer or provider to name prefix of other VPNs in our DB
		if strings.HasPrefix(strings.ToLower(otherSublayer.Name), otherVpnReadonly.namePrefix) ||
			(otherVpnProviderFound && strings.HasPrefix(strings.ToLower(otherVpnProvider.Name), otherVpnReadonly.namePrefix)) {
			otherVpnInfoParsed = &OtherVpnInfoParsed{true, false, false, nil, []*mgr.Service{}, *otherVpnReadonly}
			goto ParseOtherVpn_CheckingStage1_serviceNameRegexPrep
		}
	}

	// ok, by now we haven't found the other VPN in our DB - will try to match Windows services by 1st word of sublayer name and/or provider name of the other VPN
	sublayerName1stWord = parseFirstWordOfAName(otherSublayer.Name, "sublayer")
	otherVpnInfoParsed = &OtherVpnInfoParsed{false, false, false, nil, []*mgr.Service{}, OtherVpnInfo{name: otherSublayer.Name}}

ParseOtherVpn_CheckingStage1_serviceNameRegexPrep:
	if otherVpnInfoParsed.OtherVpnKnown { // other VPN profile known from DB, so match service names only by other VPN name prefix and provider.serviceName
		if serviceNameRegex, err = regexp.Compile("(?i)^" + otherVpnReadonly.namePrefix); err != nil { // (?i) for case-insensitive matching
			log.ErrorFE("error compiling regular expression from other VPN name prefix '%s': %w", otherVpnReadonly.namePrefix, err)
			goto ParseOtherVpn_CheckingStage3_processCLI
		}
	} else { // Other VPN not in our DB, so try matching the Windows service names against the list of default service name prefixes
		serviceNameRegexStr := otherVpnDefaultServiceNameBrandsRegexStart

		// ... also try matching by 1st word of the other VPN sublayer name, provider name, if we know them
		if sublayerName1stWord != "" && !otherVpnDefaultServiceNamePrefixesToTry.Contains(sublayerName1stWord) {
			serviceNameRegexStr += sublayerName1stWord + "|"
		}
		if providerName1stWord != "" && !otherVpnDefaultServiceNamePrefixesToTry.Contains(providerName1stWord) {
			serviceNameRegexStr += providerName1stWord + "|"
		}

		// clip the trailing '|' and close regular expression
		serviceNameRegexStr = serviceNameRegexStr[:len(serviceNameRegexStr)-1] + ")"

		if serviceNameRegex, err = regexp.Compile(serviceNameRegexStr); err != nil { // (?i) for case-insensitive matching
			log.ErrorFE("error compiling regular expression '%s' when other VPN is unknown: %w", serviceNameRegexStr, err)
			goto ParseOtherVpn_CheckingStage3_processCLI
		}
	}

ParseOtherVpn_CheckingStage2_FindRunningMatchingServices:
	if otherVpnInfoParsed.scmgr, err = OpenSCManager(); err != nil {
		log.ErrorFE("error opening SCManager: %w", err)
	} else if otherVpnInfoParsed.servicesThatWereRunning, err = otherVpnInfoParsed.scmgr.FindMatchingRunningServices(otherVpnProvider.ServiceName, serviceNameRegex); err != nil {
		log.ErrorFE("error matching service names via regular expression '%s': %w", serviceNameRegex, err)
	}

ParseOtherVpn_CheckingStage3_processCLI:
	if otherVpnInfoParsed.otherVpnCliFound, err = otherVpnInfoParsed.validateCliPath(); err != nil { // check CLI binary exists
		log.ErrorFE("error validating CLI path: %w", err)
		return otherVpnInfoParsed /*, nil*/
	} else if !otherVpnInfoParsed.otherVpnCliFound {
		log.Error(errors.New("error - CLI not found at path '" + otherVpnInfoParsed.cliPath + "'"))
		return otherVpnInfoParsed /*, nil*/
	}

	// check whether other VPN was connected
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
		log.ErrorFE("error matching '%s': %s", otherVpnInfoParsed.cliCmds.statusConnectedRE, strErr.String())
	}

	return otherVpnInfoParsed /*, nil*/
}

func startStopServiceHelper(stopSvc bool, svc *mgr.Service, reportChan chan error) {
	//log.Debug("VPN service '" + svc.Name + "' action stop=" + strconv.FormatBool(stopSvc) + " ...")
	var err error
	if stopSvc {
		err = StopService(svc)
	} else {
		err = StartService(svc)
	}

	if err == nil {
		log.Debug("VPN service '" + svc.Name + "' action stop=" + strconv.FormatBool(stopSvc) + " success")
		reportChan <- nil
	} else {
		reportChan <- log.ErrorFE("VPN service '%s' action stop=%t error: %w", svc.Name, stopSvc, err)
	}
}

func (otherVpn *OtherVpnInfoParsed) PreSteps() (retErr error) {
	log.Debug("PreSteps() started for " + otherVpn.name)
	var retErr2 error = nil

	// try to disconnect the other VPN, regardless of the previous state we recorded for it
	// if retErr := shell.Exec(log, otherVpn.cliPath, otherVpn.cliCmds.cmdDisconnect); retErr != nil {
	// 	log.Error(fmt.Errorf("error sending disconnect command to the other VPN '%s': %w", otherVpn.name, retErr))
	// }

	// try to stop the other VPN service(s) that were running
	reportChan := make(chan error)
	defer close(reportChan)
	for _, otherVpnSvc := range otherVpn.servicesThatWereRunning {
		go startStopServiceHelper(true, otherVpnSvc, reportChan)
	}
	for i := 0; i < len(otherVpn.servicesThatWereRunning); i++ {
		if retErr3 := <-reportChan; retErr2 == nil && retErr3 != nil { // error or success is already logged in the helper
			retErr2 = retErr3
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

	// try to start the other VPN service(s) that were running
	reportChan := make(chan error)
	defer close(reportChan)
	for _, otherVpnSvc := range otherVpn.servicesThatWereRunning {
		go startStopServiceHelper(false, otherVpnSvc, reportChan)
	}
	for i := 0; i < len(otherVpn.servicesThatWereRunning); i++ {
		<-reportChan // error or success is already logged in the helper
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
