// TODO FIXME: prepend license
// Copyright (c) 2024 privateLINE, LLC.

package firewall

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall/winlib"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type OtherVpnInfoParsed struct {
	OtherVpnKnown bool // true - other VPN known from our DB, false - we guessed Windows service name from the other VPN sublayer name

	otherVpnCliFound bool

	scmgr                   *scmanager
	servicesThatWereRunning []*mgr.Service // Windows services, that we know/think belong to the other VPN, that were running at the time of checking

	OtherVpnInfo
}

var (
	ZeroGUID = syscall.GUID{}

	// blacklist of words that can't be brand name candidates
	// Vlad - don't stop services whose name starts with "Wireguard", because we don't want to kill our own connection, lol
	invalidServiceNamePrefixes mapset.Set[string] = mapset.NewSet("microsoft", "windefend", "edge", "intel", "wireguard")

	// Windows service names to try always:

	// SurfShark uses random GUIDs for its sublayer 0xFFFF (named "WireGuard filters") and provider "WireGuard provider", so try its named services always
	// "Surfshark Service", "Surfshark WireGuard"

	// Must keep both lists in sync. otherVpnDefaultServiceNamePrefixesToTry must contain literal words, not regular expressions.
	otherVpnDefaultServiceNamePrefixesToTry mapset.Set[string] = mapset.NewSet("mullvad", "expressvpn", "surfshark", "nord", "proton", "ivpn", "hideme",
		"mozillavpn", "windscribe", "ipvcallout", "ipvan", "cyberghost", "proton", "tunnelbear", "vypervpn", "vyprvpn", "turbovpn", "cloudflarewarp",
		"urbanvpn", "eddieelevation", "hshld", "hotspotshield", "privateinternetaccess", "hola", "avg", "securevpn")
	// (?i) for case-insensitive matching, regex matching group not closed in this string - must be closed where used
	otherVpnDefaultServiceNameBrandsRegexStart = "(?i)^(mullvad|expressvpn|surfshark|nord|proton|ivpn|hideme|mozillavpn|windscribe|ipv(callout|an)|" +
		"cyberghost|proton|tunnelbear|vype?rvpn|turbovpn|cloudflarewarp|urbanvpn|eddie.?elevation|hshld|hotspotshield|privateinternetaccess|" +
		"hola(.?vpn|[^a-z0-9]|$)|.*updater_.*_hola|avg|securevpn"
	otherVpnDefaultServiceNamePrefixesRE = regexp.MustCompile(otherVpnDefaultServiceNameBrandsRegexStart + ")")

	// other VPNs known to us

	// Mullvad
	mullvadSublayerKey = syscall.GUID{Data1: 0xC78056FF, Data2: 0x2BC1, Data3: 0x4211, Data4: [8]byte{0xAA, 0xDD, 0x7F, 0x35, 0x8D, 0xEF, 0x20, 0x2D}}
	mullvadProfile     = OtherVpnInfo{
		name:            "Mullvad VPN",
		namePrefix:      "mullvad",
		cliPathResolved: "ProgramFiles/Mullvad VPN/resources/mullvad.exe",
		cliCmds: otherVpnCliCmds{
			cmdStatus:               "status",
			checkCliConnectedStatus: false,
			statusConnectedRE:       commonStatusConnectedRE, // must be 1st line
			statusDisconnectedRE:    commonStatusDisconnectedRE,

			cmdEnableSplitTun:                      []string{"split-tunnel", "set", "on"},
			cmdAddOurBinaryPathToSplitTunWhitelist: []string{"split-tunnel", "app", "add"},
			cmdConnect:                             "connect",
			cmdDisconnect:                          "disconnect",
		},
	}

	// TODO: NordVPN CLI
	// NordVPN
	nordVpnSublayerKey = syscall.GUID{Data1: 0x92C759E5, Data2: 0x03BA, Data3: 0x41AD, Data4: [8]byte{0xA5, 0x99, 0x68, 0xAF, 0x2C, 0x1A, 0x17, 0xE5}}
	nordVpnProfile     = OtherVpnInfo{
		name:       "NordVPN",
		namePrefix: "nord",
		//cliPathResolved:    "ProgramFiles/NordVPN/NordVPN.exe", // disabled for now, since we didn't find yet a programmatic way to check whether VPN is connected
		cliCmds: otherVpnCliCmds{
			cmdConnect:    "--connect",
			cmdDisconnect: "--disconnect",
		},
	}

	// index (DB) of other VPNs by sublayer key
	otherVpnsBySublayerGUID = map[syscall.GUID]*OtherVpnInfo{
		mullvadSublayerKey: &mullvadProfile,
		nordVpnSublayerKey: &nordVpnProfile,
	}
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
		otherVpn.cliPathResolved = strings.ReplaceAll(otherVpn.cliPathResolved, "ProgramFiles", ProgramFiles)
		otherVpn.cliPathResolved = strings.ReplaceAll(otherVpn.cliPathResolved, "/", "\\")
	} else {
		return false, log.ErrorE(errors.New("error resolving %ProgramFiles% environment variable"), 0)
	}

	// Check whether CLI .exe exists
	if _, err := os.Stat(otherVpn.cliPathResolved); os.IsNotExist(err) {
		log.Warning(fmt.Errorf("other VPN '%s' CLI '%s' not found: %w", otherVpn.name, otherVpn.cliPathResolved, err))
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
func ParseOtherVpnBySublayerGUID(otherSublayerFound bool, otherSublayer *winlib.SubLayer, manager *winlib.Manager) (otherVpnParsed *OtherVpnInfoParsed /*, err error*/) {
	var (
		err                                      error
		otherVpn                                 *OtherVpnInfo
		found                                    bool
		otherVpnProvider                         winlib.ProviderInfo
		otherVpnProviderFound                    bool
		otherVpnInfoParsed                       *OtherVpnInfoParsed
		providerName1stWord, sublayerName1stWord string // used to try to match Windows service names
		serviceNameRegex                         *regexp.Regexp
	)

	if otherVpn, found = otherVpnsBySublayerGUID[otherSublayer.Key]; found { // other VPN found by sublayer ID
		otherVpnInfoParsed = &OtherVpnInfoParsed{true, false, nil, []*mgr.Service{}, *otherVpn}
		_, otherVpnProvider, providerName1stWord = lookupOtherVpnProvider(otherSublayer.ProviderKey, manager) // lookup the other VPN provider for its serviceName
		goto ParseOtherVpn_CheckingStage1_serviceNameRegexPrep
	}

	if !otherSublayerFound { // if VPN is neither known by GUID, nor do we have sublayer (to try guessing by its name and/or its provider name) - we can only try default service names
		log.Error(errors.New("other VPN '" + windows.GUID(otherSublayer.Key).String() + "' is not known to us"))
		otherVpnInfoParsed = &OtherVpnInfoParsed{false, false, nil, []*mgr.Service{}, OtherVpnInfo{name: windows.GUID(otherSublayer.Key).String()}}
		serviceNameRegex = otherVpnDefaultServiceNamePrefixesRE
		goto ParseOtherVpn_CheckingStage2_FindRunningMatchingServices
	}

	otherVpnProviderFound, otherVpnProvider, providerName1stWord = lookupOtherVpnProvider(otherSublayer.ProviderKey, manager) // try to lookup the other VPN provider

	for _, otherVpnReadonly := range otherVpnsBySublayerGUID { // try matching the name of sublayer or provider to name prefix of other VPNs in our DB
		if strings.HasPrefix(strings.ToLower(otherSublayer.Name), otherVpnReadonly.namePrefix) ||
			(otherVpnProviderFound && strings.HasPrefix(strings.ToLower(otherVpnProvider.Name), otherVpnReadonly.namePrefix)) {
			otherVpnInfoParsed = &OtherVpnInfoParsed{true, false, nil, []*mgr.Service{}, *otherVpnReadonly}
			goto ParseOtherVpn_CheckingStage1_serviceNameRegexPrep
		}
	}

	// ok, by now we haven't found the other VPN in our DB - will try to match Windows services by 1st word of sublayer name and/or provider name of the other VPN
	sublayerName1stWord = parseFirstWordOfAName(otherSublayer.Name, "sublayer")
	otherVpnInfoParsed = &OtherVpnInfoParsed{false, false, nil, []*mgr.Service{}, OtherVpnInfo{name: otherSublayer.Name}}

ParseOtherVpn_CheckingStage1_serviceNameRegexPrep:
	if otherVpnInfoParsed.OtherVpnKnown { // other VPN profile known from DB, so match service names only by other VPN name prefix and provider.serviceName
		if serviceNameRegex, err = regexp.Compile("(?i)^" + otherVpn.namePrefix); err != nil { // (?i) for case-insensitive matching
			log.ErrorFE("error compiling regular expression from other VPN name prefix '%s': %w", otherVpn.namePrefix, err)
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
		log.Error(errors.New("error - CLI not found at path '" + otherVpnInfoParsed.cliPathResolved + "'"))
		return otherVpnInfoParsed /*, nil*/
	}

	// check whether other VPN was connected
	if _, err := otherVpn.CheckVpnConnected(); err != nil {
		log.ErrorFE("error otherVpn.CheckVpnConnected(): %w", err)
		return otherVpnInfoParsed
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
		if retErr := shell.Exec(log, otherVpn.cliPathResolved, otherVpn.cliCmds.cmdEnableSplitTun...); retErr != nil {
			log.ErrorFE("error enabling Split Tunnel in other VPN '%s': %w", otherVpn.name, retErr) // and continue
		}

		for _, svcExe := range platform.PLServiceBinariesForFirewallToUnblock() {
			cmdWhitelistOurSvcExe := append(otherVpn.cliCmds.cmdAddOurBinaryPathToSplitTunWhitelist, svcExe)
			if retErr := shell.Exec(log, otherVpn.cliPathResolved, cmdWhitelistOurSvcExe...); retErr != nil {
				log.ErrorFE("error adding '%s' to Split Tunnel in other VPN '%s': %w", svcExe, otherVpn.name, retErr) // and continue
			}
		}

		if retErr := shell.Exec(log, otherVpn.cliPathResolved, otherVpn.cliCmds.cmdConnect); retErr != nil {
			log.Error(fmt.Errorf("error sending connect command to the other VPN '%s': %w", otherVpn.name, retErr))
		}
	}

	log.Debug("PostSteps() ending for " + otherVpn.name)
}

// ================================ Windows service helpers: ================================

// Refer to these code samples:
//	https://learn.microsoft.com/en-us/windows/win32/services/stopping-a-service
//	https://learn.microsoft.com/en-us/windows/win32/services/starting-a-service
//	https://github.com/shirou/gopsutil/blob/master/winservices
//	https://opensource.srlabs.de/projects/srl_gobuster/repository/11/revisions/master/annotate/src/golang.org/x/sys/windows/svc/example/manage.go

type scmanager struct {
	mgr *mgr.Mgr
}

func OpenSCManager() (*scmanager, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	return &scmanager{m}, nil
}

func (sc *scmanager) Close() error {
	return sc.mgr.Disconnect()
}

// OpenServiceIfRunning - returns opened service if its running. Returns (nil, nil), if service is not running, but no errors.
func (sc *scmanager) OpenServiceIfRunning(serviceName string) (service *mgr.Service, err error) {
	if service, err = sc.mgr.OpenService(serviceName); err != nil {
		return nil, err
	}

	// check whether other VPN service was running
	var serviceStatus ServiceStatus
	if serviceStatus, err = QueryServiceStatusEx(service); err != nil {
		service.Close()
		return nil, log.ErrorE(fmt.Errorf("error QueryServiceStatusEx(): %w", err), 0)
	}
	if serviceStatus.State != svc.Running {
		service.Close()
		return nil, nil
	}

	return service, nil
}

// lowercaseSvcNameFromProvider can be ""
// otherVpnSvcNameRE must be configured for case-insensitive matching
func (sc *scmanager) FindMatchingRunningServices(serviceNameFromProvider string, otherVpnSvcNameRE *regexp.Regexp) (servicesRunning []*mgr.Service, err error) {
	servicesRunning = make([]*mgr.Service, 0, 1)

	var svcList []string
	if svcList, err = sc.mgr.ListServices(); err != nil {
		return servicesRunning, err
	}

	lowercaseSvcNameFromProvider := strings.ToLower(serviceNameFromProvider)
	log.Debug("FindMatchingRunningServices(): lowercaseSvcNameFromProvider='" + lowercaseSvcNameFromProvider + "' otherVpnSvcNameRE='" + otherVpnSvcNameRE.String() + "'")
	for _, svcName := range svcList {
		if otherVpnSvcNameRE.MatchString(svcName) || strings.ToLower(svcName) == lowercaseSvcNameFromProvider {
			if svc, err := sc.OpenServiceIfRunning(svcName); err != nil {
				log.ErrorFE("error opening service '%s': %w", svcName, err)
			} else if svc != nil {
				servicesRunning = append(servicesRunning, svc)
				// if len(servicesRunning) >= MAX_WINDOWS_SERVICE_CANDIDATES {
				// 	return servicesRunning, nil
				// }
			}
		}
	}

	return servicesRunning, nil
}

// ServiceStatus combines State and Accepted commands to fully describe running service.
type ServiceStatus struct {
	State         svc.State
	Accepts       svc.Accepted
	Pid           uint32
	Win32ExitCode uint32
}

// QueryServiceStatusEx return the specified name service currentState and ControlsAccepted
func QueryServiceStatusEx(service *mgr.Service) (ServiceStatus, error) {
	var p *windows.SERVICE_STATUS_PROCESS
	var bytesNeeded uint32
	var buf []byte

	if err := windows.QueryServiceStatusEx(service.Handle, windows.SC_STATUS_PROCESS_INFO, nil, 0, &bytesNeeded); err != windows.ERROR_INSUFFICIENT_BUFFER {
		return ServiceStatus{}, err
	}

	buf = make([]byte, bytesNeeded)
	p = (*windows.SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceStatusEx(service.Handle, windows.SC_STATUS_PROCESS_INFO, &buf[0], uint32(len(buf)), &bytesNeeded); err != nil {
		return ServiceStatus{}, err
	}

	return ServiceStatus{
		State:         svc.State(p.CurrentState),
		Accepts:       svc.Accepted(p.ControlsAccepted),
		Pid:           p.ProcessId,
		Win32ExitCode: p.Win32ExitCode,
	}, nil
}

// Making a copy of Control(), because we need waitHint for this particular command
// func controlServiceExt(s *mgr.Service, c svc.Cmd) (svc.Status, error) {
// 	var t windows.SERVICE_STATUS
// 	err := windows.ControlService(s.Handle, uint32(c), &t)
// 	if err != nil &&
// 		err != windows.ERROR_INVALID_SERVICE_CONTROL &&
// 		err != windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL &&
// 		err != windows.ERROR_SERVICE_NOT_ACTIVE {
// 		return svc.Status{}, err
// 	}
// 	return svc.Status{
// 		State:    svc.State(t.CurrentState),
// 		Accepts:  svc.Accepted(t.ControlsAccepted),
// 		WaitHint: t.WaitHint,
// 	}, err
// }

func controlService(s *mgr.Service, c svc.Cmd, to svc.State) error {
	status, err := s.Control(c)
	if err != nil {
		return fmt.Errorf("could not send control=%d: %v", c, err)
	}

	timeout := time.Now().Add(MAX_WAIT)
	for status.State != to {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for service to go to state=%d", to)
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("could not retrieve service status: %v", err)
		}
	}
	return nil
}

func StopService(s *mgr.Service) error {
	serviceStatus, err := QueryServiceStatusEx(s)
	// log.Debug("service '" + s.Name + "' state queried")
	if err != nil {
		return log.ErrorE(fmt.Errorf("error QueryServiceStatusEx(): %w", err), 0)
	}

	if serviceStatus.State == svc.Stopped {
		log.Debug(fmt.Sprintf("service '%s' already stopped", s.Name))
		return nil
	}

	// TODO wait for StopPending?

	return controlService(s, svc.Stop, svc.Stopped)
}

func StartService(s *mgr.Service) error {
	serviceStatus, err := QueryServiceStatusEx(s)
	if err != nil {
		return log.ErrorE(fmt.Errorf("error QueryServiceStatusEx(): %w", err), 0)
	}

	if serviceStatus.State == svc.Running {
		log.Debug(fmt.Sprintf("service '%s' already running", s.Name))
		return nil
	}

	return s.Start()
}

func implBestWireguardMtuForConditions() (recommendedMTU int, retErr error) {
	return platform.WGDefaultMTU(), nil
}
