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

	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type OtherVpnInfoParsed struct {
	otherVpnCliFound     bool
	otherVpnWasConnected bool

	scmgr                     *scmanager
	service                   *mgr.Service
	otherVpnServiceWasRunning bool

	OtherVpnInfo
}

func (otherVpn *OtherVpnInfoParsed) Close() {
	if otherVpn.service != nil {
		otherVpn.service.Close()
		otherVpn.service = nil
	}

	if otherVpn.scmgr != nil {
		otherVpn.scmgr.Close()
		otherVpn.scmgr = nil
	}
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

// ParseOtherVpn returns parsed info for the other VPN, if that other VPN is known to us - otherwise returns nil, nil
func ParseOtherVpn(otherSublayerGUID syscall.GUID) (otherVpn *OtherVpnInfoParsed, err error) {
	otherVpnReadonly, found := OtherVpnsBySublayerGUID[otherSublayerGUID]
	if !found {
		return nil, nil
	}

	otherVpnInfoParsed := &OtherVpnInfoParsed{false, false, nil, nil, false, otherVpnReadonly}

	// check CLI binary exists
	if otherVpnInfoParsed.otherVpnCliFound, err = otherVpnInfoParsed.validateCliPath(); err != nil {
		return otherVpnInfoParsed, err
	}

	// check Windows service exists
	if otherVpnInfoParsed.scmgr, err = OpenSCManager(); err != nil {
		return otherVpnInfoParsed, err
	}
	if otherVpnInfoParsed.service, err = otherVpnInfoParsed.scmgr.mgr.OpenService(otherVpnInfoParsed.serviceName); err != nil {
		return otherVpnInfoParsed, err
	}

	// check whether other VPN was connected
	if otherVpnInfoParsed.otherVpnCliFound {
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

	// check whether other VPN service was running
	if otherVpnInfoParsed.service != nil {
		//
		var serviceStatus ServiceStatus
		serviceStatus, err = QueryServiceStatusEx(otherVpnInfoParsed.service)
		if err != nil {
			return otherVpnInfoParsed, log.ErrorE(fmt.Errorf("error QueryServiceStatusEx(): %w", err), 0)
		}
		otherVpnInfoParsed.otherVpnServiceWasRunning = (serviceStatus.State == svc.Running)
	}

	return otherVpnInfoParsed, nil
}

func (otherVpn *OtherVpnInfoParsed) PreSteps() (retErr error) {
	// try to disconnect the other VPN, regardless of the previous state we recorded for it
	// if retErr := shell.Exec(log, otherVpn.cliPath, otherVpn.cliCmds.cmdDisconnect); retErr != nil {
	// 	log.Error(fmt.Errorf("error sending disconnect command to the other VPN '%s': %w", otherVpn.name, retErr))
	// }

	// try to stop the other VPN service, regardless of the previous state we recorded for it
	if retErr = StopService(otherVpn.service); retErr != nil {
		retErr = log.ErrorE(fmt.Errorf("error stopping service '%s': %w", otherVpn.service.Name, retErr), 0)
	}

	return retErr
}

// For initial implementation we run post-steps asyncronously, because the WFP transaction hasn't settled yet on the main thread -
// so restarting the other VPN service will block on that. Starting Windows service hopefully has a timeout of 10sec or so, so async should work out.
// TODO FIXME: Vlad - implement a deterministic callback for post-steps. WFP transaction starts at implReregisterFirewallAtTopPriority()
func (otherVpn *OtherVpnInfoParsed) PostSteps() {
	// 	go otherVpn.postStepsAsync()
	// }

	// func (otherVpn *OtherVpnInfoParsed) postStepsAsync() {
	defer otherVpn.Close()

	// log all the errors here, because the caller won't process them

	if !otherVpn.otherVpnServiceWasRunning {
		return
	}

	if retErr := StartService(otherVpn.service); retErr != nil {
		log.Error(fmt.Errorf("error starting service '%s': %w", otherVpn.service.Name, retErr))
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
}
