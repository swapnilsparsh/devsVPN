//
//  Daemon for IVPN Client Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Created by Stelnykovych Alexandr.
//  Copyright (c) 2023 IVPN Limited.
//
//  This file is part of the Daemon for IVPN Client Desktop.
//
//  The Daemon for IVPN Client Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The Daemon for IVPN Client Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the Daemon for IVPN Client Desktop. If not, see <https://www.gnu.org/licenses/>.
//

//go:build linux
// +build linux

package splittun

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"

	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
)

var (
	mutexSplittunLin sync.Mutex

	// error describing details if functionality not available
	funcNotAvailableError        error
	inverseModeNotAvailableError error
	stScriptPath                 string
	sysctlPath                   string = "/sbin/sysctl"
	fullTunnelEnabled            bool   = false

	// map from INET type (IPv4 or IPv6) to default routes (all zeroes)
	DefaultRoutesByIpFamily = map[uint16]*net.IPNet{}
)

// Information about added running process to the ST (by implAddPid())
// (map[<PID>]<command>)
var _addedRootProcesses map[int]string = map[int]string{}

const stPidsFile = "/sys/fs/cgroup/net_cls/ivpn-exclude/cgroup.procs"

func implInitialize() error {
	funcNotAvailableError = nil

	snapEvs := platform.GetSnapEnvs()
	if snapEvs != nil {
		funcNotAvailableError = fmt.Errorf("Split-Tunnelling not applicable out from snap sandbox")
		return funcNotAvailableError
	}

	stScriptPath = platform.SplitTunScript()
	if len(stScriptPath) <= 0 {
		funcNotAvailableError = fmt.Errorf("Split-Tunnelling script is not defined")
		return funcNotAvailableError
	}

	// Hardcoded text for detection of inverse mode not available error
	const inverseModeErrorDetectionText = "Warning: Inverse mode for IVPN Split Tunnel functionality is not applicable."
	inverseModeNotAvailableError = fmt.Errorf("%s", inverseModeErrorDetectionText)
	// check if ST functionality accessible
	// outProcessFunc := func(text string, isError bool) {
	// 	if strings.HasPrefix(text, inverseModeErrorDetectionText) {
	// 		text = strings.TrimSpace(strings.TrimPrefix(text, "Warning: "))
	// 		inverseModeNotAvailableError = fmt.Errorf("%s", text)
	// 		log.Warning(text)
	// 		return
	// 	}
	// 	if isError {
	// 		log.Error("Split Tunnel test: " + text)
	// 	} else {
	// 		log.Info("Split Tunnel test: " + text)
	// 	}
	// }
	// err := shell.ExecAndProcessOutput(nil, outProcessFunc, "", stScriptPath, "test")
	// if err != nil {
	// 	funcNotAvailableError = err
	// }

	// Ensure that ST is enabled on daemon startup?
	// if err := implApplyConfig(true, false, false, false, ConfigAddresses{}, []string{}); err != nil {
	// 	log.Error(fmt.Errorf("error implApplyConfig() on startup: %w", err))
	// }

	if _, defaultRouteIPv4IPNet, err := net.ParseCIDR(defaultRouteIPv4); err != nil {
		return log.ErrorE(fmt.Errorf("error net.ParseCIDR(%s): %w", defaultRouteIPv4, err), 0)
	} else {
		DefaultRoutesByIpFamily[AF_INET] = defaultRouteIPv4IPNet
	}
	if _, defaultRouteIPv6IPNet, err := net.ParseCIDR(defaultRouteIPv6); err != nil {
		return log.ErrorE(fmt.Errorf("error net.ParseCIDR(%s): %w", defaultRouteIPv6, err), 0)
	} else {
		DefaultRoutesByIpFamily[AF_INET6] = defaultRouteIPv6IPNet
	}

	// Register network change detector - we're using net_change_detector_linux now
	/*//
	// The OS is erasing routing rules for ST each time when main network interface disappears
	// (for example, when reconnecting WiFi)
	// Therefore, we must monitor changes in network configuration and update ST routing rules.
	if funcNotAvailableError == nil {
		onNetChange := make(chan struct{}, 1)
		if err := netlink_oshelper.RegisterLanChangeListener(onNetChange); err != nil {
			return err
		}
		// Wait for network chnages in sepatate routine
		go func() {
			var timerDelay *time.Timer
			for {
				<-onNetChange
				if timerDelay != nil {
					timerDelay.Stop()
				}
				// We can receive many 'lan change' events in a short period of time
				// but we update routes not more often than once per 2 seconds.
				timerDelay = time.AfterFunc(time.Second*2, func() {
					//err := shell.Exec(nil, stScriptPath, "update-routes")
					// if err != nil {
					// 	log.Error("failed to update routes for SplitTunneling functionality")
					// }
				})
			}
		}()
	}*/

	return funcNotAvailableError
}

func implFuncNotAvailableError() (generalStError, inversedStError error) {
	return funcNotAvailableError, inverseModeNotAvailableError
}

func implReset() error {
	// Vlad: parent Reset() call is disabled for now
	return nil

	// log.Info("Removing all PIDs")
	// return shell.Exec(nil, stScriptPath, "reset")
}

/*
func implApplyConfig(isStEnabled, isStInversed, isStInverseAllowWhenNoVpn, isVpnEnabled bool, addrConfig ConfigAddresses, splitTunnelApps []string) error {
	// If VPN does not support IPv6 - block IPv6 connectivity for 'splitted' apps in inverse mode
	vpnNoIPv6 := false
	if isVpnEnabled && len(addrConfig.IPv6Tunnel) == 0 {
		vpnNoIPv6 = true
	}

	err := enable(isStEnabled, isStInversed, isStInverseAllowWhenNoVpn, isVpnEnabled, vpnNoIPv6)
	if err != nil {
		log.Error(err)
	}
	return err
}
*/

func implApplyConfig(isStEnabled, isStInversed, isStInverseAllowWhenNoVpn, isVpnEnabled bool, addrConfig ConfigAddresses, splitTunnelApps []string) error {
	mutexSplittunLin.Lock()
	defer mutexSplittunLin.Unlock()

	fullTunnelEnabled = isVpnEnabled && !isStEnabled

	ipv4RespChan := make(chan error)
	go enableDisableSplitTunnelIPv4(fullTunnelEnabled, addrConfig.IPv4Endpoint, ipv4RespChan)
	ipv6RespChan := make(chan error)
	go enableDisableSplitTunnelIPv6(fullTunnelEnabled, ipv6RespChan)

	err4 := <-ipv4RespChan
	err6 := <-ipv6RespChan

	if err4 != nil {
		return err4
	} else {
		return err6
	}
}

func enableDisableSplitTunnelIPv4(enableFullTunnel bool, wgEndpoint net.IP, responseChan chan<- error) {
	var (
		dstOld net.IP
		dstNew *net.IPNet
	)

	defaultRoute := DefaultRoutesByIpFamily[AF_INET]

	if enableFullTunnel { // if enabling full tunnel (total shield)
		dstOld = defaultRoute.IP // ... then change from all-zeros default route destination

		wgEndpointCIDR := fmt.Sprintf("%s/%d", wgEndpoint, addrSizesByIpFamily[AF_INET])
		if _, wgEndpointIPNet, err := net.ParseCIDR(wgEndpointCIDR); err != nil {
			responseChan <- log.ErrorE(fmt.Errorf("error in net.ParseCIDR(%s): %w", wgEndpointCIDR, err), 0)
			return
		} else { // if enabling split tunnel - we reset full tunnel (total shield) customized routes back to default routes
			dstNew = wgEndpointIPNet // ... to allow only our Wireguard endpoint on the given route
		}

		lastConfiguredEndpoints[AF_INET] = &wgEndpoint // save the last configured Wireguard VPN endpoint
	} else {
		dstOld = wgEndpoint   // ... then change from our Wireguard endpoint on the matching routes
		dstNew = defaultRoute // ... back to all-zeros default route destination
	}
	if dstOld.Equal(dstNew.IP) {
		responseChan <- log.ErrorE(fmt.Errorf("unexpected condition: dstOld == dstNew.IP == %s", dstOld), 0)
		return
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		responseChan <- log.ErrorE(fmt.Errorf("netlink.RouteList failed: %w", err), 0)
		return
	}

	for _, routeOld := range routes {
		if (routeOld.Dst == nil && dstOld.Equal(defaultRoute.IP)) || (routeOld.Dst != nil && dstOld.Equal(routeOld.Dst.IP)) {
			routeNew := routeOld
			if err := netlink.RouteDel(&routeOld); err != nil {
				responseChan <- log.ErrorE(fmt.Errorf("error in netlink.RouteDel(). routeOld=%#v. Error=%w", routeOld, err), 0)
				return
			}
			routeNew.Dst = dstNew
			if err := netlink.RouteAdd(&routeNew); err != nil {
				log.Warning(fmt.Errorf("netlink.RouteAdd() failed, duplicate route already exists - skipping route creation. routeNew=%#v. Error=%w", routeNew, err), 0)
			}
		}
	}

	responseChan <- nil
}

func enableDisableSplitTunnelIPv6(enableFullTunnel bool, responseChan chan<- error) {
	var disableIPv6 string
	if enableFullTunnel {
		disableIPv6 = "=1"
	} else {
		disableIPv6 = "=0"
	}

	for _, argPfx := range []string{"net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"} {
		arg := argPfx + disableIPv6
		_, outErrText, _, _, err := shell.ExecAndGetOutput(log, 1024, "", sysctlPath, "-w", arg)
		if err != nil {
			if len(outErrText) > 0 {
				err = fmt.Errorf("(%w) %s", err, outErrText)
			}
			responseChan <- log.ErrorE(fmt.Errorf("enableDisableSplitTunnelIPv6(enableFullTunnel=%t) failed: arg='%s';. Error=%w", enableFullTunnel, arg, err), 0)
			return
		}
	}

	responseChan <- nil
}

func implAddPid(pid int, commandToExecute string) error {
	// Vlad - disabled
	return nil

	if pid <= 0 {
		return fmt.Errorf("PID is not defined")
	}
	log.Info(fmt.Sprintf("Adding PID:%d", pid))

	enabled, err := isEnabled()
	if err != nil {
		return fmt.Errorf("unable to check Split Tunnel status")
	}
	if !enabled {
		return fmt.Errorf("the Split Tunnel is disabled")
	}

	err = shell.Exec(nil, stScriptPath, "addpid", strconv.Itoa(pid))
	if err == nil {
		_addedRootProcesses[pid] = commandToExecute
	}
	return err
}

func implRemovePid(pid int) error {
	// Vlad - disabled
	return nil

	if pid <= 0 {
		return fmt.Errorf("PID is not defined")
	}
	var retErr error

	// Remove PID and all it's child processes
	pids := make(map[int]struct{}, 0)
	pids[pid] = struct{}{}

	// looking for all childs
	if runningApps, err := implGetRunningApps(); err == nil {
		allPids := make(map[int]RunningApp, len(runningApps))
		for _, app := range runningApps {
			allPids[app.Pid] = app
		}

		for _, app := range runningApps {
			if isChildOf(app, pid, allPids) {
				pids[app.Pid] = struct{}{}
			}
		}
	} else {
		retErr = err
	}

	// remove all required pids
	for pidToRemove := range pids {
		log.Info(fmt.Sprintf("Removing PID:%d", pidToRemove))
		err := shell.Exec(nil, stScriptPath, "removepid", strconv.Itoa(pidToRemove))
		if err != nil && retErr == nil {
			retErr = err
		}
		if err == nil {
			delete(_addedRootProcesses, pidToRemove)
		}
	}
	return retErr
}

func implGetRunningApps() (allProcesses []RunningApp, err error) {
	// Vlad - disabled
	return []RunningApp{}, nil

	// https://man7.org/linux/man-pages/man5/proc.5.html

	// read all PIDs which are active in ST environment
	bytes, err := os.ReadFile(stPidsFile)
	if err != nil {
		return nil, err
	}

	pidStrings := strings.Split(string(bytes), "\n")
	retMapAll := make(map[int]RunningApp, len(pidStrings))
	regexpStat := regexp.MustCompile(`^([0-9]*) (\([\S ]*\)) \S ([0-9]+) ([0-9]+) ([0-9]+)`)

	for _, s := range pidStrings {
		if len(s) <= 0 {
			continue
		}

		pid, err := strconv.Atoi(s)
		if err != nil {
			log.Warning(err)
			continue
		}

		// read PPID, ProgessGroup, Session for each pid
		ppid := 0
		statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			log.Warning(err)
		} else {
			statCols := regexpStat.FindStringSubmatch(string(statBytes))
			if len(statCols) >= 4 {
				if v, err := strconv.Atoi(statCols[3]); err == nil {
					ppid = v
				}
			}
		}

		// Read the actual pathname of the executed command
		exe := ""
		if sl, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && len(sl) > 0 {
			exe = sl
		}

		// read cmdline for each pid
		cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			log.Warning(err)
			continue
		}
		for i, b := range cmdlineBytes {
			if b == 0 {
				cmdlineBytes[i] = ' '
			}
		}
		cmdline := string(cmdlineBytes)
		// TODO: do not forget update prefixes to trim in case if privateLINE CLI arguments change name ('exclude' or 'splittun -execute')
		cmdline = strings.TrimPrefix(cmdline, "/usr/bin/ivpn exclude ")
		cmdline = strings.TrimPrefix(cmdline, "/usr/bin/ivpn splittun -execute ")
		cmdline = strings.TrimPrefix(cmdline, "ivpn exclude ")
		cmdline = strings.TrimPrefix(cmdline, "ivpn splittun -execute ")
		cmdline = strings.TrimSpace(cmdline)
		retMapAll[pid] = RunningApp{
			Pid:     pid,
			Ppid:    ppid,
			Cmdline: cmdline,
			Exe:     exe}
	}

	// remove from _addedRootProcesses PIDs which are not exists anumore
	diedRootPids := make(map[int]string, 0)
	for rootPid, rootCmd := range _addedRootProcesses {
		if _, ok := retMapAll[rootPid]; !ok {
			diedRootPids[rootPid] = rootCmd
		}
	}
	for diedPid := range diedRootPids {
		delete(_addedRootProcesses, diedPid)

		// Find new root pid for current command (if exists)
		// As new root pid will be used process with minimal PID which have ExtIvpnRootPid same as deleted PID
	}

	detachedProcessesMinPid := make(map[int]int) // map[<rootPidFromEnvVar>]<pid>

	// mark required elements as 'ExtIvpnRootPid'
	for pid, value := range retMapAll {
		if rootPid, isKnown := getRootPid(value, retMapAll); isKnown {
			value.ExtIvpnRootPid = rootPid
		}

		if value.ExtIvpnRootPid == 0 {
			// Could happen a situations when we can not to determine to which command the process belongs.
			// It occurs when ppid->pid->... sequence not ending by any element from '_addedRootProcesses'.
			// In such situations, we are trying to read environment variable 'IVPN_STARTED_ST_ID' of that process,
			// it contains the PID of the initial (root) process.
			// The IVPN CLI sets this variable for each process it starting in ST environment.
			pidEnv, err := readProcEnvVarIvpnId(value.Pid)
			if err != nil {
				log.Warning(err)
			} else {
				if _, ok := _addedRootProcesses[pidEnv]; ok {
					value.ExtIvpnRootPid = pidEnv
				} else {
					// For the situations when the root process id not exist anymore -
					// mark as root a process with minimum PID which has correspond value of IVPN_STARTED_ST_ID
					// Here we are looking for a minimal PID.
					if minPid, ok := detachedProcessesMinPid[pidEnv]; ok {
						if minPid > pid {
							detachedProcessesMinPid[pidEnv] = pid
						}
					} else {
						detachedProcessesMinPid[pidEnv] = pid
					}
				}
			}
		}

		retMapAll[pid] = value
	}

	// For the situations when the root process id not exist anymore -
	// mark as root a process with minimum PID which has correspond value of IVPN_STARTED_ST_ID
	for rootPidEnv, pid := range detachedProcessesMinPid {
		if diedRootCmd, ok := diedRootPids[rootPidEnv]; ok {
			proc := retMapAll[pid]
			retMapAll[pid] = proc
			_addedRootProcesses[proc.Pid] = diedRootCmd
		}
		for pid, value := range retMapAll {
			if value.ExtIvpnRootPid > 0 {
				continue
			}
			if rootPid, isKnown := getRootPid(value, retMapAll); isKnown {
				value.ExtIvpnRootPid = rootPid
				retMapAll[pid] = value
			}
		}
	}

	// make result slice
	retAll := make([]RunningApp, 0, len(retMapAll))
	for _, value := range retMapAll {
		// for known root processes - replace command by the original command used to run process
		if cmdLine, ok := _addedRootProcesses[value.Pid]; ok {
			value.ExtModifiedCmdLine = cmdLine
		}

		retAll = append(retAll, value)
	}
	return retAll, nil
}

func isEnabled() (bool, error) {
	return !fullTunnelEnabled, nil

	// err := shell.Exec(nil, stScriptPath, "status")
	// if err != nil {
	// 	return false, nil
	// }
	// return true, nil
}

/*
func enable(isEnable, isStInversed, isStInverseAllowWhenNoVpn, isVpnConnected, vpnNoIPv6 bool) error {
	if !isEnable {
		enabled, err := isEnabled()
		if err == nil && !enabled {
			return nil
		}
		err = shell.Exec(log, stScriptPath, "stop")
		if err != nil {
			return fmt.Errorf("failed to disable Split Tunnel: %w", err)
		}
		log.Info("Split Tunnel disabled")
	} else {
		inversedArg := ""
		inverseBlockArg := ""
		if isStInversed {
			inversedArg = "-inverse"
			// Block 'inversed' apps when VPN is not connected
			if !isVpnConnected && !isStInverseAllowWhenNoVpn {
				inverseBlockArg = "-inverse_block"
			} else if isVpnConnected && vpnNoIPv6 {
				// If VPN does not support IPv6 - block IPv6 connectivity for 'splitted' apps in inverse mode
				inverseBlockArg = "-inverse_block_ipv6"
			}

		}
		_, outErrText, _, _, err := shell.ExecAndGetOutput(log, 1024, "", stScriptPath, "start", inversedArg, inverseBlockArg)
		if err != nil {
			if len(outErrText) > 0 {
				err = fmt.Errorf("(%w) %s", err, outErrText)
			}
			// if ST start failed - clean everything (by command 'stop')
			shell.Exec(nil, stScriptPath, "stop")
			return fmt.Errorf("failed to enable Split Tunnel: %w", err)
		}
		log.Info("Split Tunnel enabled")
	}

	isActive = isEnable

	return nil
}
*/

func getRootPid(p RunningApp, allPids map[int]RunningApp) (rootPid int, isKnownRoot bool) {
	if _, ok := _addedRootProcesses[p.Ppid]; ok {
		return p.Ppid, true
	}
	if _, ok := _addedRootProcesses[p.Pid]; ok {
		return p.Pid, true
	}
	if p.ExtIvpnRootPid > 0 {
		if _, ok := _addedRootProcesses[p.ExtIvpnRootPid]; ok {
			return p.ExtIvpnRootPid, true
		}
	}

	if parentProc, ok := allPids[p.Ppid]; ok {
		if p.Ppid <= parentProc.Ppid {
			return 0, false //just to ensure there is no infinite recursion
		}
		return getRootPid(parentProc, allPids)
	}
	return p.Ppid, false
}

func isChildOf(p RunningApp, parentPid int, allPids map[int]RunningApp) bool {
	if p.Ppid == parentPid {
		return true
	}
	if p.ExtIvpnRootPid > 0 && p.ExtIvpnRootPid == parentPid {
		return true
	}

	if parentProc, ok := allPids[p.Ppid]; ok {
		if p.Ppid <= parentProc.Ppid {
			return false //just to ensure there is no infinite recursion
		}
		return isChildOf(parentProc, parentPid, allPids)
	}
	return false
}

func readProcEnvVarIvpnId(pid int) (int, error) {
	bytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return 0, err
	}

	id := 0
	vars := strings.Split(string(bytes), string(0))
	for _, line := range vars {
		cols := strings.Split(line, "=")
		if len(cols) != 2 {
			continue
		}
		if cols[0] == "IVPN_STARTED_ST_ID" {
			return strconv.Atoi(cols[1])
		}
	}

	return id, nil
}
