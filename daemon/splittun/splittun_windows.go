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

package splittun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/swapnilsparsh/devsVPN/daemon/netinfo"
	"github.com/swapnilsparsh/devsVPN/daemon/service/platform"
	"github.com/swapnilsparsh/devsVPN/daemon/shell"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var (
	// error describing details if functionality not available
	funcNotAvailableError            error
	fSplitTun_Connect                *syscall.LazyProc
	fSplitTun_Disconnect             *syscall.LazyProc
	fSplitTun_StopAndClean           *syscall.LazyProc
	fSplitTun_SplitStart             *syscall.LazyProc
	fSplitTun_ConfigSetAddresses     *syscall.LazyProc
	fSplitTun_ConfigSetSplitAppRaw   *syscall.LazyProc
	fSplitTun_ProcMonInitRunningApps *syscall.LazyProc

	//fSplitTun_GetState               *syscall.LazyProc
	//fSplitTun_ConfigGetAddresses     *syscall.LazyProc
	//fSplitTun_ConfigGetSplitAppRaw   *syscall.LazyProc
	//fSplitTun_ProcMonStart           *syscall.LazyProc
	//fSplitTun_ProcMonStop            *syscall.LazyProc
	//fSplitTun_SplitStop              *syscall.LazyProc
)

var (
	/*mutexSplittunWin,*/ mutexIPv6PowerShell sync.Mutex

	isDriverConnected bool

	// If defined, route rules were applied for inverse split tunneling.
	// This variable contains the IP address of the default gateway used in routing rules.
	appliedNextHopIpv4 net.IP
	appliedNextHopIpv6 net.IP

	// map from INET type (IPv4 or IPv6) to default routes (all zeroes)
	defaultRoutesByIpFamily = map[uint16]winipcfg.IPAddressPrefix{}

	routeBinaryPath string = "route"
	// powershellBinaryPath string = "powershell"
)

type ConfigApps struct {
	ImagesPathToSplit []string
}

type Config struct {
	Addr ConfigAddresses
	Apps ConfigApps
}

// Initialize doing initialization stuff (called on application start)
func implInitialize() error {
	// get path to 'route.exe' binary
	envVarSystemroot := strings.ToLower(os.Getenv("SYSTEMROOT"))
	if len(envVarSystemroot) == 0 {
		log.Error("!!! ERROR !!! Unable to determine 'SYSTEMROOT' environment variable!")
	} else {
		routeBinaryPath = strings.ReplaceAll(path.Join(envVarSystemroot, "system32", "route.exe"), "/", "\\")
		// powershellBinaryPath = strings.ReplaceAll(path.Join(envVarSystemroot, "system32", "WindowsPowerShell", "v1.0", "powershell.exe"), "/", "\\")
	}

	var err error
	wfpDllPath := platform.WindowsWFPDllPath()
	if len(wfpDllPath) == 0 {
		return fmt.Errorf("unable to initialize split-tunnelling wrapper: firewall dll path not initialized")
	}
	if _, err = os.Stat(wfpDllPath); err != nil {
		return fmt.Errorf("unable to initialize split-tunnelling wrapper (firewall dll not found) : '%s'", wfpDllPath)
	}

	// load dll
	dll := syscall.NewLazyDLL(wfpDllPath)

	fSplitTun_Connect = dll.NewProc("SplitTun_Connect")
	fSplitTun_Disconnect = dll.NewProc("SplitTun_Disconnect")
	fSplitTun_StopAndClean = dll.NewProc("SplitTun_StopAndClean")
	fSplitTun_ProcMonInitRunningApps = dll.NewProc("SplitTun_ProcMonInitRunningApps")
	fSplitTun_SplitStart = dll.NewProc("SplitTun_SplitStart")
	//fSplitTun_GetState = dll.NewProc("SplitTun_GetState")
	fSplitTun_ConfigSetAddresses = dll.NewProc("SplitTun_ConfigSetAddresses")
	//fSplitTun_ConfigGetAddresses = dll.NewProc("SplitTun_ConfigGetAddresses")
	fSplitTun_ConfigSetSplitAppRaw = dll.NewProc("fSplitTun_ConfigSetSplitAppRaw")
	//fSplitTun_ConfigGetSplitAppRaw = dll.NewProc("fSplitTun_ConfigGetSplitAppRaw")
	//fSplitTun_ProcMonStart = dll.NewProc("SplitTun_ProcMonStart")
	//fSplitTun_ProcMonStop = dll.NewProc("SplitTun_ProcMonStop")
	//fSplitTun_SplitStop = dll.NewProc("SplitTun_SplitStop")

	// to ensure that functionality works - just try to start/stop driver
	defer disconnect(false)

	// Check if ST driver can start
	// const retryDelay = time.Second
	// const retryCnt = 5
	// for i := 1; i <= retryCnt; i++ {
	// 	if connectErr := connect(false); connectErr != nil {
	// 		funcNotAvailableError = fmt.Errorf("Split-Tunnel functionality test failed: %w", connectErr)
	// 		if connectErr == windows.ERROR_SERVICE_MARKED_FOR_DELETE {
	// 			log.Warning(fmt.Sprintf("[%d of %d; retry in %v] : %s", i, retryCnt, retryDelay, funcNotAvailableError.Error()))
	// 			time.Sleep(retryDelay)
	// 			continue
	// 		}
	// 	} else {
	// 		if i > 1 {
	// 			log.Info("Split-Tunnel functionality test success")
	// 		}
	// 		funcNotAvailableError = nil
	// 	}
	// 	break
	// }

	// init the default routes map
	var (
		defaultRoutePrefixIPv4netipPrefix, defaultRoutePrefixIPv6netipPrefix         netip.Prefix
		defaultRoutePrefixIPv4IPAddressPrefix, defaultRoutePrefixIPv6IPAddressPrefix winipcfg.IPAddressPrefix
	)

	if defaultRoutePrefixIPv4netipPrefix, err = netip.ParsePrefix(defaultRouteIPv4); err != nil {
		return fmt.Errorf("error netip.ParsePrefix(%s): %w", defaultRouteIPv4, err)
	}
	if defaultRoutePrefixIPv6netipPrefix, err = netip.ParsePrefix(defaultRouteIPv6); err != nil {
		return fmt.Errorf("error netip.ParsePrefix(%s): %w", defaultRouteIPv6, err)
	}

	if err := defaultRoutePrefixIPv4IPAddressPrefix.SetPrefix(defaultRoutePrefixIPv4netipPrefix); err != nil {
		return fmt.Errorf("error SetPrefix IPv4: %w", err)
	}
	if err := defaultRoutePrefixIPv6IPAddressPrefix.SetPrefix(defaultRoutePrefixIPv6netipPrefix); err != nil {
		return fmt.Errorf("error SetPrefix IPv6: %w", err)
	}

	defaultRoutesByIpFamily[windows.AF_INET] = defaultRoutePrefixIPv4IPAddressPrefix
	defaultRoutesByIpFamily[windows.AF_INET6] = defaultRoutePrefixIPv6IPAddressPrefix

	return funcNotAvailableError
}

func isInitialised() error {
	// TODO: Vlad - not loading the driver

	// // check if fSplitTun_Connect and other functions initialized
	// if fSplitTun_Connect == nil ||
	// 	fSplitTun_Disconnect == nil ||
	// 	fSplitTun_StopAndClean == nil ||
	// 	fSplitTun_ProcMonInitRunningApps == nil ||
	// 	fSplitTun_SplitStart == nil ||
	// 	fSplitTun_ConfigSetAddresses == nil ||
	// 	fSplitTun_ConfigSetSplitAppRaw == nil {
	// 	return fmt.Errorf("Split-Tunnel functionality not initialized")
	// }
	return nil
}

func implFuncNotAvailableError() (generalStError, inversedStError error) {
	return funcNotAvailableError, nil
}

func implReset() error {
	for endpointType, endpoint := range lastConfiguredEndpoints { // reset both IPv4 and IPv6, if present
		if endpoint == nil {
			continue
		}
		if err := doApplySplitFullTunnelRoutes(endpointType, true, false, *endpoint); err != nil {
			return fmt.Errorf("error in doApplySplitFullTunnelRoutes(): %w", err)
		}
	}

	return nil
}

func implApplyConfig(isStEnabled, isStInversed, enableAppWhitelist, isStInverseAllowWhenNoVpn, isVpnEnabled bool, addrConfig ConfigAddresses, splitTunnelApps []string) error {
	log.Debug("implApplyConfig entered")
	defer log.Debug("implApplyConfig exited")

	// Check if functionality available
	splitTunErr, splitTunInversedErr := GetFuncNotAvailableError()
	isFunctionalityNotAvailable := splitTunErr != nil || (isStInversed && splitTunInversedErr != nil)
	if isFunctionalityNotAvailable {
		return nil
	}

	if err := isInitialised(); err != nil {
		return err
	}

	// TODO FIXME: Vlad - adjust logic
	// If: (VPN not connected + inverse split-tunneling enabled + isStInverseAllowWhenNoVpn==false) --> we need to set blackhole IP addresses for tunnel interface
	// This will forward all traffic of split-tunnel apps to 'nowhere' (in fact, it will block all traffic of split-tunnel apps)
	if isStInversed && !isStInverseAllowWhenNoVpn && !isVpnEnabled {
		addrConfig.IPv4Tunnel = net.ParseIP(BlackHoleIPv4)
		addrConfig.IPv6Tunnel = net.ParseIP(BlackHoleIPv6)
	}

	// TODO FIXME: Vlad - adjust logic
	// If ST not enabled or no configuration - just disconnect driver (if connected)
	// We do not need to start ST driver when:
	// - ST disabled
	// - VPN disconnected and NOT Inversed ST
	// - VPN disconnected and apps from ST environment allowed to use default connection
	// - ST addresses are not defined
	// - ST apps are not defined
	isDriverMustBeDisabled := !isStEnabled || (!isVpnEnabled && !isStInversed) || (!isVpnEnabled && isStInverseAllowWhenNoVpn) || addrConfig.IsEmpty() || len(splitTunnelApps) == 0
	// The inverse mode routing rules must be applied even if there is no defined apps in 'splitTunnelApps'.
	// This ensures that non-ST apps still use default connection (and bypassing VPN)
	isInverseRulesMustBeApplied := isStEnabled && isStInversed && !addrConfig.IsEmpty()

	applyInverseSplitTunRoutingRules(false, false, false) // erase applied InverseST routing rules if any

	if isDriverMustBeDisabled {
		if isDriverConnected { // If driver connected
			if err := stopAndClean(); err != nil { // stop and erase old configuration (if any)
				log.Error(err)
			}
			if err := disconnect(true); err != nil { // disconnect driver
				log.Error(err)
			}
		}
	} else {
		// If driver not connected: connect
		if err := connect(true); err != nil {
			return log.ErrorE(fmt.Errorf("failed to connect split-tunnel driver: %w", err), 0)
		}
		// clean old configuration (if any)
		if err := stopAndClean(); err != nil {
			return log.ErrorE(fmt.Errorf("failed to clean split-tunnel state: %w", err), 0)
		}

		addresses := addrConfig
		// TODO FIXME: Vlad - check logic
		// For inversed split-tunnel we just inverse IP addresses in driver configuration (defaultPublicInterfaceIP <=> tunnelInterfaceIP)
		if isStInversed {
			// In situation when there is no IPv6 connectivity on local machine (IPv6Public not defined) - we need to set IPv6Tunnel to IPv6Public
			// otherwise (if IPv6Public or IPv6Tunnel not defined) - IPv6 traffic for 'splited' apps will be blocked by ST driver
			if len(addresses.IPv6Public) == 0 && len(addresses.IPv6Tunnel) > 0 {
				addresses.IPv6Public = addresses.IPv6Tunnel
			}

			// inverse IP addresses (defaultPublicInterfaceIP <=> tunnelInterfaceIP)
			p4 := addresses.IPv4Public
			addresses.IPv4Public = addresses.IPv4Tunnel
			addresses.IPv4Tunnel = p4
			p6 := addresses.IPv6Public
			addresses.IPv6Public = addresses.IPv6Tunnel
			addresses.IPv6Tunnel = p6
		}

		// Set new configuration for driver
		cfg := Config{}
		cfg.Apps = ConfigApps{ImagesPathToSplit: splitTunnelApps}
		cfg.Addr = addresses
		if err := setConfig(cfg); err != nil {
			stopAndClean()
			disconnect(true) // disconnect driver
			return log.ErrorE(fmt.Errorf("error on configuring Split-Tunnelling: %w", err), 0)
		}

		// start split-tunneling:
		if err := start(); err != nil {
			stopAndClean()   // stop and erase old configuration (if any)
			disconnect(true) // disconnect driver
			return log.ErrorE(fmt.Errorf("error on start Split-Tunnelling: %w", err), 0)
		}

		defer log.Info(fmt.Sprintf("Split-Tunnelling started: IPv4: (%s) => (%s) IPv6: (%s) => (%s)", addresses.IPv4Tunnel, addresses.IPv4Public, addresses.IPv6Tunnel, addresses.IPv6Public))
	}

	if isInverseRulesMustBeApplied {
		// apply routing rules for inversed split-tunneling (if VPN connected) or erase applied rules (if VPN not connected)
		if err := applyInverseSplitTunRoutingRules(isVpnEnabled, isStInversed, isStEnabled); err != nil {
			applyInverseSplitTunRoutingRules(false, false, false) // erase applied routing rules if any
			stopAndClean()                                        // stop and erase old configuration (if any)
			disconnect(true)                                      // disconnect driver
			return err
		}
	}

	return nil
}

// func implApplyConfig(isStEnabled, isStInversed, enableAppWhitelist, isStInverseAllowWhenNoVpn, isVpnEnabled bool, addrConfig ConfigAddresses, splitTunnelApps []string) error {
// 	// mutexSplittunWin.Lock()
// 	// defer func() {
// 	// 	log.Debug("implApplyConfig() completed")
// 	// 	mutexSplittunWin.Unlock()
// 	// }()
// 	// log.Debug("implApplyConfig() started")

// 	// Check if functionality available
// 	var err error
// 	splitTunErr, splitTunInversedErr := GetFuncNotAvailableError()
// 	isFunctionalityNotAvailable := splitTunErr != nil || (isStInversed && splitTunInversedErr != nil)
// 	if isFunctionalityNotAvailable {
// 		_, file, line, _ := runtime.Caller(0)
// 		log.Warning(fmt.Sprintf("%s:%d: functionality not available", file, line))
// 		return nil
// 	}

// 	if err = isInitialised(); err != nil {
// 		return fmt.Errorf("error in isInitialised(): %w", err)
// 	}

// 	// Disabling default IPv6 routes doesn't work on win10 - Windows enables them back. Instead we disable/enable IPv6 on all adapters.
// 	// if addrConfig.IPv6Endpoint != nil {
// 	// 	if err = doApplySplitFullTunnelRoutes(windows.AF_INET6, isStEnabled, isVpnEnabled, addrConfig.IPv6Endpoint); err != nil {
// 	// 		err = log.ErrorE(fmt.Errorf("error in doApplySplitFullTunnelRoutes(ipv6): %w", err), 0)
// 	// 	}
// 	// }

// 	// ipv6ResponseChan := make(chan error)
// 	// fork the powershell invocation in the background and forget about it, it takes 6.8-6.9 seconds on my laptop
// 	go enableDisableIPv6(isStEnabled || !isVpnEnabled /*, ipv6ResponseChan*/)

// 	if addrConfig.IPv4Endpoint != nil {
// 		if err = doApplySplitFullTunnelRoutes(windows.AF_INET, isStEnabled, isVpnEnabled, addrConfig.IPv4Endpoint); err != nil {
// 			err = fmt.Errorf("error in doApplySplitFullTunnelRoutes(ipv4): %w", err)
// 		}
// 	}

// 	// ipv6Err := <-ipv6ResponseChan

// 	// if err != nil {
// 	return err
// 	// } else {
// 	// 	return ipv6Err
// 	// }
// }

func implAddPid(pid int, commandToExecute string) error {
	return fmt.Errorf("operation not applicable for current platform")
}

func implRemovePid(pid int) error {
	return fmt.Errorf("operation not applicable for current platform")
}

func implGetRunningApps() ([]RunningApp, error) {
	return nil, fmt.Errorf("operation not applicable for current platform")
}

// Inversed split-tunneling solution for Windows (no changes in Split-Tunnel driver implementation required):
// **IVPN daemon:**
// - Disable monitoring of the default route to the VPN server.
// - Initialize the split-tunnel driver with inverse IP addresses (PublicIP <==> TunnelIP).
// - Disable IVPN firewall or modify firewall rules: excluded apps can use only a VPN tunnel. All the rest apps can use any interface except the VPN tunnel.
//
// **Routing table modification:**
// When VPN is enabled, the default routing rules route all traffic through the VPN interface:
//
//	route add 0.0.0.0 MASK 128.0.0.0 <VPN_SVR_IP>
//	route add 128.0.0.0 MASK 128.0.0.0 <VPN_SVR_IP>
//
// These rules must remain unchanged so the system knows how to route traffic tied to the VPN interface (traffic for excluded applications).
//
// To achieve the desired split-tunneling effect, we add more specific rules that route all traffic through the default interface, effectively overlapping the VPN rules:
//
//	# In this example, we assume that the default route IP is 192.168.1.1
//	route add 0.0.0.0 MASK 192.0.0.0 192.168.1.1
//	route add 64.0.0.0 MASK 192.0.0.0 192.168.1.1
//	route add 128.0.0.0 MASK 192.0.0.0 192.168.1.1
//	route add 192.0.0.0 MASK 192.0.0.0 192.168.1.1
//
// As a result, all traffic will pass through the default non-VPN interface, except for excluded apps designated by the split-tunnel driver, which will use the VPN interface.
// TODO: Vlad - I don't think we need to manipulate the routing table for App Whitelist, firewall policies should suffice
func applyInverseSplitTunRoutingRules(isVpnEnabled, isStInversed, isStEnabled bool) (retErr error) {
	log.Debug("applyInverseSplitTunRoutingRules - disabled")
	return nil

	isNeedApplyRoutes := isVpnEnabled && isStInversed && isStEnabled

	const IPv4 = false
	const IPv6 = true
	if err := doApplyInverseRoutes(IPv4, isNeedApplyRoutes); err != nil {
		retErr = err
		log.Error(err)
	}
	if err := doApplyInverseRoutes(IPv6, isNeedApplyRoutes); err != nil {
		retErr = err
		log.Error(err)
	}
	return retErr
}

// TODO FIXME: Vlad - adjust logic
func doApplyInverseRoutes(isIPv6, enable bool) error {
	if routeBinaryPath == "" {
		return fmt.Errorf("route.exe location not specified")
	}
	var appliedNextHop *net.IP = &appliedNextHopIpv4
	blackHole := net.ParseIP(BlackHoleIPv4)
	// subnets to apply routing rules to cover all addresses (with mask "/2")
	masks := []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"}
	if isIPv6 {
		appliedNextHop = &appliedNextHopIpv6
		blackHole = net.ParseIP(BlackHoleIPv6)
		masks = []string{"::/2", "4000::/2", "8000::/2", "C000::/2"}
	}

	// internal functions
	fnErase := func(masksToErase []string) {
		if *appliedNextHop == nil {
			return
		}
		for _, mask := range masksToErase {
			cmd := []string{"delete", mask, appliedNextHop.String()}
			if err := shell.Exec(log, routeBinaryPath, cmd...); err != nil {
				log.Error(fmt.Errorf("failed to erase inverse split-tunnelling routing rules (ipv6=%v): %w", isIPv6, err))
			}
		}
		*appliedNextHop = nil
	}

	// just remove all routes if enable!=true
	if !enable {
		fnErase(masks)
		return nil
	}

	// get default gateway & interface
	var defGateway net.IP
	var defInf *net.Interface
	var err error
	if defGateway, defInf, err = netinfo.DefaultGatewayEx(isIPv6); err != nil {
		// if failed to get default gateway - use "blackhole" as next hop (it will block all traffic)
		log.Info(fmt.Errorf("not detected default gateway IP address [ipv6=%v]; routing all traffic to blackhole %v (err=%w)", isIPv6, defGateway.String(), err))
		defGateway = blackHole
		defInf, err = netinfo.GetLoopbackInterface(isIPv6)
		if err != nil {
			return err
		}
	}

	// if already applied - nothing to do
	if defGateway.Equal(*appliedNextHop) {
		return nil
	}

	// erase already applied rules (if any)
	fnErase(masks)
	*appliedNextHop = defGateway // save info about interface next hop
	var masksApplied []string
	for _, mask := range masks {
		// route add <range> <gw> [if <interface_idx>]
		cmd := []string{"add", mask, appliedNextHop.String(), "if", fmt.Sprintf("%d", defInf.Index)}
		if err := shell.Exec(log, routeBinaryPath, cmd...); err != nil {
			fnErase(masksApplied) // erase already applied rules: erase only successfully applied rules
			return log.ErrorE(fmt.Errorf("failed to apply inverse split-tunnelling routing rules (ipv6=%v): %w", isIPv6, err), 0)
		}
		masksApplied = append(masksApplied, mask)
	}
	return nil
}

// TODO FIXME: Vlad - write out descr
// TODO FIXME: Vlad - process isVpnEnabled logic. Ensure we get called if VPN gets enabled/disabled.
func doApplySplitFullTunnelRoutes(ipFamily uint16, isStEnabled bool, isVpnEnabled bool, wgEndpoint net.IP) error {
	var (
		wgEndpointDestPrefix, changeFromDestPrefix, changeToDestPrefix winipcfg.IPAddressPrefix
		wgEndpointPrefixNetip                                          netip.Prefix
		err                                                            error
	)

	// Add replacement logic vars
	wgEndpointCIDR := fmt.Sprintf("%s/%d", wgEndpoint, addrSizesByIpFamily[ipFamily])
	if wgEndpointPrefixNetip, err = netip.ParsePrefix(wgEndpointCIDR); err != nil {
		return fmt.Errorf("erorr in netip.ParsePrefix(%s): %w", wgEndpointCIDR, err)
	}
	if err = wgEndpointDestPrefix.SetPrefix(wgEndpointPrefixNetip); err != nil {
		return fmt.Errorf("error in SetPrefix(wgEndpointPrefixNetip): %w", err)
	}

	if !isVpnEnabled || isStEnabled { // if VPN is disabled, or if enabling split tunnel - we reset full tunnel (total shield) customized routes back to default routes
		changeFromDestPrefix = wgEndpointDestPrefix            // ... then change from our Wireguard endpoint on the matching routes
		changeToDestPrefix = defaultRoutesByIpFamily[ipFamily] // ... back to all-zeros default route destination
	} else { // if enabling full tunnel (total shield), and VPN is enabled
		changeFromDestPrefix = defaultRoutesByIpFamily[ipFamily] // ... then change from all-zeros default route destination
		changeToDestPrefix = wgEndpointDestPrefix                // ... to allow only our Wireguard endpoint on the given route
		lastConfiguredEndpoints[ipFamily] = &wgEndpoint          // save the last configured Wireguard VPN endpoint
	}
	//log.Debug(fmt.Sprintf("doApplySplitFullTunnelRoutes(): ipFamily=%#v, changeFromDestPrefix=%#v, changeToDestPrefix=%#v", ipFamily, changeFromDestPrefix, changeToDestPrefix))
	if changeFromDestPrefix.RawPrefix.Addr() == changeToDestPrefix.RawPrefix.Addr() {
		return fmt.Errorf("unexpected condition: changeFromDestPrefix.RawPrefix.Addr() == changeToDestPrefix.RawPrefix.Addr() == %s", changeToDestPrefix.RawPrefix.Addr())
	}

	routes, err := winipcfg.GetIPForwardTable2(winipcfg.AddressFamily(ipFamily))
	if err != nil {
		return fmt.Errorf("error in GetIPForwardTable2(): %w", err)
	}

	for _, route := range routes { // TODO: print the whole route table before the loop via "route print"
		//log.Debug(fmt.Sprintf("doApplySplitFullTunnelRoutes(): route=%#v", route))
		if route.DestinationPrefix.RawPrefix.Addr() == changeFromDestPrefix.RawPrefix.Addr() {
			changedRoute := route
			changedRoute.DestinationPrefix = changeToDestPrefix
			//log.Debug(fmt.Sprintf("doApplySplitFullTunnelRoutes(): changedRoute=%#v", changedRoute))
			if err = route.Delete(); err != nil {
				return fmt.Errorf("error in MibIPforwardRow2.Delete(). route=%#v. Error=%w", route, err)
			}
			if err = changedRoute.Create(); err != nil {
				//return fmt.Errorf("error in MibIPforwardRow2.Create(): %w", err)
				log.Warning(fmt.Errorf("MibIPforwardRow2.Create() failed, duplicate route already exists - skipping route creation. changedRoute='%#v'. Error=%w", changedRoute, err))
			}
		}
	}

	return nil
}

func catchPanic(err *error) {
	if r := recover(); r != nil {
		log.Error("PANIC (recovered): ", r)
		if e, ok := r.(error); ok {
			*err = e
		} else {
			*err = errors.New(fmt.Sprint(r))
		}
	}
}

func checkCallErrResp(retval uintptr, err error, mName string) error {
	if err != syscall.Errno(0) {
		return log.ErrorE(fmt.Errorf("%s:  %w", mName, err), 1)
	}
	if retval != 1 {
		return log.ErrorE(fmt.Errorf("Split-Tunnelling operation failed (%s)", mName), 1)
	}
	return nil
}

func connect(logging bool) (err error) {
	defer catchPanic(&err)

	// TODO FIXME: Vlad - disabled for now. Reenable back once we enable the driver.
	return nil

	if isDriverConnected {
		return nil
	}

	if logging {
		log.Info("Split-Tunnelling: Connect driver...")
	}

	if err := isInitialised(); err != nil {
		return err
	}

	drvPath := platform.WindowsSplitTunnelDriverPath()
	utfDrvPath, err := syscall.UTF16PtrFromString(drvPath)
	if err != nil {
		return fmt.Errorf("(SplitTun_Connect) Failed to convert driver file path: %w", err)
	}

	retval, _, err := fSplitTun_Connect.Call(uintptr(unsafe.Pointer(utfDrvPath)))
	if err != syscall.Errno(0) {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			err = fmt.Errorf("%w (check if IVPN Split-Tunnelling driver installed)", err)
		}
		return err
	}
	if retval != 1 {
		return fmt.Errorf("Split-Tunnelling operation failed (SplitTun_Connect)")
	}

	isDriverConnected = true
	if logging {
		log.Info("Split-Tunnelling: driver ready")
	}

	return nil
}

func disconnect(logging bool) (err error) {
	defer catchPanic(&err)

	if !isDriverConnected {
		return nil
	}
	isDriverConnected = false

	if logging {
		log.Info("Split-Tunnelling: Disconnect driver...")
	}

	if err := isInitialised(); err != nil {
		return err
	}

	retval, _, err := fSplitTun_Disconnect.Call()
	if err := checkCallErrResp(retval, err, "SplitTun_Disconnect"); err != nil {
		if logging {
			err = log.ErrorE(fmt.Errorf("failed to disconnect split-tunnel driver: %w", err), 0)
		}
		return err
	}

	return nil
}

func stopAndClean() (err error) {
	defer catchPanic(&err)

	log.Info("Split-Tunnelling: StopAndClean...")

	if err := isInitialised(); err != nil {
		return err
	}

	/// Stop and clean everything:
	///		Stop splitting
	///		Stop processes monitoring
	///		Clean all configuration/statuses
	// TODO FIXME: Vlad - disabled for now. Reenable back once we enable the driver.
	// retval, _, err := fSplitTun_StopAndClean.Call()
	// if err := checkCallErrResp(retval, err, "SplitTun_StopAndClean"); err != nil {
	// 	return err
	// }

	return nil
}

func start() (err error) {
	defer catchPanic(&err)

	log.Info("Split-Tunnelling: Start...")

	if err := isInitialised(); err != nil {
		return err
	}

	/// Start splitting.
	/// If "process monitor" not running - it will be started.
	///
	/// Operation fails when configuration not complete:
	///		- no splitting apps defined
	///		- no IP configuration (IP-public + IP-tunnel) defined at least for one protocol type (IPv4\IPv6)
	///
	/// If only IPv4 configuration defined - splitting will work only for IPv4
	/// If only IPv6 configuration defined - splitting will work only for IPv6
	// retval, _, err := fSplitTun_SplitStart.Call()
	// if err := checkCallErrResp(retval, err, "SplitTun_SplitStart"); err != nil {
	// 	return err
	// }

	// Initialize already running apps info
	/// Set application PID\PPIDs which have to be splitted.
	/// It adds new info to internal process tree but not erasing current known PID\PPIDs.
	/// Operation fails when 'process monitor' not running
	// retval, _, err = fSplitTun_ProcMonInitRunningApps.Call()

	// if err == syscall.ERROR_NO_MORE_FILES {
	// 	// ignore ERROR_NO_MORE_FILES error. It is Ok after calling of 'SplitTun_ProcMonInitRunningApps'
	// 	err = syscall.Errno(0)
	// }
	// if err := checkCallErrResp(retval, err, "SplitTun_ProcMonInitRunningApps"); err != nil {
	// 	return err
	// }

	return nil
}

func setConfig(config Config) (err error) {
	defer catchPanic(&err)

	log.Info("Split-Tunnelling: SetConfig...")

	if err := isInitialised(); err != nil {
		return err
	}
	// TODO FIXME: Vlad - disabled for now. Reenable back once we enable the driver.
	return nil

	// SET IP ADDRESSES
	IPv4Public := config.Addr.IPv4Public.To4()
	IPv4Tunnel := config.Addr.IPv4Tunnel.To4()
	IPv6Public := config.Addr.IPv6Public.To16()
	IPv6Tunnel := config.Addr.IPv6Tunnel.To16()

	if IPv4Public == nil {
		IPv4Public = make([]byte, 4)
	}
	if IPv4Tunnel == nil {
		IPv4Tunnel = make([]byte, 4)
	}
	if IPv6Public == nil {
		IPv6Public = make([]byte, 16)
	}
	if IPv6Tunnel == nil {
		IPv6Tunnel = make([]byte, 16)
	}

	retval, _, err := fSplitTun_ConfigSetAddresses.Call(
		uintptr(unsafe.Pointer(&IPv4Public[0])),
		uintptr(unsafe.Pointer(&IPv4Tunnel[0])),
		uintptr(unsafe.Pointer(&IPv6Public[0])),
		uintptr(unsafe.Pointer(&IPv6Tunnel[0])))
	if err := checkCallErrResp(retval, err, "SplitTun_ConfigSetAddresses"); err != nil {
		return err
	}

	// TODO FIXME: Vlad - disabled for now. Reenable back once we enable the driver.
	/*
		// SET APPS TO SPLIT
		for idx, appPath := range config.Apps.ImagesPathToSplit {
			appID, _ := wf.AppID(appPath)
			// TODO FIXME: Vlad:
			// Link all objects to our provider. When multiple providers are installed
			// on a computer, this makes it easy to determine who added what.
			r := &wf.Rule{
				// TODO FIXME: Vlad - make deterministic GUID from canonicalized path
				ID:   wf.RuleID(mustGUID()),
				Name: "privateLINE rule IPv4 #" + strconv.Itoa(idx),
				//Layer: wf.LayerALEAuthConnectV4,
				Layer:      wf.LayerALEAuthRecvAcceptV4,
				Sublayer:   guidSublayerUniversal,
				Weight:     900,
				Persistent: true,
				Conditions: []*wf.Match{
					// &wf.Match{
					// 	Field: wf.FieldIPLocalAddress,
					// 	Op:    wf.MatchTypeEqual,
					// 	Value: uint8(42),
					// },
					{
						Field: wf.FieldALEAppID,
						Op:    wf.MatchTypeEqual,
						Value: appID,
					},
				},
				Action: wf.ActionPermit,
			}
			if err := platform.WindowsWFPSession().AddRule(r); err != nil {
				return log.ErrorE(fmt.Errorf("failed to AddRule '%+v': %w", r, err), 0)
			} else {
				log.Debug(fmt.Sprintf("AddRule '%+v'", r))
			}
		}
	*/

	// buff, err := makeRawBuffAppsConfig(config.Apps)
	// if err != nil {
	// 	return log.ErrorE(fmt.Errorf("failed to set split-tunnelling configuration (apps): %w", err), 0)
	// }

	// var bufSize uint32 = uint32(len(buff))
	// retval, _, err = fSplitTun_ConfigSetSplitAppRaw.Call(
	// 	uintptr(unsafe.Pointer(&buff[0])),
	// 	uintptr(bufSize))
	// if err := checkCallErrResp(retval, err, "SplitTun_ConfigSetSplitAppRaw"); err != nil {
	// 	return err
	// }

	return nil
}

func makeRawBuffAppsConfig(apps ConfigApps) (bytesArr []byte, err error) {
	//	DWORD common size bytes
	//	DWORD strings cnt
	//	DWORD str1Len
	//	DWORD str2Len
	//	...
	//	WCHAR[] str1
	//	WCHAR[] str2
	//	...

	sizesBuff := new(bytes.Buffer)
	stringsBuff := new(bytes.Buffer)

	var strLen uint32 = 0
	for _, path := range apps.ImagesPathToSplit {
		uint16arr, _ := syscall.UTF16FromString(path)
		// remove NULL-termination
		uint16arr = uint16arr[:len(uint16arr)-1]

		strLen = uint32(len(uint16arr))
		if err := binary.Write(sizesBuff, binary.LittleEndian, strLen); err != nil {
			return nil, err
		}
		if err := binary.Write(stringsBuff, binary.LittleEndian, uint16arr); err != nil {
			return nil, err
		}
	}

	var totalSize uint32 = uint32(4 + 4 + sizesBuff.Len() + stringsBuff.Len())
	var stringsCnt uint32 = uint32(len(apps.ImagesPathToSplit))

	buff := new(bytes.Buffer)
	if err := binary.Write(buff, binary.LittleEndian, totalSize); err != nil {
		return nil, err
	}
	if err := binary.Write(buff, binary.LittleEndian, stringsCnt); err != nil {
		return nil, err
	}
	if err := binary.Write(buff, binary.LittleEndian, sizesBuff.Bytes()); err != nil {
		return nil, err
	}
	if err := binary.Write(buff, binary.LittleEndian, stringsBuff.Bytes()); err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

/*
func getConfig() (cfg Config, err error) {
	defer catchPanic(&err)

	// ADDRESSES
	IPv4Public := make([]byte, 4)
	IPv4Tunnel := make([]byte, 4)
	IPv6Public := make([]byte, 16)
	IPv6Tunnel := make([]byte, 16)

	retval, _, err := fSplitTun_ConfigGetAddresses.Call(
		uintptr(unsafe.Pointer(&IPv4Public[0])),
		uintptr(unsafe.Pointer(&IPv4Tunnel[0])),
		uintptr(unsafe.Pointer(&IPv6Public[0])),
		uintptr(unsafe.Pointer(&IPv6Tunnel[0])))
	if err := checkCallErrResp(retval, err, "SplitTun_ConfigGetAddresses"); err != nil {
		return Config{}, err
	}

	addr := ConfigAddresses{IPv4Public: IPv4Public, IPv4Tunnel: IPv4Tunnel, IPv6Public: IPv6Public, IPv6Tunnel: IPv6Tunnel}

	// APPS

	// get required buffer size
	var buffSize uint32 = 0
	var emptyBuff []byte
	_, _, err = fSplitTun_ConfigGetSplitAppRaw.Call(
		uintptr(unsafe.Pointer(&emptyBuff)),
		uintptr(unsafe.Pointer(&buffSize)))
	if err := checkCallErrResp(retval, err, "SplitTun_ConfigGetSplitAppRaw"); err != nil {
		return Config{}, err
	}

	// get data
	buff := make([]byte, buffSize)
	retval, _, err = fSplitTun_ConfigGetSplitAppRaw.Call(
		uintptr(unsafe.Pointer(&buff[0])),
		uintptr(unsafe.Pointer(&buffSize)))
	if err := checkCallErrResp(retval, err, "SplitTun_ConfigGetSplitAppRaw"); err != nil {
		return Config{}, err
	}

	apps, err := parseRawBuffAppsConfig(buff)
	if err != nil {
		return Config{}, log.ErrorE(fmt.Errorf("failed to obtain split-tinnelling configuration (apps): %w", err), 0)
	}

	return Config{Addr: addr, Apps: apps}, nil
}
func parseRawBuffAppsConfig(bytesArr []byte) (apps ConfigApps, err error) {
	//	DWORD common size bytes
	//	DWORD strings cnt
	//	DWORD str1Len
	//	DWORD str2Len
	//	...
	//	WCHAR[] str1
	//	WCHAR[] str2
	//	...

	var totalSize uint32
	var stringsCnt uint32
	files := make([]string, 0)

	buff := bytes.NewReader(bytesArr)
	if err := binary.Read(buff, binary.LittleEndian, &totalSize); err != nil {
		return ConfigApps{}, err
	}
	if err := binary.Read(buff, binary.LittleEndian, &stringsCnt); err != nil {
		return ConfigApps{}, err
	}

	if int(totalSize) != len(bytesArr) {
		return ConfigApps{}, fmt.Errorf("failed to parse split-tun configuration (applications)")
	}

	buffSizes := bytes.NewReader(bytesArr[4+4 : 4+4+stringsCnt*4])
	buffStrings := bytes.NewReader(bytesArr[4+4+stringsCnt*4:])

	var i uint32
	var strBytesSize uint32
	for i = 0; i < stringsCnt; i++ {
		if err := binary.Read(buffSizes, binary.LittleEndian, &strBytesSize); err != nil {
			return ConfigApps{}, err
		}

		uint16str := make([]uint16, strBytesSize)
		if err := binary.Read(buffStrings, binary.LittleEndian, &uint16str); err != nil {
			return ConfigApps{}, err
		}

		files = append(files, syscall.UTF16ToString(uint16str))
	}

	return ConfigApps{ImagesPathToSplit: files}, nil
}

func implGetState() (state State, err error) {
	defer catchPanic(&err)

	var isConfigOk uint32
	var isEnabledProcessMonitor uint32
	var isEnabledSplitting uint32

	retval, _, err := fSplitTun_GetState.Call(
		uintptr(unsafe.Pointer(&isConfigOk)),
		uintptr(unsafe.Pointer(&isEnabledProcessMonitor)),
		uintptr(unsafe.Pointer(&isEnabledSplitting)))
	if err := checkCallErrResp(retval, err, "fSplitTun_GetState"); err != nil {
		return State{}, err
	}

	return State{IsConfigOk: isConfigOk != 0, IsEnabledSplitting: isEnabledSplitting != 0}, nil
}

func implStop() (err error) {
	defer catchPanic(&err)

	// stop splitting
	retval, _, err := fSplitTun_SplitStop.Call()
	if err := checkCallErrResp(retval, err, "SplitTun_SplitStop"); err != nil {
		return err
	}

	// stop process monitor
	retval, _, err = fSplitTun_ProcMonStop.Call()
	if err := checkCallErrResp(retval, err, "SplitTun_ProcMonStop"); err != nil {
		return err
	}

	return nil
}*/
