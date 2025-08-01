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

//go:build !fastping
// +build !fastping

package service

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hayageek/threadsafe"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/swapnilsparsh/devsVPN/daemon/api"
	"github.com/swapnilsparsh/devsVPN/daemon/api/types"
	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	protocolTypes "github.com/swapnilsparsh/devsVPN/daemon/protocol/types"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall"
	"github.com/swapnilsparsh/devsVPN/daemon/vpn"
)

const (
	// In some cases the multiple (and simultaneous pings) are leading to OS crash on macOS and Windows.
	// It happens when installed some third-party 'firewall' software.
	Ping_MaxSimultaneousRequestsCount = 10
	Ping_MaxHostTimeoutFirstPhase     = time.Millisecond * 400
	Ping_MaxHostTimeoutSecondPhase    = time.Millisecond * 800
	Ping_DefaultApiHostTimeout        = time.Millisecond * 800
)

// pingHost - host to ping
type pingHost struct {
	latitude  float32
	longitude float32
	host      net.IP
	priority  uint16 // Priority (lowest value - highest priority)
}

func (ph *pingHost) setPriority(phase int, vpnTypePriority int, hostPriority int) {
	//	binary: aabb cccc dddd dddd
	//		a - phase
	//		b - vpnTypePriority (>0)
	//		c - unspecified
	//		d - host priority
	if vpnTypePriority == 0 {
		vpnTypePriority = 1 + rand.Intn(int(2)) // if 'vpnTypePriority' not specified - use random priority
	}
	ph.priority = (uint16(phase&0b11) << 14) | (uint16(vpnTypePriority&0b11) << 12) | (uint16(hostPriority & 0b11111111))
}

// PingServers collects VPN hosts latencies.
//
// The pinging operation is separated into two phases:
//
//	phase 1:	(synchronous)  Limited by timeout 'firstPhaseTimeoutMs'
//	phase 2:	(asynchronous) No time limitation (if SkipSecondPhase==true - phase2 will be skipped)
//
// Hosts priority to ping (list from higher priority to lower):
//   - Hosts for specific VPN type has the highest priority (if vpnTypePrioritized is not defined (-1) - this prioritization is ignored)
//   - Host priority decreases according to its position in the server's host's list (the first host has the highest priority)
//   - Nearest hosts to the current location have higher priority (if geo-location is known)
func (s *Service) PingServers(firstPhaseTimeoutMs int, vpnTypePrioritized vpn.Type, skipSecondPhase bool) (map[string]int, error) {
	startTime := time.Now()

	// temporarily enable the firewall, need VPN coexistence logic up - otherwise, if another VPN is already running, our pings may not go through
	if err := firewall.EnableIfNeeded(); err != nil {
		return nil, log.ErrorFE("error in firewall.EnableIfNeeded: %w", err)
	} else {
		defer firewall.DisableUnlessConnectedConnecting() // want to keep our firewall logic (incl. VPN coexistence rules) disabled most of the time
	}

	if s.ConnectedOrConnecting() {
		ret := s._pingServers.ping_getLastResults()
		if len(ret) == 0 {
			return nil, fmt.Errorf("servers pinging skipped due to connected state")
		}
		log.Info("Servers pinging skipped due to connected state. Using saved results.")
		return ret, nil
	}

	if firstPhaseTimeoutMs <= 0 {
		log.Debug("Servers pinging skipped: timeout argument value is 0")
		return nil, nil
	}

	// Block pinging when IVPNServersAccess==blocked
	if err := s.IsConnectivityBlocked(); err != nil {
		return nil, fmt.Errorf("servers pinging skipped: %v", err)
	}

	// Do not allow multiple ping request simultaneously
	if !s._pingServers._singleRequestLimitMutex.TryLock() {
		return nil, fmt.Errorf("servers pinging skipped: ping already in progress, please try again after some delay")
	}

	// Get hosts to ping in prioritized order
	hostsToPing, err := s.ping_getHosts(vpnTypePrioritized, skipSecondPhase)
	if err != nil {
		s._pingServers._singleRequestLimitMutex.Unlock()
		return nil, err
	}

	// OS-specific preparations (e.g. we need to add servers IPs to firewall exceptions list)
	// Do not forget to call s.implPingServersStopped()!!!
	hostsToNotifyFirewall := make([]net.IP, 0, hostsToPing.Length())
	for hIdx := 0; hIdx < hostsToPing.Length(); hIdx++ {
		h, _ := hostsToPing.Get(hIdx)
		hostsToNotifyFirewall = append(hostsToNotifyFirewall, h.host)
	}
	if err := s.implPingServersStarting(hostsToNotifyFirewall); err != nil {
		log.Error("implPingServersStarting failed: " + err.Error())
	}

	done := make(chan struct{}, 1)
	// Wait for full stop in separate routine
	go func() {
		<-done
		// OS-specific preparations (e.g. we need to remove servers IPs from firewall exceptions list)
		if err := s.implPingServersStopped(hostsToNotifyFirewall); err != nil {
			log.Error("implPingServersStopped failed: " + err.Error())
		}
		// release semaphore (to allow new calls of current finction)
		s._pingServers._singleRequestLimitMutex.Unlock()
	}()

	// Request geo-location in separate routine
	onGeoLookupChan := make(chan *types.GeoLookupResponse, 1)
	if firstPhaseTimeoutMs >= 2000 {
		go func() {
			geoLocation, _, err := s._api.GeoLookup(2000, protocolTypes.IPvAny)
			if err != nil {
				log.Warning("(pinging) unable to obtain geo-location (fastest server detection could be not accurate):", err)
				return
			}
			onGeoLookupChan <- geoLocation
		}()
	} else {
		log.Warning("(pinging) not enough time to check geo-location (fastest server detection could be not accurate)")
	}

	// Return value: map[host]latency
	result := make(map[string]int)

	log.Info("Pinging servers...")

	// 1)	Fast ping: ping one host for each nearest location
	//		Doing it fast. 'MaxTimeoutMsFirstPhase'ms max for each server
	firstPhaseDeadline := startTime.Add(time.Millisecond * time.Duration(firstPhaseTimeoutMs))
	isInterrupted := s._pingServers.ping_iteration(s, hostsToPing, Ping_MaxHostTimeoutFirstPhase, result, &firstPhaseDeadline, false, onGeoLookupChan)

	isNoDataSaved := s._pingServers.ping_isEmptyResults()
	if !skipSecondPhase && len(result) < hostsToPing.Length() {
		// The first ping result already received.
		// So, now there is no rush to do second ping iteration. Doing it in background.

		// 2) Full ping: Pinging all hosts for all locations. There is no time limit for this operation. It runs in background.
		go func() {
			isInterrupted := s._pingServers.ping_iteration(s, hostsToPing, Ping_MaxHostTimeoutSecondPhase, result, nil, false, onGeoLookupChan)
			if isNoDataSaved || !isInterrupted {
				s._pingServers.ping_resultNotify(s, result)
			}
			log.Info(fmt.Sprintf("Full ping finished in (%v): %d of %d pinged", time.Since(startTime), len(result), hostsToPing.Length()))
			done <- struct{}{}
		}()
	} else {
		if isNoDataSaved || !isInterrupted {
			s._pingServers.ping_resultNotify(s, result)
		}
		log.Info(fmt.Sprintf("Fast ping finished in (%v): %d of %d pinged", time.Since(startTime), len(result), hostsToPing.Length()))
		done <- struct{}{}
	}

	// Return first ping result (fast ping: first stage)
	// This result may not contain results for all servers
	return result, nil
}

// PingInternalApiHosts - pings a few internal API hosts, on internal IPs. Returns true if at least one of them pings successfully, or if there's a problem that's not our fault.
// If it encounters problems, the reasons for them are outside the current flow, thread - it logs the problem and returns true. Hoping these problems will go away by next iteration.
func (s *Service) PingInternalApiHosts() (success bool, err error) {
	s._pingInternalApiHosts._singleRequestLimitMutex.Lock() // single-instance
	defer s._pingInternalApiHosts._singleRequestLimitMutex.Unlock()

	if !s._vpnConnectedCallback() { // if VPN is not connected, it's probably due to either another thread reconnecting, or disconnect in progress - return true.
		log.Warn("warning - VPN is not connected, so not pinging API hosts")
		return true, nil
	}

	// We know the VPN is connected by now. If the firewall is disabled (for whatever reason - i.e., due to VPN reconnect or firewall redeployment being in progress) - return true.
	if fwEnabled, fwErr := firewall.GetEnabledNoLogs(); fwErr != nil {
		log.ErrorFE("error checking firewall state: %w", fwErr)
		return true, nil
	} else if !fwEnabled {
		log.Warn("warning - firewall not enabled, not enabling it here, not pinging API hosts")
		return true, nil
	}

	startTime := time.Now()

	// For API hosts to ping - resolve hostnames to IPs, and check whether IPs are on our private IP range
	//apiHostIPsToPing := make([]pingHost, 0, len(api.RestApiHostnamesToPing))
	apiHostIPsToPing := threadsafe.NewArray[pingHost](0)
	var resolveApiHostsInParallelWG sync.WaitGroup // Resolve all hosts in parallel - one host timeout takes 20 seconds on Linux.
	for _, apiHostname := range api.RestApiHostnamesToPing {
		resolveApiHostsInParallelWG.Add(1)
		go func() { // detect other VPNs by active network interface name
			defer resolveApiHostsInParallelWG.Done()

			if apiHostIPs, err2 := net.LookupIP(apiHostname); err2 != nil {
				log.ErrorFE("could not lookup IPs for API hostname '%s': %w", apiHostname, err2)
			} else if len(apiHostIPs) == 0 {
				log.ErrorFE("no IPs returned for API hostname '%s'", apiHostname)
			} else {
				for _, apiHostIP := range apiHostIPs {
					if apiHostIP.To4() != nil && apiHostIP.IsPrivate() { // ping only IPv4 IPs for now, and only if private IP
						apiHostIPsToPing.Append(pingHost{host: apiHostIP})
					}
				}
			}
		}()
	}
	resolveApiHostsInParallelWG.Wait()

	if apiHostIPsToPing.Length() <= 0 {
		return false, log.ErrorFE("error - resolving API servers doesn't yield any private IPv4 IPs")
	}

	// Return value: map[host]latency
	result := make(map[string]int)

	// log.Debug("Pinging API hosts...")

	// Fast probing. Doing it fast. 'Ping_DefaultApiHostTimeout' ms max for each API host
	firstPhaseDeadline := startTime.Add(time.Millisecond * time.Duration(Ping_DefaultApiHostTimeout))
	var scanInterruptedMsg string
	if isInterrupted := s._pingInternalApiHosts.ping_iteration(s, apiHostIPsToPing, Ping_DefaultApiHostTimeout, result, &firstPhaseDeadline, true, nil); isInterrupted {
		scanInterruptedMsg = ". Scan was interrupted."
		log.Debug(fmt.Sprintf("Fast ping of internal API hosts finished in (%v): %d of %d pinged%s", time.Since(startTime), len(result), apiHostIPsToPing.Length(), scanInterruptedMsg))
	}
	// log.Debug(fmt.Sprintf("Fast ping of internal API hosts finished in (%v): %d of %d pinged%s", time.Since(startTime), len(result), len(apiHostIPsToPing), scanInterruptedMsg))

	// Return true if at least one of the API hosts responded to ping on internal IP
	return len(result) > 0, nil
}

// ping_getHosts - Get hosts to ping
func (s *Service) ping_getHosts(vpnTypePrioritized vpn.Type, skipSecondPhase bool) (*threadsafe.Array[pingHost], error) {
	// get servers info
	servers, err := s._serversUpdater.GetServers()
	if err != nil {
		return nil, fmt.Errorf("unable to get servers list: %w", err)
	}

	svrsWg := servers.ServersGenericWireguard()
	svrsOvpn := servers.ServersGenericOpenvpn()
	uniqueHosts := make(map[string]pingHost, len(svrsWg)+len(svrsOvpn)) // map[hostIP]hostObject

	getVpnPriorityFunc := func(vpnType vpn.Type, vpnTypePrioritized vpn.Type) int {
		if vpnTypePrioritized != vpn.OpenVPN && vpnTypePrioritized != vpn.WireGuard {
			return 0 // if 'vpnTypePrioritized' not specified - use random priority
		}
		if vpnType == vpnTypePrioritized {
			return 1
		}
		return 2
	}

	getHostsFunc := func(svrs []types.ServerGeneric, isFirstPhase bool, vpnTypePriority int) {
		if len(svrs) == 0 {
			return
		}

		phasePriority := 0
		if !isFirstPhase {
			phasePriority = 1
		}

		for _, s := range svrs {
			sBase := s.GetServerInfoBase()
			hosts := s.GetHostsInfoBase()
			for i, h := range hosts {
				vpnPriority := vpnTypePriority

				htp := pingHost{
					latitude:  sBase.Latitude,
					longitude: sBase.Longitude,
					host:      net.ParseIP(strings.Split(h.EndpointIP, "/")[0]),
				}
				htp.setPriority(phasePriority, vpnPriority, i)

				if htp.host.IsUnspecified() {
					continue
				}
				hostIpStr := htp.host.String()
				if _, exists := uniqueHosts[hostIpStr]; !exists {
					uniqueHosts[hostIpStr] = htp
				}
			}
		}
	}

	// phase 1
	getHostsFunc(svrsWg, true, getVpnPriorityFunc(vpn.WireGuard, vpnTypePrioritized))
	getHostsFunc(svrsOvpn, true, getVpnPriorityFunc(vpn.OpenVPN, vpnTypePrioritized))

	if !skipSecondPhase {
		// phase 2
		getHostsFunc(svrsWg, false, getVpnPriorityFunc(vpn.WireGuard, vpnTypePrioritized))
		getHostsFunc(svrsOvpn, false, getVpnPriorityFunc(vpn.OpenVPN, vpnTypePrioritized))
	}

	//ret := make([]pingHost, len(uniqueHosts))
	ret := threadsafe.NewArray[pingHost](len(uniqueHosts))
	i := 0
	for _, v := range uniqueHosts {
		ret.Set(i, v)
		i++
	}

	// sorting by priority
	// ping_sortHosts(ret, nil)

	return ret, nil
}

// FIXME: sort.Slice() doesn't work for threadsafe.Array, gotta fix
// ping_sortHosts - won't get called for s._pingInternalApiHosts
func ping_sortHosts(hosts *threadsafe.Array[pingHost], currentLocation *types.GeoLookupResponse) {
	// sorting by priority and by location
	cLat, cLot := float64(0), float64(0)
	if currentLocation != nil {
		cLat, cLot = float64(currentLocation.Latitude), float64(currentLocation.Longitude)
	}

	sort.Slice(hosts, func(i, j int) bool {
		iHost, _ := hosts.Get(i)
		jHost, _ := hosts.Get(j)

		if iHost.priority != jHost.priority {
			return iHost.priority < jHost.priority
		}

		if currentLocation != nil {
			di := helpers.GetDistanceFromLatLonInKm(cLat, cLot, float64(iHost.latitude), float64(iHost.longitude))
			dj := helpers.GetDistanceFromLatLonInKm(cLat, cLot, float64(jHost.latitude), float64(jHost.longitude))
			return di < dj
		}
		return false
	})
}

func (p *pingSet) ping_iteration(s *Service, hostsToPing *threadsafe.Array[pingHost], hostTimeout time.Duration, pingedResult map[string]int, phaseDeadline *time.Time, pingWhileConnectedOrConnecting bool, onGeolookupChan <-chan *types.GeoLookupResponse) (isInterrupted bool) {
	if hostsToPing.Length() == 0 {
		return
	}

	resultMutex := &sync.RWMutex{}
	wg := sync.WaitGroup{}
	pingsLimit := make(chan struct{}, Ping_MaxSimultaneousRequestsCount) // limit count of allowed simultaneous pings

	lastUpdateSentTime := time.Now()

	for {
		needRetry := false
		for hIdx := 0; hIdx < hostsToPing.Length(); hIdx++ {
			h, _ := hostsToPing.Get(hIdx)

			if s.ConnectedOrConnecting() && !pingWhileConnectedOrConnecting {
				log.Info("Servers pinging stopped due to connecting or connected state")
				isInterrupted = true
				break
			}

			if phaseDeadline != nil && time.Now().Add(hostTimeout).After(*phaseDeadline) {
				log.Info("Servers pinging stopped due max-timeout for this operation")
				isInterrupted = true
				break
			}

			if h.host.IsUnspecified() {
				continue
			}

			ipStr := h.host.String()
			if len(ipStr) <= 0 {
				continue
			}

			// skip pinging twice same host
			resultMutex.RLock()
			_, isPinged := pingedResult[ipStr]
			resultMutex.RUnlock()

			if isPinged {
				continue
			}

			// If we received geo-location info: sort hosts according to new location and retry ping loop
			if onGeolookupChan != nil {
				select {
				case location := <-onGeolookupChan:
					if location != nil {
						ping_sortHosts(hostsToPing, location)
						needRetry = true
					}
				default:
				}
			}

			if needRetry {
				break
			}

			// limit count of allowed simultaneus pings
			pingsLimit <- struct{}{}
			wg.Add(1)

			// Ping single host in routine
			go func(hostIp string, timeout time.Duration) {
				defer func() {
					if r := recover(); r != nil { // recover in case of panic
						if err, ok := r.(error); ok {
							log.ErrorTrace(err)
						}
					}

					<-pingsLimit
					wg.Done()
				}()

				//log.Debug("Pinging ", hostIp, " ...") // FIXME: Vlad - disable when fleshed out
				pinger, err := probing.NewPinger(hostIp)
				if err != nil {
					log.Error("Pinger creation error: " + err.Error())
					return
				}

				pinger.SetPrivileged(true)
				pinger.Count = 2
				pinger.Timeout = timeout
				pinger.Interval = 50 * time.Millisecond

				if err := pinger.Run(); err != nil {
					log.ErrorFE("error in pinger.Run(): %w", err) // and continue
				} else {
					stat := pinger.Statistics()
					if stat.MinRtt > 0 {
						ttl := int(stat.MinRtt / time.Millisecond)

						resultMutex.Lock()
						pingedResult[hostIp] = ttl
						resultMutex.Unlock()

						//log.Debug("SUCCESS pinging ", hostIp) // FIXME: Vlad - disable when fleshed out
					}

					resultMutex.RLock()
					if p._notifyClients && phaseDeadline == nil && time.Now().After(lastUpdateSentTime.Add(time.Second*2)) {
						// periodically notify ping results when pinging in background
						p.ping_resultNotify(s, pingedResult)
						lastUpdateSentTime = time.Now()
					}
					resultMutex.RUnlock()
				}
			}(ipStr, hostTimeout)
		}
		if !needRetry {
			break
		}
	}
	wg.Wait()
	return isInterrupted
}

func (p *pingSet) ping_resultNotify(s *Service, retMap map[string]int) {
	if p._notifyClients && len(retMap) > 0 {
		p.ping_saveLastResults(retMap)
		if p == &s._pingServers { // notify only if pinging servers
			s._evtReceiver.OnPingStatus(retMap)
		}
	}
}

func (p *pingSet) ping_saveLastResults(r map[string]int) {
	if len(r) == 0 {
		return
	}
	p._results_mutex.Lock()
	defer p._results_mutex.Unlock()

	p._result = make(map[string]int)
	for k, v := range r {
		p._result[k] = v
	}
}

func (p *pingSet) ping_getLastResults() map[string]int {
	p._results_mutex.RLock()
	defer p._results_mutex.RUnlock()

	ret := make(map[string]int)
	for k, v := range p._result {
		ret[k] = v
	}
	return ret
}

func (p *pingSet) ping_isEmptyResults() bool {
	p._results_mutex.RLock()
	defer p._results_mutex.RUnlock()
	return len(p._result) == 0
}
