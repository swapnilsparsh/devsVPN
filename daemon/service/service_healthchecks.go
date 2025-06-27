// TODO FIXME: prepend license
// Copyright (c) 2025 privateLINE, LLC.

package service

import (
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall"
)

type BackendConnectivityCheckState int

const (
	PHASE0_CLEAN         BackendConnectivityCheckState = iota
	PHASE1_TRY_RECONNECT BackendConnectivityCheckState = iota
)

// 2-phase approach: reconfig firewall, then disconnect / disable Total Shield / reconnect
func (s *Service) checkConnectivityFixAsNeeded() (retErr error) {
	if s.IsDaemonStopping() {
		log.ErrorFE("error - daemon is stopping")
		s.backendConnectivityCheckState = PHASE0_CLEAN
		return nil
	}

	if apiHostsPingable, err := s.PingInternalApiHosts(); err != nil {
		s.backendConnectivityCheckState = PHASE0_CLEAN
		return log.ErrorFE("error in PingInternalApiHosts(), skipping this loop iteration. error=%w", err)
	} else if apiHostsPingable {
		s.backendConnectivityCheckState = PHASE0_CLEAN
		return nil
	}

	switch s.backendConnectivityCheckState { // by now we know that there were no errors, but that backend resources are not reachable
	case PHASE0_CLEAN: // phase 0: fully redeploy firewall and VPN coexistence rules
		s.backendConnectivityCheckState = PHASE1_TRY_RECONNECT // next time, if no errors - don't try firewall reconfig, try VPN disconnect-reconnect
		if err := firewall.TryReregisterFirewallAtTopPriority(true, true); err != nil {
			return log.ErrorFE("error in firewall.TryReregisterFirewallAtTopPriority(true, true): %w", err)
		}
	case PHASE1_TRY_RECONNECT: // phase 1: disable Total Shield and disconnect-reconnect the VPN
		s.backendConnectivityCheckState = PHASE0_CLEAN

		prefs := s._preferences // disable Total Shield in preferences
		if prefs.IsTotalShieldOn {
			prefs.IsTotalShieldOn = false
			s.setPreferences(prefs)
		}

		if s._vpnConnectedCallback() { // if VPN is currently CONNECTED - reconnect
			if err := s.reconnect(); err != nil { // This will also stop connectivityHealthchecksBackgroundMonitor. If VPN reconnects succesfully - will restart it.
				return log.ErrorFE("error Service.reconnect(): %w", err)
			}
		}
	}

	return nil
}

// connectivityHealthchecksBackgroundMonitor runs asynchronously as a forked thread.
// It polls regularly whether the VPN connection is healthy - whether internal PL hosts (on private IPs) are reachable.
// To stop this thread - send to stopPollingConnectivityHealthchecks chan.
func (s *Service) connectivityHealthchecksBackgroundMonitor() {
	if s.IsDaemonStopping() {
		return
	}

	s.connectivityHealthchecksRunningMutex.Lock() // to ensure there's only one instance of connectivityHealthchecksBackgroundMonitor
	defer s.connectivityHealthchecksRunningMutex.Unlock()

	log.Debug("connectivityHealthchecksBackgroundMonitor entered")
	defer log.Debug("connectivityHealthchecksBackgroundMonitor exited")

	s.backendConnectivityCheckState = PHASE0_CLEAN
	loopIteration := 0
	for {
		select {
		case _ = <-s.stopPollingConnectivityHealthchecks:
			log.Debug("connectivityHealthchecksBackgroundMonitor exiting on stop signal")
			return
		default: // no message received
			if s.IsDaemonStopping() {
				log.ErrorFE("error - daemon is stopping")
				return
			}

			time.Sleep(time.Second) // sleep 1 second per each loop iteration
			loopIteration = (loopIteration + 1) % 5
			if loopIteration == 0 { // test connectivity only every 5th iteration - that is, once every 5 seconds
				if err := s.checkConnectivityFixAsNeeded(); err != nil {
					log.ErrorFE("error returned by checkConnectivityFixAsNeeded(): %w", err) // and continue
				}
			}
		}
	}
}
