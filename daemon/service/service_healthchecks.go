// TODO: FIXME: prepend license
// Copyright (c) 2025 privateLINE, LLC.

package service

import (
	"time"

	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall"
	"github.com/swapnilsparsh/devsVPN/daemon/service/types"
)

type BackendConnectivityCheckState int

const (
	PHASE0_CLEAN         BackendConnectivityCheckState = iota
	PHASE1_TRY_RECONNECT BackendConnectivityCheckState = iota

	MAX_CLIENT_NOTIFICATIONS = 2
)

var (
	notificationsAfterReconnect = 0 // after we lost connectivity and reconnected, send out the notification to clients (UI, etc.) at most twice

	HealthcheckDelaysByType = map[types.HealthchecksTypeEnum]int{
		types.HealthchecksType_Ping:        5,  // for ping healthchecks type, wait 5 seconds between requests
		types.HealthchecksType_RestApiCall: 30, // for REST API healthchecks type, wait 30 seconds between requests
		types.HealthchecksType_Disabled:    60, // if disabled, wait 60 seconds between retries
	}
)

// 2-phase approach: reconfig firewall, then disconnect / disable Total Shield / reconnect
func (s *Service) checkConnectivityFixAsNeeded() (retErr error) {
	if s.IsDaemonStopping() {
		log.ErrorFE("error - daemon is stopping")
		s.backendConnectivityCheckState = PHASE0_CLEAN
		return nil
	}

	if backendReachable, err := s.CheckBackendConnectivity(); backendReachable && err == nil {
		s.backendConnectivityCheckState = PHASE0_CLEAN
		if notificationsAfterReconnect < MAX_CLIENT_NOTIFICATIONS {
			go s._evtReceiver.OnKillSwitchStateChanged(false)       // update firewall state in UI - else it may get stuck with stale "FAILED | Fix" status
			go s._evtReceiver.OnVpnStateChanged_ProcessSavedState() // notify clients abt the actual VPN state - presumably that it's connected; at most 2 notifications
			notificationsAfterReconnect++
		}
		return nil
	} else if err != nil {
		retErr = log.ErrorFE("error in CheckBackendConnectivity(): %w", err)
	}

	if !s._vpnConnectedCallback() { // only apply recovery logic if VPN is still CONNECTED; else we may hit a race condition
		s.backendConnectivityCheckState = PHASE0_CLEAN // ... if a disconnect request was received while we were waiting for the REST API call in s.CheckBackendConnectivity()
		return nil
	}

	// by now we know that backend resources are not reachable, and VPN was just checked to be CONNECTED
	notificationsAfterReconnect = 0                // reset the count of client notifications
	go s._evtReceiver.NotifyClientsVpnConnecting() // make the clients show VPN CONNECTING state

	if !s._preferences.PermissionReconfigureOtherVPNs { // if we don't have permission stored ...
		if otherVpnsDetected, _, err := firewall.ReconfigurableOtherVpnsDetected(); err != nil {
			return log.ErrorFE("error in firewall.ReconfigurableOtherVpnsDetected(): %w", err)
		} else if otherVpnsDetected { // other VPNs detected - re-notify clients that we don't have top firewall priority, need permission to reconfigure
			go s._evtReceiver.OnKillSwitchStateChanged(true) // otherwise show on UI that connectivity is blocked, and show Fix button
			s.backendConnectivityCheckState = PHASE0_CLEAN
			return nil
		}
	}

	switch s.backendConnectivityCheckState {
	case PHASE0_CLEAN: // phase 0: fully redeploy firewall and VPN coexistence rules
		s.backendConnectivityCheckState = PHASE1_TRY_RECONNECT // if backend again not reachable on next try - don't try firewall reconfig, try VPN disconnect-reconnect
		log.Debug("PHASE0_CLEAN: about to fully redeploy firewall and VPN coexistence rules")
		if err := firewall.TryReregisterFirewallAtTopPriority(s._preferences.PermissionReconfigureOtherVPNs, true); err != nil {
			return log.ErrorFE("error in firewall.TryReregisterFirewallAtTopPriority(%t, true): %w", s._preferences.PermissionReconfigureOtherVPNs, err)
		}
	case PHASE1_TRY_RECONNECT: // phase 1: disable Total Shield and disconnect-reconnect the VPN
		s.backendConnectivityCheckState = PHASE0_CLEAN // next time don't try to reconnect, reset to phase0
		log.Debug("PHASE1_TRY_RECONNECT: about to disable Total Shield and disconnect-reconnect the VPN")
		prefs := s._preferences // disable Total Shield in preferences
		if prefs.IsTotalShieldOn {
			prefs.IsTotalShieldOn = false
			s.setPreferences(prefs)
		}

		if err := s.reconnect(); err != nil { // This will also stop connectivityHealthchecksBackgroundMonitor. If VPN reconnects succesfully - will restart it.
			return log.ErrorFE("error Service.reconnect(): %w", err)
		}
	}

	return retErr
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
			delay := HealthcheckDelaysByType[s.Preferences().HealthchecksType]
			loopIteration = (loopIteration + 1) % delay
			if loopIteration == 0 { // test connectivity only every n-th iteration - that is, once every n seconds (specific for healthchecks type)
				if err := s.checkConnectivityFixAsNeeded(); err != nil {
					log.ErrorFE("error returned by checkConnectivityFixAsNeeded(): %w", err) // and continue
				}
			}
		}
	}
}
