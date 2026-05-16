//  Daemon for privateLINE Connect Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Copyright (c) 2025 privateLINE, LLC.
//
//  This file is part of the Daemon for privateLINE Connect Desktop.
//
//  The Daemon for privateLINE Connect Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The Daemon for privateLINE Connect Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the Daemon for privateLINE Connect Desktop. If not, see <https://www.gnu.org/licenses/>.

package srvhelpers

import (
	"sync"

	"github.com/swapnilsparsh/devsVPN/daemon/logger"
)

var log *logger.Logger

func init() {
	log = logger.NewLogger("srvhlp")
}

type ServiceBackgroundMonitorFunc func()
type ServiceBackgroundMonitor struct {
	MonitorName          string
	MonitorFunc          ServiceBackgroundMonitorFunc
	ResetStateFunc       ServiceBackgroundMonitorFunc // Can be nil. Should grab MonitorRunningMutex for its duration.
	MonitorEndChan       chan bool
	MonitorRunningMutex  *sync.Mutex
	MonitorStopFuncMutex *sync.Mutex
}

// StopServiceBackgroundMonitor stops the corresponding background monitor.
// It will stop it only once, if needed - or won't send stop action if the monitor was already stopped.
func (sbm *ServiceBackgroundMonitor) StopServiceBackgroundMonitor() {
	sbm.MonitorStopFuncMutex.Lock() // single-instance function per sbm
	defer sbm.MonitorStopFuncMutex.Unlock()
	log.Debug("StopServiceBackgroundMonitor: stopping monitor '", sbm.MonitorName, "'")

	// must check whether the monitor func is still running (it could've exited due to an error), else don't send to EndChan
	if !sbm.MonitorRunningMutex.TryLock() {
		sbm.MonitorEndChan <- true     // send MonitorFunc a stop signal
		sbm.MonitorRunningMutex.Lock() // wait for it to stop
		defer log.Debug("StopServiceBackgroundMonitor: monitor '", sbm.MonitorName, "' stopped")
	} else {
		defer log.Debug("StopServiceBackgroundMonitor: monitor '", sbm.MonitorName, "' was already stopped")
	}
	sbm.MonitorRunningMutex.Unlock() // release its mutex, to allow it to be restarted later
}
