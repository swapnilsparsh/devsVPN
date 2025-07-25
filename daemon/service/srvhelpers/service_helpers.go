// TODO FIXME: prepend license
// Copyright (c) 2025 privateLINE, LLC.

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
	MonitorEndChan       chan bool
	MonitorRunningMutex  *sync.Mutex
	MonitorStopFuncMutex *sync.Mutex
}

// StopServiceBackgroundMonitor stops the corresponding background monitor.
// It will stop it only once, if needed - or won't send stop action if the monitor was already stopped.
func (sbm *ServiceBackgroundMonitor) StopServiceBackgroundMonitor() {
	sbm.MonitorStopFuncMutex.Lock() // single-instance function
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
