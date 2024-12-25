// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 privateLINE, LLC.

//go:build windows
// +build windows

package vpncoexistence

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/swapnilsparsh/devsVPN/daemon/logger"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Refer to these code samples:
//	https://learn.microsoft.com/en-us/windows/win32/services/stopping-a-service
//	https://learn.microsoft.com/en-us/windows/win32/services/starting-a-service
//	https://github.com/shirou/gopsutil/blob/master/winservices
//	https://opensource.srlabs.de/projects/srl_gobuster/repository/11/revisions/master/annotate/src/golang.org/x/sys/windows/svc/example/manage.go

var log *logger.Logger

func init() {
	log = logger.NewLogger("vpncoe")
}

const (
	MAX_WAIT = 10 * time.Second
)

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
