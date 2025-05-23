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

package main

import (
	"log/syslog"
	"os"

	"github.com/swapnilsparsh/devsVPN/daemon/helpers"
	"github.com/swapnilsparsh/devsVPN/daemon/service"
	"github.com/swapnilsparsh/devsVPN/daemon/service/firewall"
)

func doPrepareToRun() error {

	// Create syslog writter
	// and initialize channel to receive log messages from service
	sysLogWriter, err := syslog.New(syslog.LOG_ERR, helpers.ServiceName)
	if err != nil {
		log.Error("Failed to initialize syslog: ", err)
	} else {
		systemLog = make(chan service.SystemLogMessage, 1)
		go func() {
			for {
				mes := <-systemLog
				switch mes.Type {
				case service.Info:
					sysLogWriter.Info(mes.Message)
				case service.Warning:
					sysLogWriter.Warning("WARNING: " + mes.Message)
				case service.Error:
					sysLogWriter.Err("ERROR: " + mes.Message)
				}
			}
		}()
	}

	return nil
}

func doBeforeStop() {
	log.Debug("doBeforeStop entered")
	defer log.Debug("doBeforeStop exited")
	firewall.DisableCoexistenceWithOtherVpnsMutex.Lock() // launcher waits for this mutex on daemon shutdown, to ensure all disable tasks have been completed
	defer firewall.DisableCoexistenceWithOtherVpnsMutex.Unlock()
}

func doStopped() {
}

func doCheckIsAdmin() bool {
	return os.Geteuid() == 0
}

func doStartedOnPort(port int, secret uint64) {
}
